// src/plugin/flavors/signal_drop.rs

#![cfg(feature = "extensions")]

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};
use log::{info, debug, warn, trace};
use blake3;
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};

// 引入核心模块
use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::extensions::kns::{KnsKernel, KnsPath, RecordKind, ResolutionPriority};
use crate::extensions::identity::{EtpIdentity, GhostIdentity, IdentityType};
use crate::crypto::onion::{OnionCrypto, OnionConfig, NonceMode, PaddingStrategy};
use crate::NodeID;

// --- 配置常量 ---
const DROP_PROTOCOL_PREFIX: &str = "signal_drop_v1";
const PATH_SEGMENT: &str = "inbox"; // 固定路径段
const RECORD_TTL: u32 = 86400; // 1天

/// 信号投放 Flavor
/// 利用 KNS DHT 作为 Dead Drop，实现无服务器、抗审查的异步信令传输。
pub struct SignalDropFlavor {
    kns: Arc<KnsKernel>,
    my_static_secret: StaticSecret,
    my_public_key: XPublicKey,
}

/// 内部传输载荷
#[derive(Serialize, Deserialize)]
struct DropPayload {
    /// 防重放时间戳
    timestamp: u64,
    /// 发送者公钥 (用于接收者验证 ECDH 来源)
    sender_pub: [u8; 32],
    /// 真实业务数据
    content: Vec<u8>,
}

impl SignalDropFlavor {
    pub fn new(
        kns: Arc<KnsKernel>,
        static_secret_bytes: [u8; 32],
    ) -> Arc<Self> {
        let secret = StaticSecret::from(static_secret_bytes);
        let public = XPublicKey::from(&secret);

        Arc::new(Self {
            kns,
            my_static_secret: secret,
            my_public_key: public,
        })
    }

    /// 发送信号 (投递)
    /// 
    /// 流程：
    /// 1. ECDH 计算当天接头暗号 (DomainID)。
    /// 2. 生成一次性幽灵身份 (GhostIdentity)。
    /// 3. 本地注册该 Domain 并授权幽灵身份写入。
    /// 4. 加密 Payload 并发布到 DHT。
    pub async fn drop_signal(&self, target_pub_bytes: [u8; 32], content: Vec<u8>) -> Result<()> {
        let target_pub = XPublicKey::from(target_pub_bytes);
        
        // 1. 密钥协商与路径派生
        let shared_secret = self.my_static_secret.diffie_hellman(&target_pub);
        let domain_id = self.derive_daily_domain_id(shared_secret.as_bytes());
        let record_path = KnsPath::new(vec![PATH_SEGMENT.to_string()])?;

        debug!("SignalDrop: Preparing drop for domain '{}'", domain_id);

        // 2. 准备加密载荷 (Onion Layer)
        let payload = DropPayload {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            sender_pub: *self.my_public_key.as_bytes(),
            content,
        };
        let payload_bytes = bincode::serialize(&payload)?;

        // 配置高安全性的加密参数
        let onion_config = OnionConfig {
            // 使用随机 Nonce，防止相同内容的 Hash 在 DHT 上碰撞，增加流量分析难度
            nonce_mode: NonceMode::Random, 
            // 填充至 256 字节块对齐，隐藏消息真实长度
            padding: PaddingStrategy::BlockAligned(256), 
        };

        // 使用接收者的公钥进行非对称加密 (Sealing)
        // 这样只有持有 target_priv 的人才能解密
        let encrypted_data = OnionCrypto::seal(&target_pub_bytes, &payload_bytes, &onion_config)
            .context("Onion encryption failed")?;

        // 3. 创建幽灵身份与临时域
        // 为了在 KNS 发布记录，必须有一个签名者。
        // 我们创建一个临时的 GhostIdentity，它只存在于内存中，用于签署这条 DHT 记录。
        // 对于 DHT 节点来说，这是一条合法的、有签名的记录。
        let ghost_identity = Arc::new(GhostIdentity::new());
        let ghost_pub = ghost_identity.public_key();
        
        // 在本地 KNS 内核中注册这个“临时域”
        // 注意：这不会向全网广播“我拥有这个域”，而是告诉本地 KNS Kernel：
        // "对于这个 ID，请使用这个 Ghost Identity 进行操作"
        let domain = self.kns.create_domain(&domain_id, ghost_identity.clone());
        
        // 显式授权 Ghost Identity 写入 (虽然 create_domain 默认会加，但显式更安全)
        // KNS 的 ACL 机制要求写入者必须在白名单内
        domain.grant_write_access(ghost_identity.node_id(), IdentityType::Ghost, ghost_pub);

        // 4. 发布记录
        // RecordKind::Static: 这是一段静态数据，不是转发指针
        domain.publish(&record_path, &encrypted_data, RecordKind::Static, RECORD_TTL)?;
        
        info!("SignalDrop: Dropped {} bytes to hidden domain '{}'", encrypted_data.len(), domain_id);
        
        // 5. 清理
        // create_domain 会将 domain 放入 KnsKernel 的 map 中。
        // 这是一个一次性操作，理论上我们应该在发布后清理它，避免内存泄漏。
        // 但目前的 KnsKernel 接口可能需要扩展 remove_domain，或者依赖 TTL 自动过期。
        // 在此示例中，我们假设 Engine 会定期清理未使用的 Domain 句柄。
        
        Ok(())
    }

    /// 收取信号 (检查)
    ///
    /// 流程：
    /// 1. ECDH 计算当天接头暗号 (DomainID)。
    /// 2. 通过 KNS 内核向 DHT 发起查询。
    /// 3. 获取加密记录，使用私钥解密。
    /// 4. 验证 Payload 内部签名。
    pub async fn check_inbox(&self, sender_pub_bytes: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let sender_pub = XPublicKey::from(sender_pub_bytes);
        
        // 1. 密钥协商与路径派生 (必须与发送方完全一致)
        let shared_secret = self.my_static_secret.diffie_hellman(&sender_pub);
        let domain_id = self.derive_daily_domain_id(shared_secret.as_bytes());
        let record_path = KnsPath::new(vec![PATH_SEGMENT.to_string()])?;

        debug!("SignalDrop: Checking inbox at '{}'...", domain_id);

        // 2. KNS 解析
        // 使用 NetworkOnly 策略，因为我们需要最新的数据，且本地肯定没有缓存
        // KnsKernel::resolve 的逻辑是：
        //   a. 查找 domain_id (在 DHT 中查找对应 Key)
        //   b. 在该 Domain 下查找 path (Blind Index)
        // 在这里，domain_id 就是 DHT Key 的一部分逻辑映射
        let encrypted_data = match self.kns.resolve(
            &domain_id, 
            &record_path, 
            ResolutionPriority::NetworkOnly
        ).await {
            Ok(data) => data,
            Err(e) => {
                // DHT 返回 Not Found 是正常情况 (没信)
                trace!("SignalDrop: No signal found (Reason: {})", e);
                return Ok(None);
            }
        };

        // 3. 解密 (Onion Open)
        let my_secret_bytes = self.my_static_secret.to_bytes();
        
        // OnionCrypto::open 会：
        //   a. 解析 Ephemeral Public Key
        //   b. 进行 ECDH
        //   c. 解密并验证 Poly1305 Tag
        let plaintext = match OnionCrypto::open(&encrypted_data, &my_secret_bytes) {
            Ok(pt) => pt,
            Err(e) => {
                warn!("SignalDrop: Decryption failed. Message meant for someone else? Error: {}", e);
                return Ok(None);
            }
        };

        // 4. 反序列化与业务验证
        let payload: DropPayload = bincode::deserialize(&plaintext)
            .context("Invalid payload format")?;

        // 验证发送者身份
        // 这一步至关重要：防止中间人虽然无法解密，但重放了其他人的包
        // 虽然 Onion 保证了只有我能解密，但没保证是谁发的 (匿名发送)。
        // 这里的 sender_pub 必须与我们预期的 sender_pub_bytes 一致。
        if payload.sender_pub != sender_pub_bytes {
            warn!("SignalDrop: Security Alert! Payload sender key mismatch.");
            return Ok(None);
        }

        // 验证时间戳 (防止重放旧消息)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if payload.timestamp > now + 300 || now.saturating_sub(payload.timestamp) > RECORD_TTL as u64 {
            warn!("SignalDrop: Message expired or timestamp invalid.");
            return Ok(None);
        }

        info!("SignalDrop: Successfully retrieved message from inbox.");
        Ok(Some(payload.content))
    }

    /// 核心算法：基于时间周期的确定性域名派生
    /// 
    /// 算法：`Hex( Blake3_Keyed( Key=SharedSecret, Data="DROP_V1" + DayIndex ) )`
    /// 结果是一个 64 字符的 Hex 字符串，作为 KNS 的 SecurityDomain ID。
    fn derive_daily_domain_id(&self, shared_secret: &[u8]) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let day_index = now / 86400; // 每天轮换一次地址
        
        // 使用 Keyed Hash 确保只有持有 SharedSecret 的人能推导出 ID
        let mut hasher = blake3::Hasher::new_keyed(
            &blake3::hash(shared_secret).into()
        );
        
        hasher.update(DROP_PROTOCOL_PREFIX.as_bytes());
        hasher.update(b"_");
        hasher.update(&day_index.to_be_bytes());
        
        let hash = hasher.finalize();
        hex::encode(hash.as_bytes())
    }
}

// --- 实现 CapabilityProvider 接口 ---
impl CapabilityProvider for SignalDropFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.signal_drop.v1".into()
    }
}

// --- 实现 Flavor 接口 (Agent 模式，不处理流数据) ---
impl Flavor for SignalDropFlavor {
    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool {
        // 此 Flavor 不通过 ETP 隧道传输数据，而是直接操作 KNS/DHT
        false
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}
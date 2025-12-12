// etp-core/src/wire/packet.rs

use crate::{PacketNumber, SessionID};
use crate::wire::frame::Frame;
use crate::crypto::noise::NoiseSession;
use serde::{Serialize, Deserialize};
use rand::Rng;
use anyhow::{Result, anyhow};
use std::fmt::Debug;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use chrono::Utc;

type HmacSha256 = Hmac<Sha256>;

/// 混淆器接口 (方言 Dialect)
pub trait Dialect: Send + Sync + Debug {
    /// 方言唯一标识
    fn id(&self) -> &'static str;
    
    /// 封装: 在加密数据外层添加伪装
    fn seal(&self, payload: &mut Vec<u8>);
    
    /// 解封: 尝试解析格式并还原 ETP 数据
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// 探针: 快速检查数据包是否看起来属于该方言 (不进行完全解包)
    /// 用于自适应学习时的快速筛选
    fn probe(&self, data: &[u8]) -> bool;
}

// --- 双模包结构 ---

/// 模式 1: 有状态包 (Stateful Packet)
/// 适用于已建立的连接，包含 SessionID 和 PacketNumber
#[derive(Debug, Serialize, Deserialize)]
pub struct StatefulPacket {
    pub session_id: SessionID,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

/// 模式 2: 无状态包 (Stateless Packet)
/// 适用于 0-RTT、打洞、或无需建立连接的一次性查询 (如 DHT FindNode)
/// 使用 Token 验证合法性，不依赖 Session 内存状态
#[derive(Debug, Serialize, Deserialize)]
pub struct StatelessPacket {
    /// 临时 Token，包含时间戳和 HMAC
    pub token: Vec<u8>, 
    /// 随机 Nonce，防止相同内容的包密文相同
    pub nonce: u64,
    pub frames: Vec<Frame>,
}

/// 统一的逻辑包枚举
#[derive(Debug)]
pub enum DecryptedPacket {
    Stateful(StatefulPacket),
    Stateless(StatelessPacket),
}

impl DecryptedPacket {
    pub fn frames(&self) -> &Vec<Frame> {
        match self {
            DecryptedPacket::Stateful(p) => &p.frames,
            DecryptedPacket::Stateless(p) => &p.frames,
        }
    }
}

// --- Token 机制 (Anti-Spam / Anti-Replay) ---

/// 无状态令牌结构
#[derive(Serialize, Deserialize)]
struct TokenData {
    timestamp: i64,
    random_salt: u64,
}

pub struct TokenManager {
    secret_key: [u8; 32],
}

impl TokenManager {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { secret_key }
    }

    /// 生成令牌
    pub fn generate_token(&self) -> Vec<u8> {
        let data = TokenData {
            timestamp: Utc::now().timestamp(),
            random_salt: rand::random(),
        };
        let bytes = bincode::serialize(&data).unwrap(); // Unwrap safe for internal struct
        
        // Append HMAC
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("HMAC can take any key length");
        mac.update(&bytes);
        let result = mac.finalize();
        
        let mut token = bytes;
        token.extend_from_slice(&result.into_bytes());
        token
    }

    /// 验证令牌 (检查签名和时效性)
    pub fn validate_token(&self, token: &[u8]) -> bool {
        if token.len() < 32 { return false; } // Min length check
        
        let split_idx = token.len() - 32; // SHA256 size
        let (data_bytes, sig_bytes) = token.split_at(split_idx);

        // 1. Verify Signature
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).unwrap();
        mac.update(data_bytes);
        if mac.verify_slice(sig_bytes).is_err() {
            return false;
        }

        // 2. Verify Timestamp (防止重放过旧的包)
        if let Ok(data) = bincode::deserialize::<TokenData>(data_bytes) {
            let now = Utc::now().timestamp();
            // 允许 30 秒的时间窗口
            if (now - data.timestamp).abs() > 30 {
                return false;
            }
            return true;
        }
        false
    }
}

// --- 物理包封装 ---

pub struct RawPacket {
    pub data: Vec<u8>,
}

impl RawPacket {
    /// 加密并封装 (自动处理双模序列化)
    pub fn encrypt_and_seal(
        packet: &DecryptedPacket,
        crypto: &mut NoiseSession, // 无论 Stateful 还是 Stateless，都需要加密上下文
        target_size: Option<usize>,
        dialect: &dyn Dialect
    ) -> Result<Self> {
        
        // 1. Serialize
        let raw_content = match packet {
            DecryptedPacket::Stateful(p) => bincode::serialize(p)?,
            DecryptedPacket::Stateless(p) => bincode::serialize(p)?,
        };

        // 2. Padding (Anti-Traffic-Analysis)
        let mut padded_content = raw_content;
        if let Some(size) = target_size {
            if padded_content.len() < size {
                let padding_len = size - padded_content.len();
                let mut rng = rand::thread_rng();
                let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
                padded_content.extend(padding);
            }
        }

        // 3. Encrypt
        // 注意：Noise 协议通常是有状态的。
        // 对于 Stateless 包，通常使用预共享的 Static Key 或者临时派生的 Key。
        // 这里为了简化接口，假设传入的 crypto 已经配置好了正确的 Key State。
        let mut encrypted = vec![0u8; padded_content.len() + 16];
        let len = crypto.encrypt(&padded_content, &mut encrypted)?;
        encrypted.truncate(len);

        // 4. Dialect Obfuscation
        dialect.seal(&mut encrypted);

        Ok(RawPacket { data: encrypted })
    }

    /// 解封并解密
    pub fn unseal_and_decrypt(
        raw_data: &[u8],
        crypto: &mut NoiseSession,
        dialect: &dyn Dialect
    ) -> Result<DecryptedPacket> {
        // 1. De-obfuscate
        let encrypted_payload = dialect.open(raw_data)?;

        // 2. Decrypt
        let mut plaintext = vec![0u8; encrypted_payload.len()];
        let len = crypto.decrypt(&encrypted_payload, &mut plaintext)?;
        plaintext.truncate(len);

        // 3. Deserialize (Try Stateful first, then Stateless)
        // Bincode 没有自描述 Type ID，所以我们需要一种区分方式。
        // 生产级：在明文头部加一个 Byte 标识 (0x00=Stateful, 0x01=Stateless)
        // 或者尝试反序列化。
        
        // 尝试解析为 Stateful
        if let Ok(p) = bincode::DefaultOptions::new().allow_trailing_bytes().deserialize::<StatefulPacket>(&plaintext) {
            // 简单的校验：SessionID 不应为 0 (假设 0 保留)
            if p.session_id != 0 {
                return Ok(DecryptedPacket::Stateful(p));
            }
        }

        // 尝试解析为 Stateless
        if let Ok(p) = bincode::DefaultOptions::new().allow_trailing_bytes().deserialize::<StatelessPacket>(&plaintext) {
            return Ok(DecryptedPacket::Stateless(p));
        }

        Err(anyhow!("Unknown packet format"))
    }
}

// 引入 bincode options 必须的 trait
use bincode::Options;
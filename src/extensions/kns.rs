// etp-core/src/extensions/kns.rs

use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};
use blake3;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};
use log::{debug, warn, info};

use crate::extensions::identity::{EtpIdentity, IdentityType};
use crate::NodeID;

use futures::future::{select_ok, join_all};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Semaphore, Notify};
use std::cmp::Ordering as CmpOrdering;


// 引入必要的加密库用于验签
use ed25519_dalek::{Verifier as EdVerifier, VerifyingKey as EdVerifyingKey, Signature as EdSignature};
// 如果开启了量子加密，引入 PQC 验证
#[cfg(feature = "quantum-encryption")]
use pqcrypto_dilithium::dilithium5;
#[cfg(feature = "quantum-encryption")]
use pqcrypto_traits::sign::DetachedSignature;


// --- 引入必要的合约调用依赖 ---
#[cfg(feature = "smart-contracts")]
use ethers::providers::{Provider, Http, Middleware};
#[cfg(feature = "smart-contracts")]
use ethers::types::{TransactionRequest, Address, Bytes as EthBytes};
#[cfg(feature = "smart-contracts")]
use std::str::FromStr;

// ============================================================================
//  1. 基础结构与路径系统
// ============================================================================

const MAX_PATH_DEPTH: usize = 10;
const MAX_RECURSION: usize = 3; // 符号链接递归上限

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KnsPath {
    segments: Vec<String>,
}

// 定义合约调用的配置结构 (序列化存储在 Record Payload 中)
#[derive(Serialize, Deserialize, Debug)]
struct ContractAction {
    /// 调用模式: "evm", "json_rpc"
    scheme: String,
    /// RPC 节点地址 (e.g. "https://mainnet.infura.io/...")
    endpoint: String,
    /// 合约地址 (Hex) 或 方法名
    target: String,
    /// 调用数据 (Hex Calldata) 或 JSON Params
    data: String,
}

impl KnsPath {
    pub fn new(segments: Vec<String>) -> Result<Self> {
        if segments.len() > MAX_PATH_DEPTH {
            return Err(anyhow!("KNS Path too deep (max 10 layers)"));
        }
        Ok(Self { segments })
    }

    pub fn from_str(path: &str) -> Result<Self> {
        let segments: Vec<String> = path.split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Self::new(segments)
    }

    /// 生成盲化索引 (Blind Index)
    /// Hmac-like construction: Hash(Seed || Segment || Separator ...)
    pub fn blind_index(&self, domain_secret: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(
            &blake3::hash(domain_secret).into()
        );
        for seg in &self.segments {
            hasher.update(seg.as_bytes());
            hasher.update(b"\0"); // 防止边界攻击
        }
        hasher.finalize().into()
    }
}

/// 增强型 KNS 记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnsRecord {
    pub kind: RecordKind,
    pub payload: Vec<u8>,   // Encrypted Data
    pub version: u64,       // Timestamp / Version
    pub signature: Vec<u8>, // Authoritative Signature
    pub signer_id: NodeID,  // Who signed this?
    pub meta_hint: Vec<u8>, // Plaintext routing hints
    pub ttl: u32,           // Time to live in seconds
}

impl KnsRecord {
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // 如果 version 是未来时间（允许5分钟偏差），或者已过期
        if self.version > now + 300 { return true; }
        now > self.version + self.ttl as u64
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RecordKind {
    Static,     // 静态数据
    Pointer,    // 软链接 (CNAME), payload 解密后是另一个 KnsPath
    Delegate,   // 权限委托 (Sub-domain), payload 是新的 PubKey
    Contract,   // 智能合约调用指令
}

// ============================================================================
//  2. 安全域 (Security Domain) - 增强版
// ============================================================================

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DomainSecrets {
    master_key: [u8; 32], // 对称加密主密钥 (ChaCha20)
    blind_seed: [u8; 32], // 盲化索引种子
}

/// 访问控制与信任存储
#[derive(Debug, Clone)]
pub struct AccessControl {
    /// 写入白名单: NodeID -> (IdentityType, PublicKeyBytes)
    /// 只有在此名单中的节点签名的记录才会被接受
    authorized_writers: HashMap<NodeID, (IdentityType, Vec<u8>)>,
    
    /// 是否允许任何人读取 (如果不加密 Payload)
    /// 注意：即便 public_read 为 true，写操作仍需签名验证
    public_read: bool,
}

pub struct SecurityDomain {
    pub id: String,
    secrets: Arc<RwLock<DomainSecrets>>,
    pub cache: Arc<RwLock<HashMap<KnsPath, KnsRecord>>>,
    
    // 当前节点的身份 (用于自己发布记录)
    identity: Arc<dyn EtpIdentity>,
    
    // ACL 与 密钥库
    acl: RwLock<AccessControl>,
}

impl SecurityDomain {
    pub fn new(id: &str, identity: Arc<dyn EtpIdentity>) -> Self {
        let mut rng = rand::thread_rng();
        let mut master = [0u8; 32];
        let mut blind = [0u8; 32];
        rng.fill_bytes(&mut master);
        rng.fill_bytes(&mut blind);

        // 默认将自己加入信任列表
        let mut writers = HashMap::new();
        writers.insert(
            identity.node_id(), 
            (identity.identity_type(), identity.public_key())
        );

        Self {
            id: id.to_string(),
            secrets: Arc::new(RwLock::new(DomainSecrets {
                master_key: master,
                blind_seed: blind,
            })),
            cache: Arc::new(RwLock::new(HashMap::new())),
            identity,
            acl: RwLock::new(AccessControl {
                authorized_writers: writers,
                public_read: false,
            }),
        }
    }

    /// 授权其他节点写入权限 (添加信任)
    /// public_key: 对方的原始公钥字节流
    pub fn grant_write_access(&self, node_id: NodeID, id_type: IdentityType, public_key: Vec<u8>) {
        self.acl.write().authorized_writers.insert(node_id, (id_type, public_key));
    }

    /// 撤销写入权限
    pub fn revoke_write_access(&self, node_id: &NodeID) {
        self.acl.write().authorized_writers.remove(node_id);
    }

    /// 发布记录 (加密 + 签名)
    pub fn publish(&self, path: &KnsPath, value: &[u8], kind: RecordKind, ttl: u32) -> Result<KnsRecord> {
        let secrets = self.secrets.read();
        
        // 1. 确定性加密 (Deterministic Encryption)
        // 使用 BlindIndex 的前 12 字节作为 Nonce。
        // 这确保了对于相同的 path 和 secrets，产生的密文也是稳定的 (对于无状态缓存很重要)。
        // 警告：如果你需要每次加密都不一样，应引入随机 Nonce 并存储在 Record 中。
        // 在 KNS 设计中，我们倾向于确定性以支持 Content-Addressable Storage (CAS) 特性。
        let cipher = ChaCha20Poly1305::new(&secrets.master_key.into());
        let blind_idx = path.blind_index(&secrets.blind_seed);
        let nonce = &blind_idx[0..12].into();
        
        let encrypted_payload = cipher.encrypt(nonce, value)
            .map_err(|_| anyhow!("Payload encryption failed"))?;

        // 2. 结构化签名 (Structured Signing)
        // 签名内容 = BlindIndex(32) + EncryptedPayload(N) + KindTag(1) + TTL(4) + Version(8)
        // 包含 Version 和 TTL 是为了防止降级攻击和重放过期数据
        let version = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&blind_idx);
        sign_data.extend_from_slice(&encrypted_payload);
        sign_data.extend_from_slice(&kind.tag().to_be_bytes());
        sign_data.extend_from_slice(&ttl.to_be_bytes());
        sign_data.extend_from_slice(&version.to_be_bytes());
        
        let signature = self.identity.sign(&sign_data)
            .context("Identity signing failed")?;

        let record = KnsRecord {
            kind,
            payload: encrypted_payload,
            version,
            signature,
            signer_id: self.identity.node_id(),
            signer_type: self.identity.identity_type(), // 记录身份类型以便验证者选择算法
            meta_hint: vec![],
            ttl,
        };

        // 更新本地缓存
        self.cache.write().insert(path.clone(), record.clone());
        Ok(record)
    }

    /// 读取接口 (仅仅是 decrypt_and_verify 的包装)
    pub fn read(&self, path: &KnsPath) -> Result<Option<Vec<u8>>> {
        let cache = self.cache.read();
        if let Some(record) = cache.get(path) {
            return self.decrypt_and_verify(path, record);
        }
        Ok(None)
    }

    /// 核心：解密与完整性验证 (The Core Security Logic)
    /// 包含：TTL检查、ACL鉴权、多态验签、解密
    pub fn decrypt_and_verify(&self, path: &KnsPath, record: &KnsRecord) -> Result<Option<Vec<u8>>> {
        // 1. 基础时效性检查 (TTL)
        if record.is_expired() {
            log::debug!("KNS: Record expired. Ver={}, TTL={}", record.version, record.ttl);
            return Ok(None);
        }

        // 2. 获取验证所需的公钥 (ACL 检查)
        // 我们必须在本地 ACL 中找到 signer_id 对应的公钥。
        // 如果找不到，说明该签名者未被授权，或者是一个未知的恶意节点。
        let (id_type, pub_key) = {
            let acl = self.acl.read();
            match acl.authorized_writers.get(&record.signer_id) {
                Some((t, k)) => (*t, k.clone()),
                None => {
                    return Err(anyhow!("Permission Denied: Signer {:?} is not an authorized writer", 
                        hex::encode(&record.signer_id[0..4])));
                }
            }
        };

        // 校验记录声称的类型与 ACL 注册的类型是否一致
        if id_type != record.signer_type {
            return Err(anyhow!("Identity Type Mismatch: ACL expects {:?}, Record claims {:?}", 
                id_type, record.signer_type));
        }

        // 3. 重构签名原始数据 (Reconstruct Signed Data)
        // 必须与 publish 中的序列化顺序严格一致
        let secrets = self.secrets.read();
        let blind_idx = path.blind_index(&secrets.blind_seed);
        
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&blind_idx);
        sign_data.extend_from_slice(&record.payload);
        sign_data.extend_from_slice(&record.kind.tag().to_be_bytes());
        sign_data.extend_from_slice(&record.ttl.to_be_bytes());
        sign_data.extend_from_slice(&record.version.to_be_bytes());

        // 4. 多态签名验证 (Polymorphic Verification)
        let sig_valid = match record.signer_type {
            // Ed25519 族 (Anchor, Avatar, Citizen, Proxy, Hive...)
            IdentityType::Anchor | IdentityType::Avatar | IdentityType::Citizen | 
            IdentityType::Proxy | IdentityType::Hive | IdentityType::Token => {
                if let Ok(verifying_key) = EdVerifyingKey::from_bytes(pub_key.as_slice().try_into().unwrap_or(&[0;32])) {
                    if let Ok(signature) = EdSignature::from_slice(&record.signature) {
                        verifying_key.verify(&sign_data, &signature).is_ok()
                    } else { false }
                } else { false }
            },

            // HMAC 族 (Whisper)
            IdentityType::Whisper => {
                // 对于 Whisper，公钥其实就是 SharedSecret 的 Hash，或者我们需要 SharedSecret 本身来验证
                // 在 ACL 模型中，如果是 Whisper 身份，我们假设 trusted_roots 存的是 SharedSecret
                // 注意：这是一个特殊情况。标准 verify 需要 key。
                // 简单实现：Whisper 不具备公共可验证性，只能由持有 Secret 的人验证。
                // 这里假设 pub_key 字段存的就是 SharedSecret (在 Whisper 模式下)
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                
                if let Ok(mut mac) = HmacSha256::new_from_slice(&pub_key) {
                    mac.update(&sign_data);
                    mac.verify_slice(&record.signature).is_ok()
                } else { false }
            },

            // Post-Quantum 族 (Fortress)
            IdentityType::Fortress => {
                #[cfg(feature = "quantum-encryption")]
                {
                    // 解析复合公钥 [Len][Dilithium][Kyber] -> 取 Dilithium
                    if pub_key.len() > 4 {
                        let len_bytes: [u8; 4] = pub_key[0..4].try_into().unwrap();
                        let sign_len = u32::from_be_bytes(len_bytes) as usize;
                        if pub_key.len() >= 4 + sign_len {
                            let dilithium_pk_bytes = &pub_key[4..4+sign_len];
                            if let Ok(pk) = dilithium5::PublicKey::from_bytes(dilithium_pk_bytes) {
                                if let Ok(sig) = dilithium5::DetachedSignature::from_bytes(&record.signature) {
                                    dilithium5::verify_detached_signature(&sig, &sign_data, &pk).is_ok()
                                } else { false }
                            } else { false }
                        } else { false }
                    } else { false }
                }
                #[cfg(not(feature = "quantum-encryption"))]
                {
                    log::error!("KNS: Received Fortress signature but quantum-encryption feature is disabled.");
                    false
                }
            },

            // 不支持签名的类型
            IdentityType::Ghost | IdentityType::Chameleon => {
                // Ghost 身份通常用于临时加密，不用于 KNS 权威记录签名
                // 如果出现，视为非法
                false 
            }
        };

        if !sig_valid {
            return Err(anyhow!("Cryptographic signature verification failed"));
        }

        // 5. 解密 Payload (Decryption)
        // 使用 Domain Master Key
        // 注意：这意味着虽然写入权限可以委托给不同的人（不同的私钥签名），
        // 但所有写入者必须共享同一个 Master Key 才能加密出有效的 Payload。
        // 这符合 "Security Domain" 作为共享保密空间的定义。
        
        let cipher = ChaCha20Poly1305::new(&secrets.master_key.into());
        let nonce = &blind_idx[0..12].into(); // 复用盲索引做 Nonce
        
        let plaintext = cipher.decrypt(nonce, record.payload.as_ref())
            .map_err(|_| anyhow!("Payload decryption failed (MasterKey mismatch?)"))?;

        Ok(Some(plaintext))
    }
}

// 辅助 trait 用于序列化枚举 tag
trait Tagged { fn tag(&self) -> u8; }
impl Tagged for RecordKind {
    fn tag(&self) -> u8 {
        match self {
            RecordKind::Static => 1,
            RecordKind::Pointer => 2,
            RecordKind::Delegate => 3,
            RecordKind::Contract => 4,
        }
    }
}

// ============================================================================
//  3. KNS Kernel & Deep Resolution
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum ResolutionPriority {
    LocalOnly,
    CachePreferred,
    NetworkOnly,
}

#[async_trait::async_trait]
pub trait ExternalResolver: Send + Sync {
    fn provider_id(&self) -> &str;
    async fn resolve_blind(&self, blind_index: &[u8; 32]) -> Result<Option<KnsRecord>>;
}

// --- 辅助结构 ---

struct HealthState {
    failures: AtomicUsize,
    last_failure: RwLock<SystemTime>,
    // 移动平均响应时间 (EMA)，用于智能超时控制
    latency_ema_ms: AtomicU64,
}

impl HealthState {
    fn new() -> Self {
        Self {
            failures: AtomicUsize::new(0),
            last_failure: RwLock::new(UNIX_EPOCH),
            latency_ema_ms: AtomicU64::new(1000), // 初始假设 1秒
        }
    }

    fn update_metric(&self, success: bool, latency_ms: u64) {
        if success {
            self.failures.store(0, Ordering::Relaxed);
            // 更新 EMA: New = Old * 0.8 + Current * 0.2
            let old = self.latency_ema_ms.load(Ordering::Relaxed);
            let new = (old * 4 + latency_ms) / 5;
            self.latency_ema_ms.store(new, Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
            *self.last_failure.write() = SystemTime::now();
        }
    }
}

pub struct KnsKernel {
    domains: RwLock<HashMap<String, Arc<SecurityDomain>>>,
    resolvers: RwLock<Vec<Arc<dyn ExternalResolver>>>,
    
    // 健康监控 & 熔断器
    health_monitor: DashMap<String, Arc<HealthState>>,

    // 全局并发控制 (防止 FD 耗尽)
    network_semaphore: Arc<Semaphore>,
    
    // 防重放缓存: Signature -> InsertionTime
    replay_cache: Arc<DashMap<Vec<u8>, SystemTime>>,
    
    // 后台任务控制 (用于优雅停机)
    shutdown_notify: Arc<Notify>,
}

// 必须实现 Drop 以便停止后台清理任务 (虽然 lazy_static 或全局单例不需要，但作为 Lib 必须严谨)
impl Drop for KnsKernel {
    fn drop(&mut self) {
        self.shutdown_notify.notify_waiters();
    }
}

impl KnsKernel {
    pub fn new() -> Self {
        let kernel = Self {
            domains: RwLock::new(HashMap::new()),
            resolvers: RwLock::new(Vec::new()),
            health_monitor: DashMap::new(),
            network_semaphore: Arc::new(Semaphore::new(256)), // 提高并发上限至 256
            replay_cache: Arc::new(DashMap::new()),
            shutdown_notify: Arc::new(Notify::new()),
        };

        // 启动后台维护线程 (Garbage Collection)
        kernel.spawn_maintenance_task();
        kernel
    }

    /// 启动后台维护任务：清理过期的重放缓存和健康状态
    fn spawn_maintenance_task(&self) {
        let replay_cache = self.replay_cache.clone();
        let notify = self.shutdown_notify.clone();

        tokio::spawn(async move {
            loop {
                // 每 60 秒执行一次清理
                tokio::select! {
                    _ = notify.notified() => break, // 收到停机信号退出
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                }

                let now = SystemTime::now();
                // 1. 清理防重放缓存 (TTL 5分钟)
                // 任何超过5分钟的签名记录都视为过期，可以被安全移除
                replay_cache.retain(|_, timestamp| {
                    match now.duration_since(*timestamp) {
                        Ok(age) => age < Duration::from_secs(300),
                        Err(_) => false, // 时间倒流，安全起见移除
                    }
                });

                // 2. (可选) 这里也可以清理 health_monitor 中长期未使用的 entry
            }
        });
    }

    // --- 基础管理接口 ---

    pub fn create_domain(&self, id: &str, identity: Arc<dyn EtpIdentity>) -> Arc<SecurityDomain> {
        let domain = Arc::new(SecurityDomain::new(id, identity));
        self.domains.write().insert(id.to_string(), domain.clone());
        domain
    }

    pub fn get_domain(&self, id: &str) -> Option<Arc<SecurityDomain>> {
        self.domains.read().get(id).cloned()
    }

    pub fn register_resolver(&self, resolver: Arc<dyn ExternalResolver>) {
        self.health_monitor.insert(
            resolver.provider_id().to_string(), 
            Arc::new(HealthState::new())
        );
        self.resolvers.write().push(resolver);
    }

    // --- 高级接口 ---

    pub async fn batch_resolve(
        &self,
        domain_id: &str,
        paths: Vec<KnsPath>,
        priority: ResolutionPriority
    ) -> Vec<Result<Vec<u8>>> {
        let mut futures = Vec::new();
        for path in paths {
            futures.push(self.resolve(domain_id, &path, priority));
        }
        join_all(futures).await
    }

    pub fn invalidate_path(&self, domain_id: &str, path: &KnsPath) -> Result<()> {
        let domain = self.get_domain(domain_id)
            .ok_or_else(|| anyhow!("Domain not found"))?;
        domain.cache.write().remove(path);
        Ok(())
    }

    // --- 核心解析逻辑 ---

    pub async fn resolve(
        &self, 
        domain_id: &str, 
        path: &KnsPath, 
        priority: ResolutionPriority
    ) -> Result<Vec<u8>> {
        self.resolve_recursive(domain_id, path, priority, 0).await
    }

    #[async_recursion::async_recursion]
    async fn resolve_recursive(
        &self,
        domain_id: &str,
        path: &KnsPath,
        priority: ResolutionPriority,
        depth: usize
    ) -> Result<Vec<u8>> {
        if depth > MAX_RECURSION {
            return Err(anyhow!("KNS Recursion limit exceeded"));
        }

        let domain = self.get_domain(domain_id)
            .ok_or_else(|| anyhow!("Domain '{}' not found", domain_id))?;

        // 1. 获取 Record (Local Logic)
        let mut record_opt = None;
        let mut needs_refresh = false;

        {
            let cache = domain.cache.read();
            if let Some(rec) = cache.get(path) {
                if !rec.is_expired() {
                    record_opt = Some(rec.clone());
                    // Proactive Refresh Check: 剩余寿命 < 20%
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    let expiry = rec.version + rec.ttl as u64;
                    if expiry > now && (expiry - now) < (rec.ttl as u64 / 5) {
                        needs_refresh = true;
                    }
                }
            }
        }

        // 如果需要刷新且允许联网，强制进入网络流程（为了数据一致性，这里选择阻塞刷新）
        if needs_refresh && !matches!(priority, ResolutionPriority::LocalOnly) {
             record_opt = None; 
        }

        // 2. 网络解析 (Network Logic)
        if record_opt.is_none() && !matches!(priority, ResolutionPriority::LocalOnly) {
            let (blind_idx, _) = {
                let secrets = domain.secrets.read();
                (path.blind_index(&secrets.blind_seed), secrets.master_key)
            };

            // 根据优先级选择策略：Race (竞速) 或 Quorum (共识)
            // [新特性 1] Quorum Consensus
            // 如果优先级是 ConsensusStrict，我们需要多个源的确认
            let fetch_result = if matches!(priority, ResolutionPriority::ConsensusStrict) {
                self.fetch_quorum(&blind_idx).await
            } else {
                self.fetch_race(&blind_idx).await
            };

            match fetch_result {
                Ok(rec) => {
                    domain.cache.write().insert(path.clone(), rec.clone());
                    record_opt = Some(rec);
                },
                Err(e) => {
                    // 如果本地也没有，那就是彻底失败
                    if record_opt.is_none() {
                        return Err(e);
                    }
                    // 否则降级使用本地（即使快过期）
                    log::warn!("KNS: Network fetch failed, using stale/local cache: {}", e);
                }
            }
        }

        let record = record_opt.ok_or_else(|| anyhow!("KNS Path not found: {:?}", path))?;

        // 3. 安全校验 (Security Check)
        // 3.1 防重放攻击 (Anti-Replay)
        // 仅对具有副作用的记录类型开启严格检查
        if matches!(record.kind, RecordKind::Delegate | RecordKind::Contract) {
            if self.replay_cache.contains_key(&record.signature) {
                return Err(anyhow!("Security Alert: Signature Replay Detected"));
            }
            self.replay_cache.insert(record.signature.clone(), SystemTime::now());
        }

        // 4. 解密与验证 (Decryption & Verification)
        let plaintext = domain.decrypt_and_verify(path, &record)?
            .ok_or_else(|| anyhow!("Record verification/decryption failed"))?;

        // 5. 业务分发 (Dispatch)
        match record.kind {
            RecordKind::Static => Ok(plaintext),
            
            RecordKind::Pointer => {
                let target_str = String::from_utf8(plaintext).context("Invalid Pointer")?;
                let target_path = KnsPath::from_str(&target_str)?;
                log::debug!("KNS: Dereferencing {} -> {}", path.segments.join("/"), target_str);
                
                // [新特性 2] Hot-Path Prefetching (预取)
                // 如果我们解析了一个 Pointer，很有可能用户接下来会解析 target_path 的子路径
                // 虽然我们无法预知子路径，但我们可以预先 "Warm Up" target_path 本身
                // 在异步任务中执行，不阻塞当前返回
                /* 
                   注意：由于这是递归调用，resolve_recursive 会处理 target_path。
                   Prefetching 的意义在于，如果 Pointer 指向的是一个目录索引，
                   我们可以在这里并行去获取该目录下的常用元数据。
                   但在当前架构下，直接递归调用已经是最优解。
                   为了体现 Prefetching，我们假设 Pointer 指向的是跨域的引用，
                   我们可以预先加载目标域的 Public Keys。
                */
                
                self.resolve_recursive(domain_id, &target_path, priority, depth + 1).await
            },
            
            RecordKind::Delegate => {
                let target_domain_id = String::from_utf8(plaintext).context("Invalid Delegate")?;
                log::debug!("KNS: Delegating to domain {}", target_domain_id);
                self.resolve_recursive(&target_domain_id, path, priority, depth + 1).await
            },
            
            RecordKind::Contract => {
                let action: ContractAction = serde_json::from_slice(&plaintext)
                    .context("Invalid ContractAction")?;
                self.execute_contract_call(action).await
            }
        }
    }

    // --- 网络策略实现 ---

    /// 策略 A: 竞速模式 (Race)
    /// 同时向所有健康的 Resolver 发起请求，取最快返回的非空结果
    async fn fetch_race(&self, blind_idx: &[u8; 32]) -> Result<KnsRecord> {
        let resolvers = self.filter_healthy_resolvers();
        if resolvers.is_empty() { return Err(anyhow!("No healthy resolvers available")); }

        let mut futures = Vec::new();
        for r in resolvers {
            let idx = *blind_idx;
            let sem = self.network_semaphore.clone();
            let health_map = self.health_monitor.clone();
            let rid = r.provider_id().to_string();

            futures.push(Box::pin(async move {
                let _permit = sem.acquire().await?;
                let start = std::time::Instant::now();
                
                let res = r.resolve_blind(&idx).await;
                
                let duration = start.elapsed().as_millis() as u64;
                if let Some(h) = health_map.get(&rid) {
                    h.update_metric(res.is_ok(), duration);
                }

                match res {
                    Ok(Some(rec)) => Ok(rec),
                    Ok(None) => Err(anyhow!("Not found")), // 转为 Err 以便 select_ok 忽略
                    Err(e) => Err(e),
                }
            }));
        }

        match select_ok(futures).await {
            Ok((rec, _)) => Ok(rec),
            Err(_) => Err(anyhow!("Record not found in any resolver (Race)")),
        }
    }

    /// 策略 B: 共识模式 (Quorum)
    /// 向所有 Resolver 发起请求，收集结果，要求 >50% 的节点返回相同且有效的数据
    async fn fetch_quorum(&self, blind_idx: &[u8; 32]) -> Result<KnsRecord> {
        let resolvers = self.filter_healthy_resolvers();
        let total = resolvers.len();
        if total == 0 { return Err(anyhow!("No resolvers")); }
        
        let threshold = (total / 2) + 1; // 多数派

        let mut futures = Vec::new();
        for r in resolvers {
            let idx = *blind_idx;
            let sem = self.network_semaphore.clone();
            // Quorum 模式下不更新 Health，或者是保守更新
            futures.push(Box::pin(async move {
                let _permit = sem.acquire().await;
                r.resolve_blind(&idx).await
            }));
        }

        let results = join_all(futures).await;
        
        // 统计结果 (Hash(Record) -> Count)
        // 我们只比较 payload 和 signature，忽略 TTL 差异
        let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut records: HashMap<Vec<u8>, KnsRecord> = HashMap::new();

        for res in results {
            if let Ok(Some(rec)) = res {
                // 用于比对的关键字段：payload + signature
                let mut finger_print = Vec::new();
                finger_print.extend_from_slice(&rec.payload);
                finger_print.extend_from_slice(&rec.signature);
                
                *counts.entry(finger_print.clone()).or_default() += 1;
                records.entry(finger_print).or_insert(rec);
            }
        }

        // 检查是否有结果满足阈值
        for (fp, count) in counts {
            if count >= threshold {
                return Ok(records.remove(&fp).unwrap());
            }
        }

        Err(anyhow!("Consensus failed: No record reached quorum {}/{}", threshold, total))
    }

    /// 辅助：筛选健康的解析器
    fn filter_healthy_resolvers(&self) -> Vec<Arc<dyn ExternalResolver>> {
        let all = self.resolvers.read();
        let mut valid = Vec::new();
        let now = SystemTime::now();

        for r in all.iter() {
            let id = r.provider_id();
            if let Some(h) = self.health_monitor.get(id) {
                // 熔断逻辑：连续失败 > 5 且 冷却时间 < 30s
                let fails = h.failures.load(Ordering::Relaxed);
                if fails > 5 {
                    let last = *h.last_failure.read();
                    if now.duration_since(last).unwrap_or_default() < Duration::from_secs(30) {
                        continue; // Skip (Open State)
                    } else {
                        // Half-Open: 允许尝试，但计数器保持高位，若再失败则立即熔断
                    }
                }
            }
            valid.push(r.clone());
        }
        valid
    }

    // --- 智能合约执行 (完整保留) ---
    async fn execute_contract_call(&self, action: ContractAction) -> Result<Vec<u8>> {
        #[cfg(not(feature = "smart-contracts"))]
        {
            return Err(anyhow!("Smart contracts disabled"));
        }

        #[cfg(feature = "smart-contracts")]
        {
            match action.scheme.as_str() {
                "evm" => {
                    let provider = Provider::<Http>::try_from(action.endpoint.as_str())?;
                    let address = Address::from_str(&action.target)?;
                    let data_bytes = hex::decode(action.data.trim_start_matches("0x"))?;
                    
                    let tx = TransactionRequest::new().to(address).data(EthBytes::from(data_bytes));
                    // 增加超时控制
                    let result = tokio::time::timeout(
                        Duration::from_secs(10), 
                        provider.call(&tx, None)
                    ).await??;
                    
                    Ok(result.to_vec())
                },
                "json_rpc" | "wasm" => {
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .build()?;
                        
                    let params: serde_json::Value = serde_json::from_str(&action.data)?;
                    let rpc_body = serde_json::json!({
                        "jsonrpc": "2.0", "method": action.target, "params": params, "id": 1
                    });
                    
                    let resp = client.post(&action.endpoint).json(&rpc_body).send().await?;
                    if !resp.status().is_success() {
                        return Err(anyhow!("RPC Error: {}", resp.status()));
                    }
                    let resp_json: serde_json::Value = resp.json().await?;
                    if let Some(res) = resp_json.get("result") {
                        Ok(serde_json::to_vec(res)?)
                    } else {
                        Err(anyhow!("RPC response missing 'result'"))
                    }
                },
                _ => Err(anyhow!("Unsupported scheme: {}", action.scheme))
            }
        }
    }
}

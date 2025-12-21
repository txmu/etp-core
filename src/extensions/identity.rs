// etp-core/src/extensions/identity.rs

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::fmt::Debug;
use anyhow::{Result, anyhow, Context};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::{Rng, RngCore};
use parking_lot::RwLock;

// Crypto Primitives
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use blake3;

use crate::NodeID;

use tokio_util::sync::CancellationToken;

// ============================================================================
//  1. 基础定义
// ============================================================================

/// 匿名等级定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub enum AnonymityLevel {
    None,           // 实名/基石
    Pseudonymous,   // 假名 (长期 ID)
    Group,          // 群体 (无法区分个体)
    Deniable,       // 可否认 (无法证明是你说的)
    Unlinkable,     // 不可关联 (每次都不一样)
    Ghost,          // 幽灵 (内存级一次性)
}

/// 身份类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityType {
    Anchor, Avatar, Ghost, Hive, Citizen, Token, Proxy, Chameleon, Whisper, Fortress
}

/// ETP 身份核心特征
pub trait EtpIdentity: Send + Sync + Debug {
    /// 获取身份类型
    fn identity_type(&self) -> IdentityType;
    
    /// 获取匿名等级
    fn anonymity_level(&self) -> AnonymityLevel;

    /// 获取用于网络寻址的 ID (NodeID)
    fn node_id(&self) -> NodeID;
    
    /// 获取公钥 (序列化字节流)
    fn public_key(&self) -> Vec<u8>;
    
    /// 对数据签名 (用于 KNS 发布或握手)
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// 验证签名
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool;
    
    /// 身份是否过期
    fn expiration(&self) -> Option<SystemTime>;
    
    /// 安全擦除私钥
    fn zeroize_secrets(&mut self);
    
    /// 获取用于加密通信的 X25519 私钥 (可选)
    /// Ghost 等身份可能只支持加密不支持签名
    fn encryption_secret(&self) -> Option<StaticSecret>;
}

// ============================================================================
//  2. 十种身份实现
// ============================================================================

// --- 1. Anchor Identity (基石) ---
// 用途：长期基础设施，不可否认，高安全性
#[derive(Debug)]
pub struct AnchorIdentity {
    key: SigningKey,
    created_at: SystemTime,
}

impl AnchorIdentity {
    pub fn new() -> Self {
        Self {
            key: SigningKey::generate(&mut rand::thread_rng()),
            created_at: SystemTime::now(),
        }
    }
    
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
            created_at: SystemTime::now(),
        }
    }
}

impl EtpIdentity for AnchorIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Anchor }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::None }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(self.key.verifying_key().as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if let Ok(signature) = Signature::from_slice(sig) {
            return self.key.verifying_key().verify(data, &signature).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { None }
    
    fn zeroize_secrets(&mut self) {
        // SigningKey 内部通常已经实现了 Zeroize，但我们这里无法直接调用内部字段的 zeroize
        // 实际上 ed25519-dalek 的 Keypair 处理较好。
        // 这里只是示意接口调用
    }
    
    fn encryption_secret(&self) -> Option<StaticSecret> {
        // 将 Ed25519 转换为 X25519 (仅用于兼容，通常 Anchor 不直接用于 ECDH)
        // 为安全起见，Anchor 应该只用于签名
        None 
    }
}

// --- 2. Avatar Identity (化身) ---
// 用途：用户日常身份，支持轮换
#[derive(Debug)]
pub struct AvatarIdentity {
    current_key: RwLock<SigningKey>,
    // 历史公钥链，用于证明身份连续性 (简化版)
    version: u32,
}

impl AvatarIdentity {
    pub fn new() -> Self {
        Self {
            current_key: RwLock::new(SigningKey::generate(&mut rand::thread_rng())),
            version: 1,
        }
    }
    
    pub fn rotate(&self) {
        let mut guard = self.current_key.write();
        *guard = SigningKey::generate(&mut rand::thread_rng());
        // 实际逻辑应包含用旧钥签新钥
    }
}

impl EtpIdentity for AvatarIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Avatar }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Pseudonymous }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(self.current_key.read().verifying_key().as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        self.current_key.read().verifying_key().to_bytes().to_vec()
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.current_key.read().sign(data).to_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if let Ok(signature) = Signature::from_slice(sig) {
            return self.current_key.read().verifying_key().verify(data, &signature).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { None }
    fn zeroize_secrets(&mut self) { /* handled by RwLock drop mostly */ }
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 3. Ghost Identity (幽灵) ---
// 用途：一次性，阅后即焚，无签名能力
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct GhostIdentity {
    secret: [u8; 32],
}

impl GhostIdentity {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self { secret }
    }
}

impl EtpIdentity for GhostIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Ghost }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Ghost }
    
    fn node_id(&self) -> NodeID {
        // Ghost ID 是 Ephemeral Pubkey 的哈希
        let static_secret = StaticSecret::from(self.secret);
        let pubkey = XPublicKey::from(&static_secret);
        blake3::hash(pubkey.as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        let static_secret = StaticSecret::from(self.secret);
        let pubkey = XPublicKey::from(&static_secret);
        pubkey.as_bytes().to_vec()
    }
    
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow!("Ghost identity cannot sign messages"))
    }
    
    fn verify(&self, _data: &[u8], _sig: &[u8]) -> bool {
        false // Ghost 无法提供签名验证
    }
    
    fn expiration(&self) -> Option<SystemTime> { 
        Some(SystemTime::now()) // 立即过期
    }
    
    fn zeroize_secrets(&mut self) {
        self.secret.zeroize();
    }
    
    fn encryption_secret(&self) -> Option<StaticSecret> {
        Some(StaticSecret::from(self.secret))
    }
}

// --- 4. Hive Identity (蜂群) ---
// 用途：多签/门限签名。这里模拟一个 N-of-N 的聚合身份
// 实际上这里存储的是部分私钥，verify 验证的是聚合签名
#[derive(Debug)]
pub struct HiveIdentity {
    shard_key: SigningKey, // 当前节点的私钥分片
    group_pubkey: VerifyingKey, // 群体公钥
    members: usize,
}

impl HiveIdentity {
    pub fn new(group_pub_bytes: [u8; 32]) -> Result<Self> {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let group_pubkey = VerifyingKey::from_bytes(&group_pub_bytes)
            .map_err(|_| anyhow!("Invalid group key"))?;
        Ok(Self {
            shard_key: key,
            group_pubkey,
            members: 3,
        })
    }
}

impl EtpIdentity for HiveIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Hive }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Group }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(self.group_pubkey.as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        self.group_pubkey.as_bytes().to_vec()
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 实际上这应该是一个多轮 MPC 交互过程
        // 这里我们返回部分签名 (Partial Signature)
        // 标记为: [0xHV][ShardID][Sig]
        let sig = self.shard_key.sign(data);
        let mut out = vec![0x48, 0x56]; // "HV"
        out.extend_from_slice(&sig.to_bytes());
        Ok(out)
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        // 验证完整的群体签名
        if let Ok(signature) = Signature::from_slice(sig) {
            return self.group_pubkey.verify(data, &signature).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { None }
    fn zeroize_secrets(&mut self) {}
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 5. Citizen Identity (公民) ---
// 用途：绑定 PoW，抗女巫
#[derive(Debug)]
pub struct CitizenIdentity {
    key: SigningKey,
    nonce: u64, // PoW Nonce
    difficulty: u8,
}

impl CitizenIdentity {
    /// 生产级异步工厂：生成带有 PoW 证明的公民身份
    /// 
    /// # Arguments
    /// * `difficulty` - 目标哈希前导零位难度
    /// * `cancel_token` - 可选的取消令牌。若提供，可在外部随时停止计算
    pub async fn create_async(
        difficulty: u8, 
        cancel_token: Option<CancellationToken>
    ) -> Result<Self> {
        info!("Citizen: Initiating PoW (Difficulty: {}). Resources allocated.", difficulty);
        
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let key_bytes = signing_key.to_bytes();

        // 将任务卸载至 spawn_blocking 以保护 Reactor 线程
        let nonce = tokio::task::spawn_blocking(move || {
            let mut current_nonce = 0u64;
            loop {
                // 每 16384 次迭代检查一次取消状态，平衡计算效率与响应灵敏度
                if current_nonce & 0x3FFF == 0 {
                    if let Some(ref token) = cancel_token {
                        if token.is_cancelled() {
                            return Err(anyhow!("Citizen PoW interrupted by cancellation token"));
                        }
                    }
                }

                let mut hasher = blake3::Hasher::new();
                hasher.update(&pub_bytes);
                hasher.update(&current_nonce.to_be_bytes());
                let hash = hasher.finalize();

                if Self::check_difficulty(hash.as_bytes(), difficulty) {
                    return Ok(current_nonce);
                }

                // 移除 1_000_000 安全阀，由外部 cancel_token 接管生命周期控制
                current_nonce = current_nonce.wrapping_add(1);
            }
        }).await.context("Citizen PoW task panic")??;

        debug!("Citizen: PoW successful. Nonce found: {}", nonce);

        Ok(Self {
            key: SigningKey::from_bytes(&key_bytes),
            nonce,
            difficulty,
        })
    }

    /// 核心判定逻辑：统计 BLAKE3 结果的前导零
    fn check_difficulty(hash: &[u8], target_difficulty: u8) -> bool {
        let mut actual_zeros = 0;
        for &byte in hash {
            if byte == 0 {
                actual_zeros += 8;
            } else {
                actual_zeros += byte.leading_zeros() as usize;
                break;
            }
        }
        actual_zeros >= target_difficulty as usize
    }
}

impl EtpIdentity for CitizenIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Citizen }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Pseudonymous }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(self.key.verifying_key().as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        // 返回 PubKey + Nonce + Diff
        let mut buf = self.key.verifying_key().to_bytes().to_vec();
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.push(self.difficulty);
        buf
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if let Ok(s) = Signature::from_slice(sig) {
            return self.key.verifying_key().verify(data, &s).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { None }
    fn zeroize_secrets(&mut self) {}
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 6. Token Identity (盲视) ---
// 用途：持有令牌，证明权限但不暴露身份
#[derive(Debug)]
pub struct TokenIdentity {
    token_data: Vec<u8>,
    issuer_sig: Vec<u8>, // 盲签名结果
    ephemeral_key: SigningKey, // 用于本次会话的临时密钥
}

impl TokenIdentity {
    pub fn new(token: Vec<u8>, sig: Vec<u8>) -> Self {
        Self {
            token_data: token,
            issuer_sig: sig,
            ephemeral_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }
}

impl EtpIdentity for TokenIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Token }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Unlinkable }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(&self.token_data).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        // 展示 Token + IssuerSig 以证明合法性
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.token_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.token_data);
        buf.extend_from_slice(&self.issuer_sig);
        buf
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 使用临时密钥签名，证明持有该 Token
        Ok(self.ephemeral_key.sign(data).to_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        // 验证者需要先验证 Token 对 Issuer 的有效性，再验证 Sig 对 EphemeralKey 的有效性
        // 这里简化为验证 EphemeralKey
        if let Ok(s) = Signature::from_slice(sig) {
            return self.ephemeral_key.verifying_key().verify(data, &s).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { Some(SystemTime::now() + Duration::from_secs(3600)) }
    fn zeroize_secrets(&mut self) {}
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 7. Proxy Identity (代理) ---
// 用途：授权委托
#[derive(Debug)]
pub struct ProxyIdentity {
    sub_key: SigningKey,
    master_pub: VerifyingKey,
    delegation_sig: Signature, // Master 对 SubKey 的签名
    scope: String,
    expire: SystemTime,
}

impl ProxyIdentity {
    pub fn new(master: &AnchorIdentity, scope: &str, ttl_sec: u64) -> Self {
        let sub = SigningKey::generate(&mut rand::thread_rng());
        let expire = SystemTime::now() + Duration::from_secs(ttl_sec);
        
        // 构造委托书
        let mut doc = Vec::new();
        doc.extend_from_slice(sub.verifying_key().as_bytes());
        doc.extend_from_slice(scope.as_bytes());
        let exp_ts = expire.duration_since(UNIX_EPOCH).unwrap().as_secs();
        doc.extend_from_slice(&exp_ts.to_be_bytes());
        
        let sig_bytes = master.sign(&doc).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        
        Self {
            sub_key: sub,
            master_pub: master.key.verifying_key(),
            delegation_sig: sig,
            scope: scope.to_string(),
            expire,
        }
    }
}

impl EtpIdentity for ProxyIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Proxy }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Pseudonymous }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(self.sub_key.verifying_key().as_bytes()).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        // 返回 Proxy Bundle
        self.sub_key.verifying_key().as_bytes().to_vec()
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        if SystemTime::now() > self.expire {
            return Err(anyhow!("Proxy identity expired"));
        }
        Ok(self.sub_key.sign(data).to_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if let Ok(s) = Signature::from_slice(sig) {
            return self.sub_key.verifying_key().verify(data, &s).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { Some(self.expire) }
    fn zeroize_secrets(&mut self) {}
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 8. Chameleon Identity (拟态) ---
// 用途：隐写术，无公钥可见
#[derive(Debug)]
pub struct ChameleonIdentity {
    seed: [u8; 32],
}

impl ChameleonIdentity {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self { seed }
    }
}

impl EtpIdentity for ChameleonIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Chameleon }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Unlinkable }
    
    fn node_id(&self) -> NodeID {
        // ID 是动态变化的
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed);
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_be_bytes());
        hasher.finalize().into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        // 拟态身份不公开公钥，而是返回随机噪声
        let mut noise = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut noise);
        noise
    }
    
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        // 拟态签名通常是隐写的，这里返回空
        Ok(vec![])
    }
    
    fn verify(&self, _data: &[u8], _sig: &[u8]) -> bool { false }
    fn expiration(&self) -> Option<SystemTime> { None }
    fn zeroize_secrets(&mut self) { self.seed.zeroize(); }
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 9. Whisper Identity (否认) ---
// 用途：可否认认证 (HMAC)
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct WhisperIdentity {
    shared_secret: [u8; 32], // 对称密钥
}

impl WhisperIdentity {
    pub fn new(secret: [u8; 32]) -> Self { Self { shared_secret: secret } }
}

impl EtpIdentity for WhisperIdentity {
    fn identity_type(&self) -> IdentityType { IdentityType::Whisper }
    fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::Deniable }
    
    fn node_id(&self) -> NodeID {
        blake3::hash(&self.shared_secret).into()
    }
    
    fn public_key(&self) -> Vec<u8> {
        // 公钥就是共享密钥的哈希 (为了协商)
        blake3::hash(&self.shared_secret).as_bytes().to_vec()
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 使用 HMAC 签名。任何知道 Secret 的人都能签，所以可否认
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.shared_secret)
            .map_err(|_| anyhow!("HMAC error"))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    
    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        type HmacSha256 = Hmac<Sha256>;
        if let Ok(mut mac) = HmacSha256::new_from_slice(&self.shared_secret) {
            mac.update(data);
            return mac.verify_slice(sig).is_ok();
        }
        false
    }
    
    fn expiration(&self) -> Option<SystemTime> { None }
    fn zeroize_secrets(&mut self) { self.shared_secret.zeroize(); }
    fn encryption_secret(&self) -> Option<StaticSecret> { None }
}

// --- 10. Fortress Identity (堡垒)（条件编译实现） ---
// 用途：后量子安全


// ----------------------------------------------------------------------------
// 场景 A: 开启了 quantum-encryption 特性 -> 真实实现
// ----------------------------------------------------------------------------
#[cfg(feature = "quantum-encryption")]
mod fortress_impl {
    use super::*;
    use pqcrypto_kyber::kyber1024; 
    use pqcrypto_dilithium::dilithium5; 
    use pqcrypto_traits::sign::{SecretKey as SignSecret, PublicKey as SignPublic, DetachedSignature};
    use pqcrypto_traits::kem::{SecretKey as KemSecret, PublicKey as KemPublic, Ciphertext};

    #[derive(Debug)]
    pub struct FortressIdentity {
        sign_pk: dilithium5::PublicKey,
        sign_sk: dilithium5::SecretKey,
        kem_pk: kyber1024::PublicKey,
        kem_sk: kyber1024::SecretKey,
    }

    impl FortressIdentity {
        pub fn new() -> Self {
            let (sign_pk, sign_sk) = dilithium5::keypair();
            let (kem_pk, kem_sk) = kyber1024::keypair();
            Self { sign_pk, sign_sk, kem_pk, kem_sk }
        }
        
        pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
                .map_err(|_| anyhow!("Invalid Kyber ciphertext"))?;
            let shared_secret = kyber1024::decapsulate(&ct, &self.kem_sk);
            Ok(shared_secret.as_bytes().to_vec())
        }
    }

    impl EtpIdentity for FortressIdentity {
        fn identity_type(&self) -> IdentityType { IdentityType::Fortress }
        fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::None }
        
        fn node_id(&self) -> NodeID {
            let mut hasher = blake3::Hasher::new();
            hasher.update(self.sign_pk.as_bytes());
            hasher.update(self.kem_pk.as_bytes());
            hasher.finalize().into()
        }
        
        fn public_key(&self) -> Vec<u8> {
            let sign_bytes = self.sign_pk.as_bytes();
            let kem_bytes = self.kem_pk.as_bytes();
            let mut buf = Vec::with_capacity(4 + sign_bytes.len() + kem_bytes.len());
            buf.extend_from_slice(&(sign_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(sign_bytes);
            buf.extend_from_slice(kem_bytes);
            buf
        }
        
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            let signature = dilithium5::detached_sign(data, &self.sign_sk);
            Ok(signature.as_bytes().to_vec())
        }
        
        fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
            if let Ok(signature) = dilithium5::DetachedSignature::from_bytes(sig) {
                return dilithium5::verify_detached_signature(&signature, data, &self.sign_pk).is_ok();
            }
            false
        }
        
        fn expiration(&self) -> Option<SystemTime> { None }
        fn zeroize_secrets(&mut self) { /* PQ libs handle drop */ }
        fn encryption_secret(&self) -> Option<StaticSecret> { None }
    }
}

// ----------------------------------------------------------------------------
// 场景 B: 未开启 quantum-encryption -> Stub 实现
// ----------------------------------------------------------------------------
#[cfg(not(feature = "quantum-encryption"))]
mod fortress_impl {
    use super::*;

    #[derive(Debug)]
    pub struct FortressIdentity;

    impl FortressIdentity {
        pub fn new() -> Self {
            // 在运行时发出警告，而不是编译错误，保持接口兼容性
            log::warn!("FortressIdentity initialized in STUB mode (quantum features disabled).");
            Self
        }
    }

    impl EtpIdentity for FortressIdentity {
        fn identity_type(&self) -> IdentityType { IdentityType::Fortress }
        fn anonymity_level(&self) -> AnonymityLevel { AnonymityLevel::None }
        
        fn node_id(&self) -> NodeID { [0u8; 32] } // Dummy ID
        
        fn public_key(&self) -> Vec<u8> { vec![] }
        
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("Quantum encryption feature is disabled"))
        }
        
        fn verify(&self, _data: &[u8], _sig: &[u8]) -> bool { false }
        
        fn expiration(&self) -> Option<SystemTime> { None }
        fn zeroize_secrets(&mut self) {}
        fn encryption_secret(&self) -> Option<StaticSecret> { None }
    }
}

// 重新导出当前环境下的实现
pub use fortress_impl::FortressIdentity;

// ============================================================================
//  3. 身份管理器 (Factory)
// ============================================================================

pub struct IdentityManager;

impl IdentityManager {
    pub fn create_anchor() -> Arc<dyn EtpIdentity> {
        Arc::new(AnchorIdentity::new())
    }
    
    pub fn create_ghost() -> Arc<dyn EtpIdentity> {
        Arc::new(GhostIdentity::new())
    }
    
    // ... helper for others
}
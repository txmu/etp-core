// etp-core/src/security/zkp_negotiation.rs

use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use blake3;
use rand::Rng;
use constant_time_eq::constant_time_eq; // 需要在 Cargo.toml 添加 constant_time_eq
use anyhow::{Result, anyhow};
use log::{debug, warn, info};
use parking_lot::RwLock;

/// 能力 ID (例如 "etp.flavor.vpn.v1")
pub type CapabilityId = String;

/// 协商载荷 (网络传输格式)
#[derive(Debug, Clone)]
pub struct NegotiationPayload {
    /// 随机盐 (Nonce)，增加熵
    pub salt: [u8; 16],
    /// 能力哈希列表 (包含真实能力和混淆用的假能力)
    pub capability_hashes: Vec<[u8; 32]>,
}

/// 零知识能力协商器
pub struct ZkpNegotiator {
    /// 本地支持的所有能力 ID 注册表
    local_capabilities: RwLock<HashSet<CapabilityId>>,
}

impl ZkpNegotiator {
    pub fn new() -> Self {
        Self {
            local_capabilities: RwLock::new(HashSet::new()),
        }
    }

    /// 注册本地支持的能力
    pub fn register_capability(&self, cap_id: CapabilityId) {
        self.local_capabilities.write().insert(cap_id);
    }

    /// 生成协商包 (Client/Server 发送自己的支持列表)
    /// shared_secret: Noise 协议派生的会话密钥
    pub fn generate_offer(&self, shared_secret: &[u8]) -> NegotiationPayload {
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; 16];
        rng.fill(&mut salt);

        let caps = self.local_capabilities.read();
        let mut hashes = Vec::with_capacity(caps.len() + 5);

        // 1. 生成真实能力的哈希
        // Hash = BLAKE3_Keyed(Key=SharedSecret, Data=Salt + CapID)
        for cap in caps.iter() {
            let hash = Self::compute_hash(shared_secret, &salt, cap);
            hashes.push(hash);
        }

        // 2. 生成诱饵哈希 (Decoys / Chaff)
        // 随机生成 3-5 个假哈希，防止通过列表长度推测节点类型
        let decoy_count = rng.gen_range(3..6);
        for _ in 0..decoy_count {
            let mut decoy = [0u8; 32];
            rng.fill(&mut decoy);
            hashes.push(decoy);
        }

        // 3. 乱序 (Shuffle)
        // 简单的 Fisher-Yates shuffle
        for i in (1..hashes.len()).rev() {
            let j = rng.gen_range(0..=i);
            hashes.swap(i, j);
        }

        NegotiationPayload {
            salt,
            capability_hashes: hashes,
        }
    }

    /// 处理对方的协商包，计算交集
    /// 返回: 双方共同支持的能力 ID 列表
    pub fn process_offer(&self, shared_secret: &[u8], payload: &NegotiationPayload) -> Vec<CapabilityId> {
        let caps = self.local_capabilities.read();
        let mut common_capabilities = Vec::new();

        // 为了防止时序攻击，我们不应该在发现一个匹配后立即停止或改变行为太明显。
        // 但由于我们是在遍历本地已知的能力去匹配对方的列表，
        // 只要比较函数是 Constant Time 的，安全性就相对可控。

        for cap in caps.iter() {
            // 根据对方的 Salt 和我们的 Shared Secret，计算如果对方支持该能力应呈现的哈希
            let expected_hash = Self::compute_hash(shared_secret, &payload.salt, cap);

            // 在对方发送的哈希列表中查找
            // 这里是一个 O(N*M) 的操作，但由于能力数量通常较少 (<100)，性能可接受
            let mut found = false;
            for remote_hash in &payload.capability_hashes {
                if constant_time_eq(&expected_hash, remote_hash) {
                    found = true;
                    // 注意：不要 break，继续以此消耗恒定时间？
                    // 严格来说，为了抗极端的侧信道，应该遍历完。
                    // 但在这里，我们假设 constant_time_eq 足够。
                }
            }

            if found {
                debug!("ZKP: Discovered common capability '{}'", cap);
                common_capabilities.push(cap.clone());
            }
        }

        info!("ZKP Negotiation finished. Common capabilities: {:?}", common_capabilities);
        common_capabilities
    }

    /// 核心哈希算法
    fn compute_hash(secret: &[u8], salt: &[u8], cap_id: &str) -> [u8; 32] {
        // 使用 Keyed Hash 确保只有拥有会话密钥的人才能验证
        // Input = Salt + CapabilityString
        let mut hasher = blake3::Hasher::new_keyed(Self::derive_blake3_key(secret));
        hasher.update(salt);
        hasher.update(cap_id.as_bytes());
        hasher.finalize().into()
    }

    /// 将任意长度的 secret 转换为 32 字节的 Blake3 Key
    fn derive_blake3_key(secret: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ETP_ZKP_KEY_DERIVATION");
        hasher.update(secret);
        hasher.finalize().into()
    }
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_negotiation_flow() {
        let alice_negotiator = ZkpNegotiator::new();
        alice_negotiator.register_capability("etp.vpn.v1".to_string());
        alice_negotiator.register_capability("etp.chat.v2".to_string());

        let bob_negotiator = ZkpNegotiator::new();
        bob_negotiator.register_capability("etp.vpn.v1".to_string());
        bob_negotiator.register_capability("etp.forum.v1".to_string()); // Alice doesn't have this

        // 模拟 Noise 握手后的共享密钥
        let shared_secret = [0x42u8; 32];

        // 1. Alice 生成 Offer
        let offer = alice_negotiator.generate_offer(&shared_secret);
        
        // 验证混淆：Alice 有 2 个能力，加上 3-5 个诱饵，总数应 >= 5
        assert!(offer.capability_hashes.len() >= 5);

        // 2. Bob 处理 Offer
        let common = bob_negotiator.process_offer(&shared_secret, &offer);

        // 3. 验证结果
        // 应该只有 "etp.vpn.v1"
        assert_eq!(common.len(), 1);
        assert_eq!(common[0], "etp.vpn.v1");
        
        // 验证 Alice 的 chat 和 Bob 的 forum 都没有泄露给对方
        // (Bob 无法知道 Alice 发送的那些不匹配的哈希代表什么，除非 Bob 自己也支持 Chat 并去尝试匹配)
    }

    #[test]
    fn test_zkp_security_wrong_key() {
        let alice = ZkpNegotiator::new();
        alice.register_capability("secret.feature".to_string());
        
        let bob = ZkpNegotiator::new();
        bob.register_capability("secret.feature".to_string());

        let key_alice = [0xAA; 32];
        let key_hacker = [0xBB; 32]; // 中间人或攻击者猜测的 Key

        let offer = alice.generate_offer(&key_alice);
        
        // Hacker 尝试用错误的 Key 解析
        let common = bob.process_offer(&key_hacker, &offer);
        
        // 即使 Bob 支持该功能，但因为 Key 不匹配，计算出的 Hash 不同，无法识别
        assert!(common.is_empty());
    }
}
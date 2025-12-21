// etp-core/src/security/zkp_negotiation.rs

//! # ZKP 能力协商模块 - 完全体实现
//! 
//! 本模块实现了基于零知识证明思路的插件能力协商。
//! 通过动态 `secret_seed` 实现逻辑网络频率隔离，确保异构网络间无法互相识别。

use std::collections::HashSet;
use parking_lot::RwLock;
use blake3;
use rand::{Rng, thread_rng};
use constant_time_eq::constant_time_eq;
use anyhow::{Result, anyhow};
use log::{info, debug, trace, warn};
use serde::{Serialize, Deserialize};

/// 能力 ID 类型，例如 "etp.flavor.vpn.v1"
pub type CapabilityId = String;

/// 协商载荷：在线路上传输的二进制格式
/// 增加了 Serde 支持，以便在 node.rs 中进行编解码
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationPayload {
    /// 16 字节随机盐，防止针对特定能力的预计算彩虹表攻击
    pub salt: [u8; 16],
    /// 包含真实能力哈希与诱饵哈希的混淆列表
    pub capability_hashes: Vec<[u8; 32]>,
}

/// 零知识能力协商器核心
/// 
/// 相比初版，增加了动态 `secret_seed` 支持，是实现 FusionNexus 控制权的核心。
pub struct ZkpNegotiator {
    /// 本地注册的能力集合
    local_capabilities: RwLock<HashSet<CapabilityId>>,
    /// 逻辑网络种子 (Secret Seed)，用于跨网频率隔离
    /// 初始值来自编译时 env!("INTERNAL_ETP_SEED")
    secret_seed: RwLock<String>,
}

impl ZkpNegotiator {
    /// 初始化协商器
    /// initial_seed: 初始频率种子
    pub fn new(initial_seed: String) -> Self {
        Self {
            local_capabilities: RwLock::new(HashSet::new()),
            secret_seed: RwLock::new(initial_seed),
        }
    }

    /// [生产级接口] 动态更新网络种子（切换逻辑频率）
    /// 调用此函数后，所有后续的握手都将尝试匹配新的频率
    pub fn update_seed(&self, new_seed: String) {
        let mut guard = self.secret_seed.write();
        *guard = new_seed;
        info!("ZKP: Network logic frequency mutated. Seed shifted.");
    }

    /// 获取当前生效的种子 (内部调试/审计用)
    pub fn get_current_seed(&self) -> String {
        self.secret_seed.read().clone()
    }

    /// 注册本地支持的插件能力
    /// 通常在 Node 启动时由 PluginRegistry 自动调用
    pub fn register_capability(&self, cap_id: CapabilityId) {
        let mut guard = self.local_capabilities.write();
        guard.insert(cap_id);
        debug!("ZKP: Registered capability '{}'", id = cap_id);
    }

    /// 生成发往对端的协商提议 (Offer)
    /// 
    /// # Arguments
    /// * `shared_secret` - Noise 协议握手后得到的共享密钥
    pub fn generate_offer(&self, shared_secret: &[u8]) -> NegotiationPayload {
        let mut rng = thread_rng();
        let mut salt = [0u8; 16];
        rng.fill(&mut salt);

        let caps = self.local_capabilities.read();
        let seed = self.secret_seed.read();
        
        let mut hashes = Vec::with_capacity(caps.len() + 8);

        // 1. 基于当前频率种子和会话密钥派生 Keyed Hash 专用的 32 字节 Key
        let key = self.derive_blake3_key(shared_secret, &*seed);

        // 2. 计算真实能力的哈希
        // 使用 Keyed Hash 确保第三方即便拿到了 Payload 和 Salt 也无法反推能力名
        for cap in caps.iter() {
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&salt);
            hasher.update(cap.as_bytes());
            hashes.push(hasher.finalize().into());
        }

        // 3. 注入 3 到 7 个随机诱饵哈希 (Decoys)
        // 诱饵的数量本身也是随机的，防止攻击者通过列表长度分析插件分布
        let decoy_count = rng.gen_range(3..8);
        for _ in 0..decoy_count {
            let mut decoy = [0u8; 32];
            rng.fill(&mut decoy);
            hashes.push(decoy);
        }

        // 4. 执行 Fisher-Yates 洗牌算法，彻底消除真实能力的位置特征
        for i in (1..hashes.len()).rev() {
            let j = rng.gen_range(0..=i);
            hashes.swap(i, j);
        }

        NegotiationPayload {
            salt,
            capability_hashes: hashes,
        }
    }

    /// 处理对端发来的提议，识别共同支持的能力
    /// 
    /// 使用恒定时间比较逻辑，防止通过响应速度推测匹配成功的个数。
    pub fn process_offer(&self, shared_secret: &[u8], payload: &NegotiationPayload) -> Vec<CapabilityId> {
        let caps = self.local_capabilities.read();
        let seed = self.secret_seed.read();
        let mut common = Vec::new();

        let key = self.derive_blake3_key(shared_secret, &*seed);

        for cap in caps.iter() {
            // 计算本地能力在对端 Salt 下的预期哈希
            let mut hasher = blake3::Hasher::new_keyed(&key);
            hasher.update(&payload.salt);
            hasher.update(cap.as_bytes());
            let expected = hasher.finalize();

            // 在对端提供的哈希集合中进行查找
            let mut found = false;
            for remote_hash in &payload.capability_hashes {
                // [Security] 必须使用恒定时间比较，抵御时序侧信道攻击
                if constant_time_eq(expected.as_bytes(), remote_hash) {
                    found = true;
                    // 注意：不在这里 break，以保持计算路径的对称性（虽然后续开销不同，但能缓解大部分分析）
                }
            }

            if found {
                trace!("ZKP: Common capability identified: {}", cap);
                common.push(cap.clone());
            }
        }

        common
    }

    /// 核心密钥派生函数 (HKDF-like)
    /// 将物理层的加密信心（Noise）与逻辑层的网络频率（Seed）缝合在一起
    fn derive_blake3_key(&self, shared_secret: &[u8], seed: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        // 增加域分离前缀，防止 Key 重用攻击
        hasher.update(b"ETP_ZKP_DOMAIN_SEP_V2_2024_PROD");
        hasher.update(seed.as_bytes());
        hasher.update(shared_secret);
        hasher.finalize().into()
    }
}

// ============================================================================
//  5. 单元测试套件 (全量不省略)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_negotiation_full_cycle() {
        let shared_secret = b"this_is_a_shared_noise_key_32bytes";
        let seed = "dimension_alpha".to_string();

        let alice = ZkpNegotiator::new(seed.clone());
        alice.register_capability("etp.vpn.v1".to_string());
        alice.register_capability("etp.chat.v2".to_string());

        let bob = ZkpNegotiator::new(seed.clone());
        bob.register_capability("etp.vpn.v1".to_string());
        bob.register_capability("etp.proxy.v1".to_string()); // Alice 没有这个

        // 1. Alice 生成提议
        let offer = alice.generate_offer(shared_secret);
        
        // 2. Bob 处理提议
        let common = bob.process_offer(shared_secret, &offer);

        // 3. 验证结果
        assert!(common.contains(&"etp.vpn.v1".to_string()));
        assert!(!common.contains(&"etp.chat.v2".to_string()));
        assert_eq!(common.len(), 1);
    }

    #[test]
    fn test_frequency_isolation_security() {
        let shared_secret = b"same_shared_key";
        
        // Network A 和 Network B 使用不同的种子
        let alice = ZkpNegotiator::new("freq_a".to_string());
        alice.register_capability("etp.core".to_string());

        let bob = ZkpNegotiator::new("freq_b".to_string());
        bob.register_capability("etp.core".to_string());

        let offer = alice.generate_offer(shared_secret);
        let common = bob.process_offer(shared_secret, &offer);

        // 即使支持相同的能力且共享密钥一致，因为种子（频率）不同，无法识别对方
        assert!(common.is_empty(), "Different seeds must result in zero common capabilities");
    }

    #[test]
    fn test_dynamic_seed_switching() {
        let shared_secret = b"test_key";
        let alice = ZkpNegotiator::new("seed_1".to_string());
        alice.register_capability("test".to_string());

        let mut bob = ZkpNegotiator::new("seed_1".to_string());
        bob.register_capability("test".to_string());

        // 初始状态：可以通信
        let offer1 = alice.generate_offer(shared_secret);
        assert_eq!(bob.process_offer(shared_secret, &offer1).len(), 1);

        // Bob 动态切换种子
        bob.update_seed("seed_2".to_string());

        // 切换后：无法解析旧种子的包
        let offer2 = alice.generate_offer(shared_secret);
        assert_eq!(bob.process_offer(shared_secret, &offer2).len(), 0);
        
        // 验证 Alice 切换后恢复通信
        alice.update_seed("seed_2".to_string());
        let offer3 = alice.generate_offer(shared_secret);
        assert_eq!(bob.process_offer(shared_secret, &offer3).len(), 1);
    }

    #[test]
    fn test_constant_time_comparison() {
        // 这是一个逻辑测试。由于 Rust 编译优化的不确定性，
        // 真正的时序测试需要硬件级测量，但此处确保逻辑路径覆盖。
        let alice = ZkpNegotiator::new("seed".into());
        let shared_secret = &[0u8; 32];
        let payload = alice.generate_offer(shared_secret);
        
        // 即使传入空能力，也应能正常处理载荷而不崩溃
        let bob = ZkpNegotiator::new("seed".into());
        let common = bob.process_offer(shared_secret, &payload);
        assert!(common.is_empty());
    }
}
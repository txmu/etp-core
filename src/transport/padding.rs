// etp-core/src/transport/padding.rs

use rand::Rng;
use std::fmt::Debug;

/// 填充策略接口 (Strategy/Mod)
/// 决定如何为一个 Payload 添加 Padding，以混淆长度特征
pub trait PaddingStrategy: Send + Sync + Debug {
    /// 计算需要的 Padding 长度
    /// current_len: 当前 Payload 长度
    /// mtu: 最大传输单元限制
    /// 返回: 需要追加的填充字节数
    fn calculate_padding(&self, current_len: usize, mtu: usize) -> usize;
}

// --- 默认实现 ---

/// 不填充 (最大化带宽效率)
#[derive(Debug, Clone)]
pub struct NoPadding;

impl PaddingStrategy for NoPadding {
    fn calculate_padding(&self, _current_len: usize, _mtu: usize) -> usize {
        0
    }
}

/// 块对齐填充 (Block Aligned)
/// 将长度填充为 block_size 的倍数
#[derive(Debug, Clone)]
pub struct BlockPadding {
    pub block_size: usize,
}

impl PaddingStrategy for BlockPadding {
    fn calculate_padding(&self, current_len: usize, mtu: usize) -> usize {
        if self.block_size == 0 { return 0; }
        let remainder = current_len % self.block_size;
        if remainder == 0 { return 0; }
        
        let pad = self.block_size - remainder;
        if current_len + pad > mtu {
            0 // 超过 MTU 就不填充了
        } else {
            pad
        }
    }
}

/// 随机长度填充 (Randomized)
/// 增加随机长度的 Padding，使流量指纹模糊化
#[derive(Debug, Clone)]
pub struct RandomPadding {
    pub min_pad: usize,
    pub max_pad: usize,
}

impl PaddingStrategy for RandomPadding {
    fn calculate_padding(&self, current_len: usize, mtu: usize) -> usize {
        let mut rng = rand::thread_rng();
        let pad = rng.gen_range(self.min_pad..=self.max_pad);
        
        if current_len + pad > mtu {
            // 尽力填充到 MTU
            if mtu > current_len { mtu - current_len } else { 0 }
        } else {
            pad
        }
    }
}

/// TLS 拟态填充 (Mimicry)
/// 尝试模拟 TLS 握手包的典型长度 (如 ClientHello 517 bytes)
/// 这是一个高级策略示例
#[derive(Debug, Clone)]
pub struct TlsMimicPadding;

impl PaddingStrategy for TlsMimicPadding {
    fn calculate_padding(&self, current_len: usize, mtu: usize) -> usize {
        // 简单模拟：如果包很小 (<100)，填充到 500-600 之间模拟握手
        if current_len < 100 {
            let target = 517; // 典型 ClientHello
            if target > current_len && target <= mtu {
                return target - current_len;
            }
        }
        // 其他情况应用少量随机填充
        let rng_pad = rand::thread_rng().gen_range(0..16);
        if current_len + rng_pad <= mtu { rng_pad } else { 0 }
    }
}
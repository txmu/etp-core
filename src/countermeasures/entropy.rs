// etp-core/src/countermeasures/entropy.rs

use rand::{Rng, thread_rng};
use base64::{Engine as _, engine::general_purpose};

/// 熵归一化工具
/// 目的：使加密流量的统计特征（PopCount, Printable Ratio）看起来像普通文本或特定编码
pub struct EntropyReducer;

impl EntropyReducer {
    /// 降低熵值：将高熵的密文转换为类似 Base64 或 Hex 的低熵表现形式
    /// 注意：这会增加带宽开销，但能有效绕过 FET 检测
    pub fn reduce(data: &[u8]) -> Vec<u8> {
        // 简单策略：Base64 编码
        // OpenGFW 的 ex1 (PopCount) 对 Base64 字符集通常在 3.0-4.0 之间，
        // 而全随机数据在 4.0 左右。
        // Base64 字符全是可打印的，ex3 (Printable%) = 100%。
        // OpenGFW 豁免逻辑：if ex3 > 0.5 -> exempt.
        // 所以 Base64 编码可以直接绕过 FET。
        
        // 为了不显得太像标准的 Base64，可以加盐或使用自定义字符集
        let encoded = general_purpose::STANDARD.encode(data);
        encoded.into_bytes()
    }

    /// 恢复数据
    pub fn restore(data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = general_purpose::STANDARD.decode(data)?;
        Ok(decoded)
    }

    /// 混淆策略：插入随机的可打印字符作为 padding
    pub fn inject_printable_chaff(data: &mut Vec<u8>, target_len: usize) {
        let mut rng = thread_rng();
        while data.len() < target_len {
            // ASCII printable range: 32-126
            let ch = rng.gen_range(32..=126);
            data.push(ch);
        }
    }
}
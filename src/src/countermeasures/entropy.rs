// etp-core/src/countermeasures/entropy.rs

use rand::{Rng, thread_rng};
use base64::{Engine as _, engine::{GeneralPurpose, GeneralPurposeConfig}, alphabet::Alphabet};
use anyhow::{Result, anyhow};

/// 熵归一化工具
pub struct EntropyReducer;

/// 自定义字符集配置
/// 标准 Base64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
/// 这是一个混淆过的字符集示例（类似于 URL safe 但置换了顺序）
const CUSTOM_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

impl EntropyReducer {
    /// 降低熵值：支持加盐和自定义 Base64
    /// mode: 0=Standard, 1=CustomCharset
    pub fn reduce(data: &[u8], use_custom_charset: bool) -> Vec<u8> {
        let mut rng = thread_rng();
        
        // 1. 加盐 (Salt)
        // 在头部插入 2 字节随机盐，并将其混入数据首部，改变整个编码后的序列
        // 使得相同的明文每次编码结果都不同
        let salt: [u8; 2] = rng.gen();
        let mut salted_data = Vec::with_capacity(2 + data.len());
        salted_data.extend_from_slice(&salt);
        salted_data.extend_from_slice(data);

        // 2. 编码
        if use_custom_charset {
            let alpha = Alphabet::new(CUSTOM_ALPHABET).expect("Invalid alphabet");
            let engine = GeneralPurpose::new(&alpha, GeneralPurposeConfig::new());
            engine.encode(&salted_data).into_bytes()
        } else {
            // 标准 Base64
            base64::engine::general_purpose::STANDARD.encode(&salted_data).into_bytes()
        }
    }

    /// 恢复数据
    pub fn restore(data: &[u8], use_custom_charset: bool) -> Result<Vec<u8>> {
        // 1. 解码
        let decoded = if use_custom_charset {
            let alpha = Alphabet::new(CUSTOM_ALPHABET).map_err(|_| anyhow!("Invalid alphabet"))?;
            let engine = GeneralPurpose::new(&alpha, GeneralPurposeConfig::new());
            engine.decode(data)?
        } else {
            base64::engine::general_purpose::STANDARD.decode(data)?
        };

        // 2. 去盐
        if decoded.len() < 2 {
            return Err(anyhow!("Data too short to contain salt"));
        }
        
        // 既然盐只是 prepend，直接切片即可。
        // 如果做了 XOR 混淆，这里需要逆运算。
        // 为了生产级实现的健壮性，这里不做复杂的 XOR，因为 TLS/Noise 已经加密过了。
        // Salt 的目的是改变 Base64 的输出形态。
        
        Ok(decoded[2..].to_vec())
    }

    /// 混淆策略：插入符合 Base64 字符集分布的随机垃圾数据
    /// 用于填充包长度
    pub fn inject_printable_chaff(data: &mut Vec<u8>, target_len: usize) {
        let mut rng = thread_rng();
        let charset = if rng.gen_bool(0.5) {
            base64::alphabet::STANDARD.as_str().as_bytes()
        } else {
            CUSTOM_ALPHABET.as_bytes()
        };
        
        while data.len() < target_len {
            let idx = rng.gen_range(0..charset.len());
            data.push(charset[idx]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_reduction_cycle() {
        let original = b"Sensitive Data Header";
        
        // Test Standard
        let reduced = EntropyReducer::reduce(original, false);
        assert_ne!(original.to_vec(), reduced); // Should be encoded
        let restored = EntropyReducer::restore(&reduced, false).unwrap();
        assert_eq!(original.to_vec(), restored);

        // Test Custom
        let reduced_custom = EntropyReducer::reduce(original, true);
        assert_ne!(reduced, reduced_custom); // Custom charset produces different output
        let restored_custom = EntropyReducer::restore(&reduced_custom, true).unwrap();
        assert_eq!(original.to_vec(), restored_custom);
    }

    #[test]
    fn test_salting_randomness() {
        let original = b"Fixed Input";
        
        let enc1 = EntropyReducer::reduce(original, false);
        let enc2 = EntropyReducer::reduce(original, false);
        
        // 由于加盐，即使明文相同，密文也应不同
        assert_ne!(enc1, enc2);
        
        // 都能解密回原数据
        assert_eq!(EntropyReducer::restore(&enc1, false).unwrap(), original.to_vec());
        assert_eq!(EntropyReducer::restore(&enc2, false).unwrap(), original.to_vec());
    }
}
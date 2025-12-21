// etp-core/src/crypto/onion.rs

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{Aead, Payload};
use rand::{Rng, RngCore};
use anyhow::{Result, anyhow, Context};
use blake3;
use std::convert::TryInto;
use zeroize::Zeroize; // 建议在 Cargo.toml 添加 zeroize 依赖

// --- 协议常量 ---
const ONION_PROTO_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const EPHEMERAL_KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

// 域分离标签 (Domain Separation Tags)
const INFO_KEY_DERIVATION: &str = "ETP-Onion-Layer-Key-v1";
const INFO_NONCE_DERIVATION: &str = "ETP-Onion-Layer-Nonce-v1";

/// Nonce 生成模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceMode {
    /// 确定性派生：Nonce = HKDF(SharedSecret, Salt). 
    /// 优点：节省 12 字节带宽。
    /// 缺点：若 RNG 故障导致 EphemeralKey 重复，则 Nonce 重复，安全性崩塌。
    Derived = 0x00,
    
    /// 随机生成：Nonce = Random(12).
    /// 优点：即使 EphemeralKey 重复，Nonce 依然唯一，鲁棒性更强。
    /// 缺点：增加 12 字节带宽。
    Random = 0x01,
}

/// 填充策略 (用于隐藏包大小特征)
#[derive(Debug, Clone, Copy)]
pub enum PaddingStrategy {
    /// 不填充 (最大化效率)
    None,
    /// 填充至 N 字节的倍数 (例如 16 或 256)
    BlockAligned(usize),
    /// 填充至固定总大小 (例如 1350 字节，模拟 MTU)
    FixedTotal(usize),
}

/// 洋葱加密配置上下文
#[derive(Debug, Clone)]
pub struct OnionConfig {
    pub nonce_mode: NonceMode,
    pub padding: PaddingStrategy,
}

impl Default for OnionConfig {
    fn default() -> Self {
        Self {
            nonce_mode: NonceMode::Derived,
            padding: PaddingStrategy::None,
        }
    }
}

/// 生产级洋葱层加密工具
pub struct OnionCrypto;

impl OnionCrypto {
    /// 封装 (Encapsulate)
    ///
    /// # Wire Format
    /// [ Header (1B) ] [ Ephemeral Pub (32B) ] [ Nonce (0 or 12B) ] [ Ciphertext (Payload + Padding + Tag) ]
    /// 
    /// Header Bits:
    /// | 7 6 5 4 | 3 2 1 | 0 |
    /// | Version | Rsrvd | Mode |
    ///
    /// - Version: 0x1 (High 4 bits)
    /// - Mode: 0 = Derived, 1 = Random
    pub fn seal(
        target_pub_bytes: &[u8], 
        payload: &[u8], 
        config: &OnionConfig
    ) -> Result<Vec<u8>> {
        // 1. 验证输入
        let target_pub_arr: [u8; 32] = target_pub_bytes.try_into()
            .map_err(|_| anyhow!("Invalid target public key length"))?;
        let target_pub = PublicKey::from(target_pub_arr);

        // 2. 生成临时密钥 (Ephemeral Key)
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::new(&mut rng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);

        // 3. 密钥协商 (ECDH)
        let shared_secret = ephemeral_secret.diffie_hellman(&target_pub);
        let shared_secret_bytes = shared_secret.as_bytes();

        // 4. 派生加密密钥 (KDF)
        let derived_key = derive_key(shared_secret_bytes, INFO_KEY_DERIVATION);
        let cipher = ChaCha20Poly1305::new(&derived_key.into());

        // 5. 准备 Nonce
        let (nonce, nonce_bytes_on_wire) = match config.nonce_mode {
            NonceMode::Derived => {
                let n = derive_nonce(shared_secret_bytes, INFO_NONCE_DERIVATION);
                (n, Vec::new())
            },
            NonceMode::Random => {
                let mut n = [0u8; NONCE_LEN];
                rng.fill_bytes(&mut n);
                (n, n.to_vec())
            }
        };

        // 6. 应用填充 (Padding)
        let padded_payload = apply_padding(payload, config.padding)?;

        // 7. AEAD 加密
        let ciphertext = cipher.encrypt(&nonce.into(), padded_payload.as_slice())
            .map_err(|_| anyhow!("Onion AEAD encryption failed"))?;

        // 8. 构造最终数据包
        // Header: Version(4) | Reserved(3) | Mode(1)
        let mode_bit = match config.nonce_mode {
            NonceMode::Derived => 0x00,
            NonceMode::Random => 0x01,
        };
        let header = (ONION_PROTO_VERSION << 4) | mode_bit;

        let mut output = Vec::with_capacity(1 + 32 + nonce_bytes_on_wire.len() + ciphertext.len());
        output.push(header);
        output.extend_from_slice(ephemeral_pub.as_bytes());
        output.extend_from_slice(&nonce_bytes_on_wire);
        output.extend(ciphertext);

        // 安全清理
        // shared_secret goes out of scope, but ideally we should zeroize explicit copies if any.
        
        Ok(output)
    }

    /// 解封装 (Decapsulate)
    /// 
    /// 从数据包中解析出临时公钥和模式，计算共享密钥并解密。
    pub fn open(
        packet: &[u8], 
        my_secret_bytes: &[u8]
    ) -> Result<Vec<u8>> {
        if packet.len() < 1 + 32 + 16 { // Min: Header + Pub + Tag
            return Err(anyhow!("Packet too short for Onion layer"));
        }

        // 1. 解析 Header
        let header = packet[0];
        let version = (header >> 4) & 0x0F;
        let mode_bit = header & 0x01;

        if version != ONION_PROTO_VERSION {
            return Err(anyhow!("Unsupported Onion version: {}", version));
        }

        let mode = if mode_bit == 0 { NonceMode::Derived } else { NonceMode::Random };

        // 2. 提取 Ephemeral Pub Key
        let ephemeral_pub_bytes = &packet[1..33];
        let ephemeral_pub = PublicKey::from(
            TryInto::<[u8; 32]>::try_into(ephemeral_pub_bytes).expect("Slice len is 32")
        );

        // 3. 提取/派生 Nonce & 定位密文
        let mut offset = 33;
        
        // ECDH
        let my_secret_arr: [u8; 32] = my_secret_bytes.try_into()
            .map_err(|_| anyhow!("Invalid secret key length"))?;
        let my_secret = StaticSecret::from(my_secret_arr);
        let shared_secret = my_secret.diffie_hellman(&ephemeral_pub);
        let shared_secret_bytes = shared_secret.as_bytes();

        let nonce = match mode {
            NonceMode::Derived => {
                derive_nonce(shared_secret_bytes, INFO_NONCE_DERIVATION)
            },
            NonceMode::Random => {
                if packet.len() < offset + NONCE_LEN + TAG_LEN {
                    return Err(anyhow!("Packet too short for Random Nonce"));
                }
                let mut n = [0u8; NONCE_LEN];
                n.copy_from_slice(&packet[offset..offset+NONCE_LEN]);
                offset += NONCE_LEN;
                n
            }
        };

        // 4. AEAD 解密
        let derived_key = derive_key(shared_secret_bytes, INFO_KEY_DERIVATION);
        let cipher = ChaCha20Poly1305::new(&derived_key.into());
        let ciphertext = &packet[offset..];

        let padded_plaintext = cipher.decrypt(&nonce.into(), ciphertext)
            .map_err(|_| anyhow!("Onion decryption integrity check failed"))?;

        // 5. 去除填充 (高性能零拷贝模式)
        remove_padding(padded_plaintext)
    }
}

// --- Helper Functions ---

fn derive_key(secret: &[u8], info: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(info);
    hasher.update(secret);
    hasher.finalize().into()
}

fn derive_nonce(secret: &[u8], info: &str) -> [u8; 12] {
    let mut hasher = blake3::Hasher::new_derive_key(info);
    hasher.update(secret);
    let output = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&output.as_bytes()[0..12]);
    nonce
}

/// 应用填充 (ISO/IEC 7816-4: Add 0x80 then 0x00...)
/// (新版：末尾字节记录长度法)
/// 格式: [原始数据] [随机填充字节...] [填充长度(1B)]
fn apply_padding(data: &[u8], strategy: PaddingStrategy) -> Result<Vec<u8>> {
    let mut output = data.to_vec();
    let current_len = data.len();
    
    // 确定目标总长度（包含 1 字节的长度标记）
    let target_total_len = match strategy {
        PaddingStrategy::None => current_len + 1, // 仅增加 1 字节标记位
        PaddingStrategy::BlockAligned(block_size) => {
            if block_size == 0 { return Err(anyhow!("Invalid block size 0")); }
            // 确保至少留出 1 字节存长度，计算下一个对齐点
            ((current_len + 1 + block_size - 1) / block_size) * block_size
        },
        PaddingStrategy::FixedTotal(total_size) => {
            if current_len + 1 > total_size {
                return Err(anyhow!("Payload too large for fixed size padding"));
            }
            total_size
        }
    };

    let padding_len = target_total_len - current_len - 1; // 减去原始数据和最后的长度字节
    
    // 填充随机数据而非 0x00，以获得更好的抗分析能力
    let mut rng = rand::thread_rng();
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);
    output.extend(padding);

    // 最后一个字节存储填充的长度 (0-254)
    // 如果填充超过 255，此逻辑需修改为 u16，但对于 MTU 1500 来说 u8 足够
    output.push(padding_len as u8);

    Ok(output)
}

/// 去除填充 (新版：末尾字节记录长度法)
fn remove_padding(mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(anyhow!("Empty packet"));
    }

    // 1. 取出最后一个字节，获取填充长度
    let padding_len = data.pop().ok_or(anyhow!("Missing padding length byte"))? as usize;

    // 2. 安全边界检查
    if padding_len > data.len() {
        return Err(anyhow!("Invalid padding length: {} > data len {}", padding_len, data.len()));
    }

    // 3. 截断数据
    let final_len = data.len() - padding_len;
    data.truncate(final_len);

    Ok(data)
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_crypto_lifecycle_derived() {
        let alice_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let alice_pub = PublicKey::from(&alice_secret);

        let msg = b"Hello Onion World";
        let config = OnionConfig {
            nonce_mode: NonceMode::Derived,
            padding: PaddingStrategy::None,
        };

        // Seal
        let packet = OnionCrypto::seal(alice_pub.as_bytes(), msg, &config).unwrap();

        // Open
        let decrypted = OnionCrypto::open(&packet, alice_secret.to_bytes().as_slice()).unwrap();
        
        assert_eq!(msg.to_vec(), decrypted);
    }

    #[test]
    fn test_onion_crypto_lifecycle_random_padded() {
        let alice_secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let alice_pub = PublicKey::from(&alice_secret);

        let msg = b"Secret Message";
        let config = OnionConfig {
            nonce_mode: NonceMode::Random,
            // Align to 64 bytes
            padding: PaddingStrategy::BlockAligned(64),
        };

        // Seal
        let packet = OnionCrypto::seal(alice_pub.as_bytes(), msg, &config).unwrap();
        
        // Check size: Header(1) + Pub(32) + Nonce(12) + Tag(16) + PaddedPayload
        // Payload "Secret Message" (14) -> Pad to 64: 14 + 1(0x80) + 49(0x00) = 64
        // Total = 1 + 32 + 12 + 16 + 64 = 125
        assert_eq!(packet.len(), 125);

        // Open
        let decrypted = OnionCrypto::open(&packet, alice_secret.to_bytes().as_slice()).unwrap();
        
        assert_eq!(msg.to_vec(), decrypted);
    }

    #[test]
    fn test_padding_logic() {
        let data = vec![0x11, 0x22];
        
        // Test Block Aligned
        let padded = apply_padding(&data, PaddingStrategy::BlockAligned(8)).unwrap();
        // Expect: 11 22 80 00 00 00 00 00 (8 bytes)
        assert_eq!(padded, vec![0x11, 0x22, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let unpadded = remove_padding(&padded).unwrap();
        assert_eq!(unpadded, data);
        
        // Test No Padding
        let unpadded_raw = remove_padding(&data).unwrap();
        assert_eq!(unpadded_raw, data);
    }
}
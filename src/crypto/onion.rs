// etp-core/src/crypto/onion.rs

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{Aead, Payload};
use rand::RngCore;
use anyhow::{Result, anyhow};
use blake3;

/// 生产级洋葱层加密工具
/// 使用 ECIES (Elliptic Curve Integrated Encryption Scheme) 变体
/// Ephemeral Key (X25519) + HKDF/Blake3 + ChaCha20Poly1305
pub struct OnionCrypto;

impl OnionCrypto {
    /// 封装 (Encapsulate): 客户端使用，将 payload 加密给 target_pub
    /// 返回: (Ephemeral Public Key Bytes, Encrypted Data)
    pub fn seal(target_pub_bytes: &[u8], payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // 1. 还原目标公钥
        let target_pub_arr: [u8; 32] = target_pub_bytes.try_into()
            .map_err(|_| anyhow!("Invalid public key length"))?;
        let target_pub = PublicKey::from(target_pub_arr);

        // 2. 生成临时私钥 (Ephemeral Secret)
        let mut rng = rand::thread_rng();
        let ephemeral_secret = EphemeralSecret::new(&mut rng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);

        // 3. 密钥协商 (ECDH)
        let shared_secret = ephemeral_secret.diffie_hellman(&target_pub);

        // 4. 密钥派生 (KDF)
        // 使用 Blake3 KDF 将共享密钥派生为 ChaCha20 Key 和 Nonce
        let derived_key = blake3::derive_key("ETP Onion Layer", shared_secret.as_bytes());
        let nonce = [0u8; 12]; // Fixed nonce is safe here because key is ephemeral/unique per packet

        // 5. AEAD 加密
        let cipher = ChaCha20Poly1305::new(&derived_key.into());
        let ciphertext = cipher.encrypt(&nonce.into(), payload)
            .map_err(|_| anyhow!("Onion encryption failed"))?;

        Ok((ephemeral_pub.as_bytes().to_vec(), ciphertext))
    }

    /// 解封装 (Decapsulate): 中继节点使用，使用自己的私钥解开一层
    /// ephemeral_pub_bytes: 包头携带的临时公钥
    /// my_secret_bytes: 自己的私钥
    pub fn open(ephemeral_pub_bytes: &[u8], ciphertext: &[u8], my_secret_bytes: &[u8]) -> Result<Vec<u8>> {
        // 1. 还原密钥
        let ephemeral_pub_arr: [u8; 32] = ephemeral_pub_bytes.try_into()
            .map_err(|_| anyhow!("Invalid ephemeral key"))?;
        let ephemeral_pub = PublicKey::from(ephemeral_pub_arr);
        
        let my_secret_arr: [u8; 32] = my_secret_bytes.try_into()
            .map_err(|_| anyhow!("Invalid secret key"))?;
        let my_secret = StaticSecret::from(my_secret_arr);

        // 2. 密钥协商 (ECDH)
        let shared_secret = my_secret.diffie_hellman(&ephemeral_pub);

        // 3. 密钥派生
        let derived_key = blake3::derive_key("ETP Onion Layer", shared_secret.as_bytes());
        let nonce = [0u8; 12];

        // 4. AEAD 解密
        let cipher = ChaCha20Poly1305::new(&derived_key.into());
        let plaintext = cipher.decrypt(&nonce.into(), ciphertext)
            .map_err(|_| anyhow!("Onion decryption failed (integrity check error)"))?;

        Ok(plaintext)
    }
}
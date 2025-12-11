// etp-core/src/wire/packet.rs

use crate::{PacketNumber, SessionID};
use crate::wire::frame::Frame;
use crate::crypto::noise::NoiseSession;
use crate::plugin::Dialect; // 引用插件系统
use serde::{Serialize, Deserialize};
use rand::Rng;
use anyhow::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptedPacket {
    pub session_id: SessionID,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

impl DecryptedPacket {
    pub fn new(session_id: SessionID, packet_number: PacketNumber) -> Self {
        Self { session_id, packet_number, frames: Vec::new() }
    }
    pub fn add_frame(&mut self, frame: Frame) { self.frames.push(frame); }
    
    // 生产级：使用 bincode options 限制大小，防止 DOS
    pub fn to_bytes(&self) -> Result<Vec<u8>> { 
        use bincode::Options;
        Ok(bincode::DefaultOptions::new().with_limit(65535).serialize(self)?) 
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> { 
        use bincode::Options;
        let p = bincode::DefaultOptions::new()
            .with_limit(65535)
            .allow_trailing_bytes() // 允许 Padding 存在
            .deserialize(data)?;
        Ok(p)
    }
}

pub struct RawPacket {
    pub data: Vec<u8>,
}

impl RawPacket {
    /// 加密并封装 (使用指定方言)
    pub fn encrypt_and_seal(
        logic_packet: &DecryptedPacket,
        crypto: &mut NoiseSession,
        target_size: Option<usize>,
        dialect: &dyn Dialect // 使用方言接口
    ) -> Result<Self> {
        
        let mut raw_content = logic_packet.to_bytes()?;

        // 1. Padding Logic (生产级)
        // 使用 PKCS#7 或 随机填充。ETP 选择随机填充。
        if let Some(size) = target_size {
            if raw_content.len() < size {
                let padding_len = size - raw_content.len();
                let mut rng = rand::thread_rng();
                let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
                raw_content.extend(padding);
            }
        }

        // 2. Encryption (ChaCha20-Poly1305)
        let mut encrypted = vec![0u8; raw_content.len() + 16]; // Tag size
        let len = crypto.encrypt(&raw_content, &mut encrypted)?;
        encrypted.truncate(len);

        // 3. Dialect Sealing (方言伪装)
        dialect.seal(&mut encrypted);

        Ok(RawPacket { data: encrypted })
    }

    /// 解封并解密
    pub fn unseal_and_decrypt(
        raw_data: &[u8],
        crypto: &mut NoiseSession,
        dialect: &dyn Dialect
    ) -> Result<DecryptedPacket> {
        // 1. Dialect Opening
        let encrypted_payload = dialect.open(raw_data)?;

        // 2. Decryption
        let mut plaintext = vec![0u8; encrypted_payload.len()];
        let len = crypto.decrypt(&encrypted_payload, &mut plaintext)?;
        plaintext.truncate(len);

        // 3. Deserialization
        DecryptedPacket::from_bytes(&plaintext)
    }
}
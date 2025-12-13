// etp-core/src/wire/packet.rs

use crate::{PacketNumber, SessionID};
use crate::wire::frame::Frame;
use crate::crypto::noise::NoiseSession;
use serde::{Serialize, Deserialize};
use rand::Rng;
use anyhow::{Result, anyhow};
use std::fmt::Debug;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use chrono::Utc;
use bytes::{Bytes, BytesMut, BufMut};
use std::sync::Mutex;
use lazy_static::lazy_static; // 需要在 Cargo.toml 添加 lazy_static

type HmacSha256 = Hmac<Sha256>;

// --- 内存池 (Buffer Pool) ---
// 用于复用 RawPacket 的底层缓冲区，避免频繁的堆分配
const POOL_PACKET_SIZE: usize = 2048; // 略大于 MTU
const POOL_CAPACITY: usize = 1000;

struct BufferPool {
    pool: Vec<Vec<u8>>,
}

impl BufferPool {
    fn new() -> Self {
        Self { pool: Vec::with_capacity(POOL_CAPACITY) }
    }

    fn acquire(&mut self) -> Vec<u8> {
        if let Some(mut buf) = self.pool.pop() {
            buf.clear();
            buf
        } else {
            Vec::with_capacity(POOL_PACKET_SIZE)
        }
    }

    fn release(&mut self, mut buf: Vec<u8>) {
        if self.pool.len() < POOL_CAPACITY && buf.capacity() >= POOL_PACKET_SIZE {
            buf.clear(); // 保留 capacity
            self.pool.push(buf);
        }
        // 否则 Drop
    }
}

lazy_static! {
    static ref PACKET_POOL: Mutex<BufferPool> = Mutex::new(BufferPool::new());
}

/// 获取缓冲区的辅助函数
pub fn acquire_buffer() -> Vec<u8> {
    PACKET_POOL.lock().unwrap().acquire()
}

/// 释放缓冲区的辅助函数
pub fn release_buffer(buf: Vec<u8>) {
    PACKET_POOL.lock().unwrap().release(buf);
}

/// 混淆器接口
pub trait Dialect: Send + Sync + Debug {
    fn id(&self) -> &'static str;
    fn seal(&self, payload: &mut Vec<u8>);
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn probe(&self, data: &[u8]) -> bool;
}

// --- 包结构定义 ---

#[derive(Debug, Serialize, Deserialize)]
pub struct StatefulPacket {
    pub session_id: SessionID,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatelessPacket {
    pub token: Vec<u8>, 
    pub nonce: u64,
    pub frames: Vec<Frame>,
}

#[derive(Debug)]
pub enum DecryptedPacket {
    Stateful(StatefulPacket),
    Stateless(StatelessPacket),
}

impl DecryptedPacket {
    pub fn frames(&self) -> &Vec<Frame> {
        match self {
            DecryptedPacket::Stateful(p) => &p.frames,
            DecryptedPacket::Stateless(p) => &p.frames,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TokenData {
    timestamp: i64,
    random_salt: u64,
}

pub struct TokenManager {
    secret_key: [u8; 32],
}

impl TokenManager {
    pub fn new(secret_key: [u8; 32]) -> Self { Self { secret_key } }

    pub fn generate_token(&self) -> Vec<u8> {
        let data = TokenData {
            timestamp: Utc::now().timestamp(),
            random_salt: rand::random(),
        };
        let bytes = bincode::serialize(&data).unwrap(); 
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("HMAC error");
        mac.update(&bytes);
        let result = mac.finalize();
        let mut token = bytes;
        token.extend_from_slice(&result.into_bytes());
        token
    }

    pub fn validate_token(&self, token: &[u8]) -> bool {
        if token.len() < 32 { return false; } 
        let split_idx = token.len() - 32; 
        let (data_bytes, sig_bytes) = token.split_at(split_idx);
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).unwrap();
        mac.update(data_bytes);
        if mac.verify_slice(sig_bytes).is_err() { return false; }
        if let Ok(data) = bincode::deserialize::<TokenData>(data_bytes) {
            if (Utc::now().timestamp() - data.timestamp).abs() > 30 { return false; }
            return true;
        }
        false
    }
}

// --- 物理包封装 (零拷贝优化) ---

/// 物理层数据包
/// 持有 Bytes，支持零拷贝切片传递给 UDP socket (如果使用了 tokio-uring 或 sendmsg)
/// 但标准的 UdpSocket::send_to 需要 &[u8]，所以我们依然保留 Vec<u8> 或 Bytes 的形式
pub struct RawPacket {
    /// 这里的 data 使用 Bytes，它可以是从 Pool 中获取的 Vec 转换而来
    pub data: Bytes, 
    /// 原始缓冲区，用于 Drop 时归还给 Pool (可选，若使用 Bytes 的 Owner 机制需小心)
    /// 简化起见，我们在 RawPacket 销毁时不自动归还到 Pool，而是依赖调用方在加密时复用
    /// 或者，我们只在 Encrypt 时从 Pool 拿 Vec，加密完转成 Bytes 发送，发送完 Bytes Drop 释放内存。
    /// 标准 Bytes 是引用计数的，不直接对应我们的 Pool。
    /// 所以为了最大化利用 Pool，RawPacket 内部应持有 `Vec<u8>` (from pool)。
    /// 但为了 `Bytes` 接口兼容性，我们这里权衡一下：
    /// 加密时： Acquire Vec -> Encrypt -> Dialect -> Wrap in RawPacket.
    /// 发送后： RawPacket Drop -> Vec Drop (Dealloc).
    /// 为了真的复用，我们需要手动释放。
    /// 
    /// 改进：RawPacket 持有 `Option<Vec<u8>>`。如果不空，Drop 时 release。
    pub _backing_buffer: Option<Vec<u8>>,
}

impl RawPacket {
    /// 零拷贝加密并封装
    /// 使用分散/聚集 I/O 思想：预分配一个足够大的 Buffer (从 Pool)，然后依次写入。
    pub fn encrypt_and_seal(
        packet: &DecryptedPacket,
        crypto: &mut NoiseSession,
        target_size: Option<usize>,
        dialect: &dyn Dialect
    ) -> Result<Self> {
        
        // 1. 获取缓冲区 (从池中)
        let mut buffer = acquire_buffer();
        
        // 2. 序列化 (Bincode 写入 Buffer)
        // bincode::serialize_into 会追加数据
        match packet {
            DecryptedPacket::Stateful(p) => bincode::serialize_into(&mut buffer, p)?,
            DecryptedPacket::Stateless(p) => bincode::serialize_into(&mut buffer, p)?,
        };

        // 3. Padding
        if let Some(size) = target_size {
            if buffer.len() < size {
                let padding_len = size - buffer.len();
                // 快速填充随机数
                let current_len = buffer.len();
                buffer.resize(current_len + padding_len, 0);
                rand::thread_rng().fill(&mut buffer[current_len..]);
            }
        }

        // 4. Encrypt
        // Noise 协议加密是原地或追加的。这里我们需要一个输出缓冲区。
        // 为了避免拷贝，我们再次利用 Pool，或者如果是 In-place 加密支持的话更好。
        // snow/noise 通常支持 write_message 到输出 buf。
        // 为了性能，我们拿第二个 buffer 作为密文容器。
        let mut cipher_buffer = acquire_buffer();
        // 预留空间 (Header 等) 如果需要。Noise 追加 tag。
        cipher_buffer.resize(buffer.len() + 16 + 100, 0); // 预估容量
        
        let len = crypto.encrypt(&buffer, &mut cipher_buffer)?;
        cipher_buffer.truncate(len);
        
        // 归还明文 buffer
        release_buffer(buffer);

        // 5. Dialect Obfuscation (In-place if possible)
        dialect.seal(&mut cipher_buffer);

        Ok(RawPacket {
            data: Bytes::from(cipher_buffer.clone()), // Zero-copy share if needed, but here we enforce ownership logic below
            _backing_buffer: Some(cipher_buffer),
        })
    }

    /// 解封并解密
    pub fn unseal_and_decrypt(
        raw_data: &[u8],
        crypto: &mut NoiseSession,
        dialect: &dyn Dialect
    ) -> Result<DecryptedPacket> {
        // 1. De-obfuscate
        let encrypted_payload = dialect.open(raw_data)?;

        // 2. Decrypt
        // 使用 Pool 获取解密缓冲区
        let mut plaintext_buf = acquire_buffer();
        plaintext_buf.resize(encrypted_payload.len(), 0);
        
        let len = crypto.decrypt(&encrypted_payload, &mut plaintext_buf)?;
        plaintext_buf.truncate(len);

        // 3. Deserialize
        // 尝试解析
        use bincode::Options;
        let decoder = bincode::DefaultOptions::new().allow_trailing_bytes();

        let result = if let Ok(p) = decoder.deserialize::<StatefulPacket>(&plaintext_buf) {
             if p.session_id != 0 {
                 Ok(DecryptedPacket::Stateful(p))
             } else {
                 Err(anyhow!("Invalid ID"))
             }
        } else if let Ok(p) = decoder.deserialize::<StatelessPacket>(&plaintext_buf) {
             Ok(DecryptedPacket::Stateless(p))
        } else {
             Err(anyhow!("Format error"))
        };
        
        // 归还缓冲区
        release_buffer(plaintext_buf);
        
        result
    }
}

impl Drop for RawPacket {
    fn drop(&mut self) {
        if let Some(buf) = self._backing_buffer.take() {
            release_buffer(buf);
        }
    }
}
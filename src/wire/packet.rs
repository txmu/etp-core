// etp-core/src/wire/packet.rs

use std::cell::RefCell;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Serialize, Deserialize};
use rand::Rng;
use anyhow::{Result, anyhow, Context};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use chrono::Utc;
use bytes::Bytes;

// 引入核心类型
use crate::{PacketNumber, SessionID};
use crate::wire::frame::Frame;
use crate::crypto::noise::NoiseSession;
use crate::plugin::Dialect;

// [Security] 引入集束修改后的安全反序列化函数
use crate::common::safe_deserialize;

// [Security] 引入物理内存擦除特性
#[cfg(feature = "paranoid-security")]
use zeroize::Zeroize;

// HMAC 类型别名
type HmacSha256 = Hmac<Sha256>;

// ============================================================================
//  1. 高性能线程局部内存池 (Thread-Local Buffer Pool)
//  替代了原先的 Global Mutex，消除了多核竞争，极大提升 10Gbps+ 吞吐性能
// ============================================================================

const POOL_PACKET_SIZE: usize = 2048; // 默认缓冲区大小 (略大于标准 MTU)
const POOL_CAPACITY: usize = 1000;    // 每个线程缓存的 Buffer 数量上限

struct BufferPool {
    pool: Vec<Vec<u8>>,
    // 可选：统计指标，用于性能调优
    #[cfg(debug_assertions)]
    hits: usize,
}

impl BufferPool {
    fn new() -> Self {
        Self { 
            pool: Vec::with_capacity(POOL_CAPACITY),
            #[cfg(debug_assertions)]
            hits: 0,
        }
    }

    fn acquire(&mut self) -> Vec<u8> {
        if let Some(mut buf) = self.pool.pop() {
            #[cfg(debug_assertions)] { self.hits += 1; }
            buf.clear(); // 逻辑清空，保留 Capacity
            buf
        } else {
            Vec::with_capacity(POOL_PACKET_SIZE)
        }
    }
    
    fn release(&mut self, mut buf: Vec<u8>) {
        // [Security] 偏执模式：归还前强制擦除内存，防止残留密钥或明文
        #[cfg(feature = "paranoid-security")]
        {
            buf.as_mut_slice().zeroize();
        }

        // 只有当 Buffer 容量合适且池未满时才回收，否则 Drop 释放内存
        if self.pool.len() < POOL_CAPACITY && buf.capacity() >= POOL_PACKET_SIZE {
            self.pool.push(buf);
        }
    }
}

// 使用 thread_local! 宏替代 lazy_static
thread_local! {
    static PACKET_POOL: RefCell<BufferPool> = RefCell::new(BufferPool::new());
}

/// 从当前线程的内存池获取缓冲区
pub fn acquire_buffer() -> Vec<u8> {
    PACKET_POOL.with(|pool| pool.borrow_mut().acquire())
}

/// 将缓冲区归还给当前线程的内存池
pub fn release_buffer(buf: Vec<u8>) {
    PACKET_POOL.with(|pool| pool.borrow_mut().release(buf));
}

// ============================================================================
//  2. 数据包逻辑结构 (Logical Structures)
// ============================================================================

/// 有状态数据包 (会话内)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatefulPacket {
    pub session_id: SessionID,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

/// 无状态数据包 (握手/OOB)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatelessPacket {
    pub token: Vec<u8>, 
    pub nonce: u64,
    pub frames: Vec<Frame>,
}

/// 解密后的包枚举
#[derive(Debug)]
pub enum DecryptedPacket {
    Stateful(StatefulPacket),
    Stateless(StatelessPacket),
}

impl DecryptedPacket {
    /// 辅助构造函数：创建新的有状态包
    pub fn new(session_id: SessionID, pn: PacketNumber) -> Self {
        Self::Stateful(StatefulPacket {
            session_id,
            packet_number: pn,
            frames: Vec::new(),
        })
    }

    /// 获取内部帧列表的引用
    pub fn frames(&self) -> &Vec<Frame> {
        match self {
            DecryptedPacket::Stateful(p) => &p.frames,
            DecryptedPacket::Stateless(p) => &p.frames,
        }
    }

    /// 向包中添加帧 (仅用于测试或构造)
    pub fn add_frame(&mut self, frame: Frame) {
        match self {
            DecryptedPacket::Stateful(p) => p.frames.push(frame),
            DecryptedPacket::Stateless(p) => p.frames.push(frame),
        }
    }

    /// 序列化为字节 (仅用于测试)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            DecryptedPacket::Stateful(p) => Ok(bincode::serialize(p)?),
            DecryptedPacket::Stateless(p) => Ok(bincode::serialize(p)?),
        }
    }

    /// 从字节反序列化 (仅用于测试，生产环境走 RawPacket)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if let Ok(p) = safe_deserialize::<StatefulPacket>(data) {
            return Ok(Self::Stateful(p));
        }
        if let Ok(p) = safe_deserialize::<StatelessPacket>(data) {
            return Ok(Self::Stateless(p));
        }
        Err(anyhow!("Unknown packet format"))
    }
}

// ============================================================================
//  3. 令牌管理 (Token Management)
// ============================================================================

#[derive(Serialize, Deserialize)]
struct TokenData {
    timestamp: i64,
    random_salt: u64,
}

/// 负责生成和验证无状态令牌 (防重放/DoS)
pub struct TokenManager {
    secret_key: [u8; 32],
}

impl TokenManager {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { secret_key }
    }

    pub fn generate_token(&self) -> Vec<u8> {
        let data = TokenData {
            timestamp: Utc::now().timestamp(),
            random_salt: rand::random(),
        };
        // 这里可以使用标准 serialize，因为是我们自己生成的数据，可信
        let bytes = bincode::serialize(&data).unwrap(); 
        
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).expect("HMAC init failed");
        mac.update(&bytes);
        let result = mac.finalize();
        
        // Token = Data + HMAC
        let mut token = bytes;
        token.extend_from_slice(&result.into_bytes());
        token
    }

    pub fn validate_token(&self, token: &[u8]) -> bool {
        // 最小长度检查 (HMAC-SHA256 是 32 字节)
        if token.len() < 32 { return false; } 
        
        let split_idx = token.len() - 32; 
        let (data_bytes, sig_bytes) = token.split_at(split_idx);
        
        // 1. 验证签名
        let mut mac = HmacSha256::new_from_slice(&self.secret_key).unwrap();
        mac.update(data_bytes);
        if mac.verify_slice(sig_bytes).is_err() { 
            return false; 
        }
        
        // 2. 验证数据内容与时间戳
        // [Security] 使用安全反序列化，防止 Token 本身包含恶意构造的巨大对象
        if let Ok(data) = safe_deserialize::<TokenData>(data_bytes) {
            let now = Utc::now().timestamp();
            // 允许 30 秒的时间误差 (防重放窗口)
            if (now - data.timestamp).abs() > 30 { 
                return false; 
            }
            return true;
        }
        
        false
    }
}

// ============================================================================
//  4. 物理包封装 (RawPacket - Zero Copy Optimized)
// ============================================================================

/// 封装了物理层传输的字节数据
/// 拥有底层 Buffer 的所有权，并在 Drop 时自动归还给 Pool
pub struct RawPacket {
    /// 对外暴露的数据切片 (Bytes 提供了引用计数和切片能力)
    pub data: Bytes, 
    /// 内部持有的原始 Buffer，用于 Drop 时归还
    /// Option 用于在 Drop 时 take() 所有权
    pub _backing_buffer: Option<Vec<u8>>,
}

impl RawPacket {
    /// 零拷贝加密并封装
    /// 
    /// 流程: Logical Packet -> Serialize -> Padding -> Encrypt -> Obfuscate -> RawPacket
    pub fn encrypt_and_seal(
        packet: &DecryptedPacket,
        crypto: &mut NoiseSession,
        target_size: Option<usize>,
        dialect: &dyn Dialect
    ) -> Result<Self> {
        
        // 1. 获取缓冲区 (从 Thread-Local Pool)
        let mut buffer = acquire_buffer();
        
        // 2. 序列化 (Bincode 写入 Buffer)
        // 使用 serialize_into 直接写入 vec，避免额外内存分配
        match packet {
            DecryptedPacket::Stateful(p) => bincode::serialize_into(&mut buffer, p)
                .context("Packet serialization failed")?,
            DecryptedPacket::Stateless(p) => bincode::serialize_into(&mut buffer, p)
                .context("Packet serialization failed")?,
        };

        // 3. 填充 (Padding)
        // 如果指定了目标大小，且当前数据小于目标大小，则填充随机数据
        // 注意：Noise 协议会把这部分作为明文一起加密，因此对端解密后需要能识别截止位
        // 或者依赖 Bincode 的自描述性忽略尾部数据 (safe_deserialize 已开启 allow_trailing_bytes)
        if let Some(size) = target_size {
            if buffer.len() < size {
                let padding_len = size - buffer.len();
                let current_len = buffer.len();
                // 扩容并填充垃圾数据
                buffer.resize(current_len + padding_len, 0);
                rand::thread_rng().fill(&mut buffer[current_len..]);
            }
        }

        // 4. 加密 (Encrypt)
        // 使用第二个 buffer 作为密文容器 (Noise 协议通常需要 OutBuffer)
        let mut cipher_buffer = acquire_buffer();
        // 预估容量：明文 + MAC (16) + Dialect Header (e.g. 100)
        cipher_buffer.resize(buffer.len() + 16 + 128, 0); 
        
        let len = crypto.encrypt(&buffer, &mut cipher_buffer)
            .context("Noise encryption failed")?;
        cipher_buffer.truncate(len);
        
        // 明文处理完毕，立即归还明文 buffer (触发 Zeroize)
        release_buffer(buffer);

        // 5. 方言伪装 (Dialect Obfuscation)
        // In-place 修改密文 buffer，添加头部或进行混淆
        dialect.seal(&mut cipher_buffer);

        Ok(RawPacket {
            data: Bytes::from(cipher_buffer.clone()), 
            _backing_buffer: Some(cipher_buffer),
        })
    }

    /// 解封并解密
    /// 
    /// 流程: Raw Data -> De-obfuscate -> Decrypt -> Deserialize (Safe) -> Logical Packet
    pub fn unseal_and_decrypt(
        raw_data: &[u8],
        crypto: &mut NoiseSession,
        dialect: &dyn Dialect
    ) -> Result<DecryptedPacket> {
        // 1. 去伪装 (De-obfuscate)
        // 注意：open 可能会返回一个新的 Vec，或者 Cow。Dialect trait 目前定义为返回 Result<Vec<u8>>
        let encrypted_payload = dialect.open(raw_data)
            .context("Dialect open failed")?;

        // 2. 解密 (Decrypt)
        // 使用 Pool 获取解密缓冲区
        let mut plaintext_buf = acquire_buffer();
        // 确保缓冲区足够大
        plaintext_buf.resize(encrypted_payload.len(), 0);
        
        let len = crypto.decrypt(&encrypted_payload, &mut plaintext_buf)
            .context("Noise decryption failed")?;
        plaintext_buf.truncate(len);

        // 3. 安全反序列化 (Safe Deserialize)
        // 尝试解析为 Stateful (大部分流量)
        if let Ok(p) = safe_deserialize::<StatefulPacket>(&plaintext_buf) {
             // 简单的完整性检查
             if p.session_id != 0 {
                 // 成功，归还缓冲区
                 release_buffer(plaintext_buf);
                 return Ok(DecryptedPacket::Stateful(p));
             }
        } 
        
        // 尝试解析为 Stateless (握手包/OOB)
        if let Ok(p) = safe_deserialize::<StatelessPacket>(&plaintext_buf) {
             release_buffer(plaintext_buf);
             return Ok(DecryptedPacket::Stateless(p));
        }
        
        // 失败，归还缓冲区并报错
        release_buffer(plaintext_buf);
        Err(anyhow!("Packet decode failed: Invalid format or integrity check error"))
    }
}

/// 自动资源回收
impl Drop for RawPacket {
    fn drop(&mut self) {
        if let Some(buf) = self._backing_buffer.take() {
            release_buffer(buf);
        }
    }
}
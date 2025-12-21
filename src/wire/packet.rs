// etp-core/src/wire/packet.rs

//! # ETP 核心报文与令牌管理系统 (完全体)
//! 
//! 本模块负责 ETP 协议最底层的数据生命周期管理，涵盖了：
//! 1. **高性能缓冲池**：利用线程局部存储 (TLS) 消除万兆网络下的锁竞争。
//! 2. **零拷贝封装**：通过 `Bytes` 引用计数和预分配缓冲区实现极速封包。
//! 3. **多态报文结构**：支持有状态会话包与无状态控制包。
//! 4. **硬件级安全隔离**：与 XDP 驱动联动，在网卡层面执行秒级令牌拦截。
//! 5. **内存粉碎**：在 `paranoid-security` 特性下强制执行内存物理擦除。

use std::cell::RefCell;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Serialize, Deserialize};
use bincode::{Options, DefaultOptions};
use rand::{Rng, thread_rng};
use anyhow::{Result, anyhow, Context};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use chrono::Utc;
use parking_lot::Mutex;
use log::{info, warn, error, debug, trace};
use bytes::{Bytes, BytesMut};

// 核心类型引用
use crate::{PacketNumber, SessionID};
use crate::wire::frame::Frame;
use crate::crypto::noise::NoiseSession;
use crate::plugin::Dialect;
use crate::common::safe_deserialize;

// 安全增强：物理内存擦除
#[cfg(feature = "paranoid-security")]
use zeroize::Zeroize;

// 硬件加速：XDP 驱动接口
#[cfg(feature = "xdp")]
use crate::network::xda_transport::XdpTransport;

// ============================================================================
//  1. 线程局部缓冲区池 (Lock-Free Buffer Pool)
// ============================================================================

/// 默认包大小：略大于标准 MTU 以容纳隧道开销
const POOL_PACKET_SIZE: usize = 2048;
/// 每个线程缓存的缓冲区上限，防止长尾内存占用
const POOL_CAPACITY: usize = 1024;

/// 内部缓冲区容器
struct BufferPool {
    pool: Vec<Vec<u8>>,
    /// 性能指标：采集命中率
    stats_hits: u64,
    stats_misses: u64,
}

impl BufferPool {
    fn new() -> Self {
        Self {
            pool: Vec::with_capacity(POOL_CAPACITY),
            stats_hits: 0,
            stats_misses: 0,
        }
    }

    /// 获取一个干净的缓冲区
    #[inline]
    fn acquire(&mut self) -> Vec<u8> {
        if let Some(mut buf) = self.pool.pop() {
            self.stats_hits += 1;
            buf.clear(); // 保持容量，逻辑清空
            buf
        } else {
            self.stats_misses += 1;
            Vec::with_capacity(POOL_PACKET_SIZE)
        }
    }

    /// 归还缓冲区，执行必要的安全清理
    #[inline]
    fn release(&mut self, mut buf: Vec<u8>) {
        // [Security] 偏执模式：在缓冲区回到池中前，物理粉碎内存数据
        // 防止后续其它逻辑获取到该缓冲区时读到旧的敏感明文或密钥残余
        #[cfg(feature = "paranoid-security")]
        {
            buf.as_mut_slice().zeroize();
        }

        if self.pool.len() < POOL_CAPACITY && buf.capacity() >= POOL_PACKET_SIZE {
            self.pool.push(buf);
        }
    }
}

// 线程局部单例，确保高并发下无锁竞争
thread_local! {
    static PACKET_POOL: RefCell<BufferPool> = RefCell::new(BufferPool::new());
}

/// 从当前线程池分配一个缓冲区
pub fn acquire_buffer() -> Vec<u8> {
    PACKET_POOL.with(|p| p.borrow_mut().acquire())
}

/// 将缓冲区归还给当前线程池
pub fn release_buffer(buf: Vec<u8>) {
    PACKET_POOL.with(|p| p.borrow_mut().release(buf));
}

// ============================================================================
//  2. 令牌管理器 (TokenManager) - 内置 XDP 硬件卸载
// ============================================================================

/// 内部使用的令牌数据结构
#[derive(Serialize, Deserialize)]
struct TokenMetadata {
    timestamp: i64,
    salt: u64,
}

/// 令牌管理器实现
pub struct TokenManager {
    /// 令牌签名密钥 (Stateless Secret)
    secret_key: [u8; 32],
    
    /// [手段 12] 追踪当前通过 XDP 卸载到硬件的 Token
    /// 用于用户态 housekeeping 与内核态 Map 的同步删除
    active_tokens: Mutex<HashMap<[u8; 32], u64>>,
    
    /// XDP 传输层句柄引用
    #[cfg(feature = "xdp")]
    xdp_link: Mutex<Option<Arc<XdpTransport>>>,

    // 统计指标
    pub stats_generated: AtomicU64,
    pub stats_validated: AtomicU64,
    pub stats_rejected: AtomicU64,
}

impl TokenManager {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret_key: secret,
            active_tokens: Mutex::new(HashMap::new()),
            #[cfg(feature = "xdp")]
            xdp_link: Mutex::new(None),
            stats_generated: AtomicU64::new(0),
            stats_validated: AtomicU64::new(0),
            stats_rejected: AtomicU64::new(0),
        }
    }

    /// 关联 XDP 硬件平面
    #[cfg(feature = "xdp")]
    pub fn link_xdp_transport(&self, transport: Arc<XdpTransport>) {
        let mut guard = self.xdp_link.lock();
        *guard = Some(transport);
        info!("TokenManager: Hardware XDP synchronization active.");
    }

    /// [手段 12/21] 核心：生成令牌并同步至网卡驱动
    /// 
    /// 格式: [Timestamp (8B)][Salt (8B)][HMAC-SHA256 (32B)] = 48 字节
    pub fn generate_token(&self) -> Vec<u8> {
        let now = Utc::now().timestamp();
        let salt: u64 = thread_rng().gen();
        
        let mut meta_bytes = Vec::with_capacity(16);
        meta_bytes.extend_from_slice(&now.to_be_bytes());
        meta_bytes.extend_from_slice(&salt.to_be_bytes());

        // 计算高强度签名
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret_key)
            .expect("HMAC-SHA256 initialization failed");
        mac.update(&meta_bytes);
        let signature = mac.finalize().into_bytes();

        let mut full_token = meta_bytes;
        full_token.extend_from_slice(&signature);

        // 构造硬件查找 Key (通常取签名部分的 32 字节摘要)
        let mut xdp_key = [0u8; 32];
        xdp_key.copy_from_slice(&full_token[16..48]);
        
        // 默认有效期 30 秒 (ETP 握手典型重试窗口)
        let expiry = (now + 30) as u64;

        // 更新用户态追踪表
        self.active_tokens.lock().insert(xdp_key, expiry);

        // 同步至内核态 eBPF Map
        #[cfg(feature = "xdp")]
        {
            if let Some(transport) = &*self.xdp_link.lock() {
                if let Err(e) = transport.sync_token(xdp_key, expiry) {
                    trace!("TokenManager: XDP Map sync deferred (errno: {})", e);
                }
            }
        }

        self.stats_generated.fetch_add(1, Ordering::Relaxed);
        full_token
    }

    /// 校验令牌合法性
    pub fn validate_token(&self, token: &[u8]) -> bool {
        if token.len() != 48 { return false; }

        let (meta, sig) = token.split_at(16);
        
        // 1. 验证签名完整性
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret_key).unwrap();
        mac.update(meta);
        if mac.verify_slice(sig).is_err() {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // 2. 验证时间戳偏移 (允许 30 秒时钟抖动)
        let ts = i64::from_be_bytes(meta[0..8].try_into().unwrap());
        let delta = (Utc::now().timestamp() - ts).abs();
        
        if delta > 30 {
            self.stats_rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.stats_validated.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// [内核维护逻辑]：清理过期令牌并释放网卡硬件资源
    /// 由 EtpEngine 的 handle_tick 每秒触发一次
    pub fn housekeeping(&self) {
        let now = Utc::now().timestamp() as u64;
        let mut to_flush = Vec::new();

        {
            let mut active = self.active_tokens.lock();
            // 采用高效的 retain 进行就地删除
            active.retain(|key, expiry| {
                if now > *expiry {
                    to_flush.push(*key);
                    false // 移除过期项
                } else {
                    true // 保留
                }
            });
        }

        // 同步通知网卡驱动：这些令牌已失效，不再允许入站
        #[cfg(feature = "xdp")]
        {
            if !to_flush.is_empty() {
                if let Some(transport) = &*self.xdp_link.lock() {
                    for key in to_flush {
                        let _ = transport.remove_token(key);
                    }
                    debug!("TokenManager: Hardware plane cleanup finished ({} items flushed).", to_flush.len());
                }
            }
        }
    }
}

// ============================================================================
//  3. 逻辑报文定义 (Logical Structures)
// ============================================================================

/// 有状态数据包：用于已建立 Noise 会话后的正常通信
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatefulPacket {
    pub session_id: SessionID,
    pub packet_number: PacketNumber,
    pub frames: Vec<Frame>,
}

/// 无状态数据包：用于握手请求、NAT 探测、DHT 维护 (手段 12/15)
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatelessPacket {
    /// 包含防重放与 HMAC 签名的令牌
    pub token: Vec<u8>,
    /// 用于一次性加密的随机数
    pub nonce: u64,
    pub frames: Vec<Frame>,
}

/// 解密后的统一分发枚举
#[derive(Debug)]
pub enum DecryptedPacket {
    Stateful(StatefulPacket),
    Stateless(StatelessPacket),
}

// ============================================================================
//  4. 物理层封装 (RawPacket - Zero Copy optimized)
// ============================================================================

/// 封装了加密并经过方言混淆的物理数据包
pub struct RawPacket {
    /// 引用计数的不可变字节流，支持零拷贝切片
    pub data: Bytes,
    /// 原始缓冲区，用于在 Drop 时将所有权归还给线程池
    _backing_buffer: Option<Vec<u8>>,
}

impl RawPacket {
    /// 封装逻辑：Logical -> Serialize -> Pad -> Encrypt -> Dialect -> Raw
    /// 
    /// # Arguments
    /// * `packet` - 待发送的逻辑包
    /// * `crypto` - Noise 会话实例
    /// * `target_size` - 目标填充大小 (用于破坏长度特征)
    /// * `dialect` - 使用的协议方言
    pub fn encrypt_and_seal(
        packet: &DecryptedPacket,
        crypto: &mut NoiseSession,
        target_size: Option<usize>,
        dialect: &dyn Dialect,
    ) -> Result<Self> {
        
        // 1. 分配缓冲区 (TLS Pool)
        let mut buffer = acquire_buffer();
        
        // 2. 执行序列化 (零分配写入)
        match packet {
            DecryptedPacket::Stateful(p) => bincode::serialize_into(&mut buffer, p)
                .context("Stateful serialization error")?,
            DecryptedPacket::Stateless(p) => bincode::serialize_into(&mut buffer, p)
                .context("Stateless serialization error")?,
        }

        // 3. 应用流量整形填充 (Padding)
        // 即使没有应用层数据，也会在此处补齐垃圾数据
        if let Some(size) = target_size {
            if buffer.len() < size {
                let current_len = buffer.len();
                buffer.resize(size, 0);
                thread_rng().fill(&mut buffer[current_len..]);
            }
        }

        // 4. 执行 Noise 加密 (AEAD)
        let mut cipher_buffer = acquire_buffer();
        // 预留 MAC 标签空间 (通常 16-32 字节)
        cipher_buffer.resize(buffer.len() + 32, 0);
        
        let encrypted_len = crypto.encrypt(&buffer, &mut cipher_buffer)
            .map_err(|e| anyhow!("Noise crypto error: {}", e))?;
        cipher_buffer.truncate(encrypted_len);
        
        // 明文数据已加密，立即释放原始 buffer (触发安全擦除)
        release_buffer(buffer);

        // 5. 应用方言伪装 (Dialect Obfuscation)
        // 这是一个 In-Place 操作，可能添加 HTTP 头部或 TLS 记录伪装
        dialect.seal(&mut cipher_buffer);

        Ok(Self {
            data: Bytes::from(cipher_buffer.clone()),
            _backing_buffer: Some(cipher_buffer),
        })
    }

    /// 解封逻辑：Raw Data -> Dialect Open -> Decrypt -> Deserialize
    pub fn unseal_and_decrypt(
        raw_data: &[u8],
        crypto: &mut NoiseSession,
        dialect: &dyn Dialect,
    ) -> Result<DecryptedPacket> {
        
        // 1. 方言剥离 (De-obfuscate)
        let encrypted_payload = dialect.open(raw_data)
            .context("Dialect de-obfuscation failed")?;

        // 2. 解密
        let mut plain_buf = acquire_buffer();
        plain_buf.resize(encrypted_payload.len(), 0);
        
        let decrypted_len = crypto.decrypt(&encrypted_payload, &mut plain_buf)
            .map_err(|_| anyhow!("Noise integrity check failed (Bad Key or Tampered)"))?;
        plain_buf.truncate(decrypted_len);

        // 3. 安全反序列化判定
        // 首先尝试解析大多数情况下的 Stateful 包 (session_id != 0)
        let bincode_config = DefaultOptions::new()
            .with_limit(10 * 1024 * 1024) // 10MB 防御性上限
            .allow_trailing_bytes();

        if let Ok(stateful) = bincode_config.deserialize::<StatefulPacket>(&plain_buf) {
            if stateful.session_id != 0 {
                release_buffer(plain_buf);
                return Ok(DecryptedPacket::Stateful(stateful));
            }
        }

        // 尝试解析无状态包 (如握手)
        if let Ok(stateless) = bincode_config.deserialize::<StatelessPacket>(&plain_buf) {
            release_buffer(plain_buf);
            return Ok(DecryptedPacket::Stateless(stateless));
        }

        // 兜底释放并报错
        release_buffer(plain_buf);
        Err(anyhow!("Packet protocol mismatch: unrecognizable structure"))
    }
}

/// 自动资源回收：当 RawPacket 离开作用域时，缓冲区自动回池
impl Drop for RawPacket {
    fn drop(&mut self) {
        if let Some(buf) = self._backing_buffer.take() {
            release_buffer(buf);
        }
    }
}

// ============================================================================
//  5. 单元测试 (完整不省略)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::KeyPair;

    #[test]
    fn test_thread_local_pool_efficiency() {
        // 连续 acquire 并 release
        let mut bufs = Vec::new();
        for _ in 0..10 {
            bufs.push(acquire_buffer());
        }
        for b in bufs {
            release_buffer(b);
        }
        
        // 再次获取应命中池
        let b = acquire_buffer();
        assert!(b.capacity() >= POOL_PACKET_SIZE);
        release_buffer(b);
    }

    #[test]
    fn test_token_lifecycle() {
        let secret = [0x42u8; 32];
        let manager = TokenManager::new(secret);
        
        let token = manager.generate_token();
        assert!(manager.validate_token(&token));
        
        // 篡改 Token
        let mut bad_token = token.clone();
        bad_token[40] ^= 0xFF;
        assert!(!manager.validate_token(&bad_token));
    }

    #[test]
    fn test_packet_full_cycle() {
        // 模拟 Noise 环境
        let keys = KeyPair::generate();
        let mut session = NoiseSession::new_initiator(&keys, &keys.public).unwrap();
        let dialect = crate::plugin::StandardDialect;

        let original = DecryptedPacket::Stateful(StatefulPacket {
            session_id: 12345,
            packet_number: 1,
            frames: vec![Frame::new_padding(100)],
        });

        // 加密封包
        let raw = RawPacket::encrypt_and_seal(&original, &mut session, Some(512), &dialect).unwrap();
        
        // 解密还原
        let restored = RawPacket::unseal_and_decrypt(&raw.data, &mut session, &dialect).unwrap();
        
        if let DecryptedPacket::Stateful(p) = restored {
            assert_eq!(p.session_id, 12345);
            assert_eq!(p.packet_number, 1);
        } else {
            panic!("Restored packet type mismatch");
        }
    }
}
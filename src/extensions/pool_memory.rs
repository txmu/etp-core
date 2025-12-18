// etp-core/src/extensions/pool_memory.rs

use std::sync::Arc;
use std::collections::HashMap;
use std::io::{Read, Write};
use parking_lot::{Mutex, RwLock};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};
use rand::RngCore;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{Aead, Key, Nonce};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;

// 引入 ETP 核心组件以实现紧密集成
use crate::NodeID;

// ============================================================================
//  权限系统
// ============================================================================

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub can_read: bool,
    pub can_write: bool,
    pub can_exec: bool,
    pub can_share: bool,
    pub can_unshare: bool,
    pub can_erase: bool,
    pub can_own: bool,
}

impl Permissions {
    /// 解析权限字符串 (e.g., "rwx----")
    pub fn from_str(perm_str: &str) -> Result<Self> {
        if perm_str.len() != 7 {
            return Err(anyhow!("Invalid permission string length"));
        }
        let chars: Vec<char> = perm_str.chars().collect();
        Ok(Self {
            can_read: chars[0] == 'r',
            can_write: chars[1] == 'w',
            can_exec: chars[2] == 'x',
            can_share: chars[3] == 's',
            can_unshare: chars[4] == 'u',
            can_erase: chars[5] == 'e',
            can_own: chars[6] == 'p',
        })
    }
}

// ============================================================================
//  核心内存结构
// ============================================================================

/// 模拟物理内存页
#[derive(Debug, Clone)]
pub struct Page {
    pub index: usize,
    pub data: Vec<u8>, // 页数据
}

impl Page {
    pub fn new(index: usize, size: usize) -> Self {
        Self {
            index,
            data: vec![0u8; size],
        }
    }
}

/// 模拟内存段
#[derive(Debug)]
pub struct Segment {
    pub start_addr: usize,
    pub length: usize,
    pub memory_ref: Arc<VirtualMemory>, // 引用所属的虚拟内存
    pub owner: Option<String>, // Owner ID (e.g. NodeID hex)
    pub permissions: HashMap<String, Permissions>, // User -> Perms
    pub priority: u8,
}

/// 虚拟内存控制器
pub struct VirtualMemory {
    // 物理存储：页索引 -> 页数据
    // 这里简化模拟，直接存 Vec
    pub pages: RwLock<Vec<Option<Page>>>,
    pub page_size: usize,
    pub key: Key, // 加密密钥
}

impl VirtualMemory {
    pub fn new(total_size: usize, page_size: usize) -> Self {
        let num_pages = (total_size + page_size - 1) / page_size;
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);

        Self {
            pages: RwLock::new((0..num_pages).map(|_| None).collect()),
            page_size,
            key: *Key::from_slice(&key_bytes),
        }
    }

    /// 读操作 (自动处理缺页)
    pub fn read(&self, addr: usize, len: usize) -> Result<Vec<u8>> {
        let page_idx = addr / self.page_size;
        let offset = addr % self.page_size;
        
        // 简单实现：跨页读取暂不支持或需循环
        if offset + len > self.page_size {
            return Err(anyhow!("Cross-page read not implemented in this simulation"));
        }

        // 缺页处理 (Lazy Allocation)
        {
            let read_lock = self.pages.read();
            if page_idx >= read_lock.len() {
                return Err(anyhow!("Segmentation fault: Address out of bounds"));
            }
            if let Some(page) = &read_lock[page_idx] {
                return Ok(page.data[offset..offset+len].to_vec());
            }
        } // Drop read lock

        // Allocate page
        let mut write_lock = self.pages.write();
        if write_lock[page_idx].is_none() {
            write_lock[page_idx] = Some(Page::new(page_idx, self.page_size));
        }
        
        let page = write_lock[page_idx].as_ref().unwrap();
        Ok(page.data[offset..offset+len].to_vec())
    }

    /// 写操作
    pub fn write(&self, addr: usize, data: &[u8]) -> Result<()> {
        let page_idx = addr / self.page_size;
        let offset = addr % self.page_size;
        
        if offset + data.len() > self.page_size {
            return Err(anyhow!("Cross-page write not implemented"));
        }

        let mut write_lock = self.pages.write();
        if page_idx >= write_lock.len() {
            return Err(anyhow!("Segmentation fault"));
        }

        if write_lock[page_idx].is_none() {
            write_lock[page_idx] = Some(Page::new(page_idx, self.page_size));
        }

        let page = write_lock[page_idx].as_mut().unwrap();
        page.data[offset..offset+data.len()].copy_from_slice(data);
        Ok(())
    }

    // --- 高级功能 ---

    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(data);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded)?;
        Ok(decoded)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = Nonce::from_slice(&[0u8; 12]); // Fixed nonce for simulation only!
        cipher.encrypt(nonce, data).map_err(|e| anyhow!("Encryption error: {}", e))
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(&self.key);
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher.decrypt(nonce, data).map_err(|e| anyhow!("Decryption error: {}", e))
    }
}

// ============================================================================
//  共享内存池 (Shared Memory Pool)
// ============================================================================

pub struct SharedMemoryPool {
    segments: RwLock<Vec<Arc<RwLock<Segment>>>>,
    capacity_bytes: usize,
    used_bytes: Mutex<usize>,
}

impl SharedMemoryPool {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            segments: RwLock::new(Vec::new()),
            capacity_bytes,
            used_bytes: Mutex::new(0),
        }
    }

    pub fn allocate(&self, size: usize, owner: String, priority: u8) -> Result<Arc<RwLock<Segment>>> {
        let mut used = self.used_bytes.lock();
        
        // 1. 尝试复用或合并 (简化：直接检查容量)
        if *used + size > self.capacity_bytes {
            // 简单的驱逐策略：找到优先级较低的
            // 这里略过实现，直接报错
            return Err(anyhow!("Memory Pool OOM"));
        }

        // 2. 创建新内存
        let vm = Arc::new(VirtualMemory::new(size, 256)); // page size 256
        let segment = Arc::new(RwLock::new(Segment {
            start_addr: 0, // Virtual base
            length: size,
            memory_ref: vm,
            owner: Some(owner.clone()),
            permissions: HashMap::new(),
            priority,
        }));

        // 赋予 Owner 全部权限
        segment.write().permissions.insert(owner, Permissions::from_str("rwxseup")?);

        self.segments.write().push(segment.clone());
        *used += size;

        Ok(segment)
    }

    pub fn free(&self, segment: Arc<RwLock<Segment>>) {
        let mut segs = self.segments.write();
        if let Some(idx) = segs.iter().position(|s| Arc::ptr_eq(s, &segment)) {
            let len = segment.read().length;
            segs.remove(idx);
            *self.used_bytes.lock() -= len;
        }
    }

    pub fn get_usage_ratio(&self) -> f64 {
        *self.used_bytes.lock() as f64 / self.capacity_bytes as f64
    }
}

// --- 紧密集成 ---
// 允许从 ETP Node 获取全局 Pool 实例 (单例模式模拟)
use std::sync::OnceLock;
static GLOBAL_POOL: OnceLock<SharedMemoryPool> = OnceLock::new();

pub fn get_global_pool() -> &'static SharedMemoryPool {
    GLOBAL_POOL.get_or_init(|| SharedMemoryPool::new(1024 * 1024 * 100)) // 100MB Default
}
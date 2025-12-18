// etp-core/src/extensions/ufs_adapter.rs

#![cfg(feature = "ultrafileserver")]

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::io::SeekFrom;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use log::{info, warn, error, debug};
use anyhow::{Result, anyhow, Context};
use std::time::SystemTime;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  UFS 协议定义 (Binary Protocol)
// ============================================================================

const UFS_PROTO_VER: u8 = 0x01;

// 指令集 (Command Set)
const CMD_LIST_REQ: u8   = 0x01; // 列出目录: [Ver][CMD][PathStr]
const CMD_LIST_RESP: u8  = 0x02; // 响应目录: [Ver][CMD][JSON]
const CMD_GET_REQ: u8    = 0x03; // 下载文件: [Ver][CMD][Offset(8)][PathStr]
const CMD_GET_RESP: u8   = 0x04; // 文件数据: [Ver][CMD][Offset(8)][Data...]
const CMD_PUT_REQ: u8    = 0x05; // 上传/写入: [Ver][CMD][Offset(8)][PathStrLen(2)][PathStr][Data...]
const CMD_DEL_REQ: u8    = 0x06; // 删除文件: [Ver][CMD][PathStr]
const CMD_INFO_REQ: u8   = 0x07; // 获取元数据: [Ver][CMD][PathStr]
const CMD_INFO_RESP: u8  = 0x08; // 响应元数据: [Ver][CMD][JSON]
const CMD_ERROR: u8      = 0xFF; // 错误响应: [Ver][CMD][ErrMsg]

// 读写块大小
const CHUNK_SIZE: usize = 64 * 1024; // 64KB

// ============================================================================
//  数据结构
// ============================================================================

#[derive(Serialize, Deserialize, Debug)]
pub struct FileMetadata {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: u64,
    pub mime_type: String, // 简单 MIME 推断
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectoryListing {
    pub path: String,
    pub files: Vec<FileMetadata>,
}

// ============================================================================
//  Flavor 实现
// ============================================================================

/// UltraFileServer Flavor
/// 将本地文件系统暴露给 ETP 网络，支持类 WebDAV 的操作，但通过高效的二进制流传输。
pub struct UltraFileServerFlavor {
    /// 根目录 (Chroot Jail)
    root_dir: PathBuf,
    /// 网络发送通道 (用于回包)
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    /// 是否允许写入 (Upload/Delete)
    read_only: bool,
}

impl UltraFileServerFlavor {
    pub fn new(
        root_path: &str,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        read_only: bool,
    ) -> Result<Arc<Self>> {
        let root = PathBuf::from(root_path).canonicalize()
            .context("Invalid root path")?;
        
        if !root.exists() || !root.is_dir() {
            return Err(anyhow!("Root path must be an existing directory"));
        }

        info!("UFS Adapter initialized. Root: {:?}, ReadOnly: {}", root, read_only);

        Ok(Arc::new(Self {
            root_dir: root,
            network_tx,
            read_only,
        }))
    }

    // --- 路径安全检查 (Path Sanitization) ---
    // 防止目录遍历攻击 (Directory Traversal)
    fn resolve_path(&self, relative_path: &str) -> Result<PathBuf> {
        // 移除开头的所有 ./ 和 /
        let clean_rel = relative_path.trim_start_matches(|c| c == '/' || c == '\\' || c == '.');
        let joined = self.root_dir.join(clean_rel);
        
        // 规范化路径 (处理 ..)
        // 注意：canonicalize 要求路径必须存在，对于写入新文件，我们需要检查其父目录
        // 这里做一个简单的词法检查，更严格的检查通常需要 OS 支持
        // 为简化，我们只允许 path 不包含 ".." 组件
        if relative_path.split('/').any(|p| p == "..") || relative_path.split('\\').any(|p| p == "..") {
            return Err(anyhow!("Invalid path: Traversal detected"));
        }

        Ok(joined)
    }

    // --- 业务处理逻辑 ---

    async fn handle_list(&self, peer: SocketAddr, path_str: String) -> Result<()> {
        let target_path = self.resolve_path(&path_str)?;
        
        if !target_path.exists() {
            return self.send_error(peer, "Path not found").await;
        }

        let mut entries = Vec::new();
        let mut dir_reader = fs::read_dir(target_path).await?;

        while let Some(entry) = dir_reader.next_entry().await? {
            let meta = entry.metadata().await?;
            let name = entry.file_name().to_string_lossy().to_string();
            
            // 简单的 MIME 推断
            let mime = if meta.is_dir() {
                "inode/directory".to_string()
            } else {
                match Path::new(&name).extension().and_then(|s| s.to_str()) {
                    Some("txt") => "text/plain",
                    Some("json") => "application/json",
                    Some("jpg") | Some("png") => "image/jpeg",
                    Some("mp4") => "video/mp4",
                    _ => "application/octet-stream",
                }.to_string()
            };

            let modified = meta.modified()
                .unwrap_or(SystemTime::now())
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            entries.push(FileMetadata {
                name,
                is_dir: meta.is_dir(),
                size: meta.len(),
                modified,
                mime_type: mime,
            });
        }

        let listing = DirectoryListing {
            path: path_str,
            files: entries,
        };

        let json_bytes = serde_json::to_vec(&listing)?;
        let mut resp = vec![UFS_PROTO_VER, CMD_LIST_RESP];
        resp.extend(json_bytes);

        self.send_raw(peer, resp).await
    }

    async fn handle_get(&self, peer: SocketAddr, path_str: String, offset: u64) -> Result<()> {
        let target_path = self.resolve_path(&path_str)?;
        
        let mut file = match File::open(&target_path).await {
            Ok(f) => f,
            Err(_) => return self.send_error(peer, "File not found or access denied").await,
        };

        // Seek
        if offset > 0 {
            if let Err(_) = file.seek(SeekFrom::Start(offset)).await {
                return self.send_error(peer, "Seek failed").await;
            }
        }

        // 读取一块数据 (Chunked Read)
        // 注意：在大文件传输中，我们不应该在这里循环读取所有数据，
        // 否则会阻塞 Flavor 线程。
        // UFS 协议设计为请求-响应式：客户端请求 Offset X，服务端返回 Offset X 的数据块。
        // 客户端收到后，再请求 Offset X + ChunkSize。
        // 这样实现了流控和多路复用的公平性。
        
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = file.read(&mut buf).await?;
        buf.truncate(n);

        // 构造响应: [Ver][CMD][Offset(8)][Data]
        let mut resp = Vec::with_capacity(1 + 1 + 8 + n);
        resp.push(UFS_PROTO_VER);
        resp.push(CMD_GET_RESP);
        resp.extend_from_slice(&offset.to_be_bytes());
        resp.extend(buf);

        self.send_raw(peer, resp).await
    }

    async fn handle_put(&self, peer: SocketAddr, path_str: String, offset: u64, data: Vec<u8>) -> Result<()> {
        if self.read_only {
            return self.send_error(peer, "Server is read-only").await;
        }

        let target_path = self.resolve_path(&path_str)?;
        
        // 确保父目录存在
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // 打开文件 (Create or Append/Write)
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&target_path)
            .await?;

        file.seek(SeekFrom::Start(offset)).await?;
        file.write_all(&data).await?;
        
        // 不需要显式 ACK，ETP 层保证可靠性。
        // 或者可以发送 CMD_INFO_RESP 更新文件大小。
        debug!("UFS: Wrote {} bytes to {} at {}", data.len(), path_str, offset);
        Ok(())
    }

    async fn handle_del(&self, peer: SocketAddr, path_str: String) -> Result<()> {
        if self.read_only {
            return self.send_error(peer, "Server is read-only").await;
        }

        let target_path = self.resolve_path(&path_str)?;
        if target_path.is_dir() {
            fs::remove_dir_all(target_path).await?;
        } else {
            fs::remove_file(target_path).await?;
        }
        
        // 返回新的列表或 Info
        self.send_error(peer, "OK: Deleted").await // 复用 Error 帧发送简单消息
    }

    async fn handle_info(&self, peer: SocketAddr, path_str: String) -> Result<()> {
        let target_path = self.resolve_path(&path_str)?;
        if let Ok(meta) = fs::metadata(&target_path).await {
             let modified = meta.modified()?.duration_since(std::time::UNIX_EPOCH)?.as_secs();
             let info = FileMetadata {
                 name: path_str,
                 is_dir: meta.is_dir(),
                 size: meta.len(),
                 modified,
                 mime_type: "application/octet-stream".into(),
             };
             let json_bytes = serde_json::to_vec(&info)?;
             let mut resp = vec![UFS_PROTO_VER, CMD_INFO_RESP];
             resp.extend(json_bytes);
             self.send_raw(peer, resp).await?;
        } else {
             self.send_error(peer, "Not found").await?;
        }
        Ok(())
    }

    // --- 辅助 ---

    async fn send_raw(&self, target: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.network_tx.send((target, data)).await
            .map_err(|_| anyhow!("Network channel closed"))
    }

    async fn send_error(&self, target: SocketAddr, msg: &str) -> Result<()> {
        let mut resp = vec![UFS_PROTO_VER, CMD_ERROR];
        resp.extend_from_slice(msg.as_bytes());
        self.send_raw(target, resp).await
    }
}

// ============================================================================
//  Plugin Interface 实现
// ============================================================================

impl CapabilityProvider for UltraFileServerFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.ufs.v1".into()
    }
}

impl Flavor for UltraFileServerFlavor {
    fn priority(&self) -> u8 {
        100
    }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != UFS_PROTO_VER {
            return false;
        }

        let cmd = data[1];
        let payload = &data[2..];
        let peer = ctx.src_addr;
        
        // 为了不阻塞 Flavor 调度线程，所有 IO 操作都 Spawn 出去
        // 需要 Clone Arc
        // 在 Rust 2018+，self 如果是 &Arc<Self> (via trait object wrapper logic in core), 
        // 但这里 self 是 &UltraFileServerFlavor。我们需要在外部通过 Arc 包装。
        // 标准做法是 Flavor trait 自身不强制 Arc，但在注册时是 Arc<dyn Flavor>。
        // 这里的 self 是引用。我们需要一种方式将 `self` 的数据移动到 async block。
        // 
        // 解决方案：UltraFileServerFlavor 的字段大多是轻量的 (PathBuf, Sender) 或 Arc。
        // 我们可以 Clone 字段。或者更好的是，我们在 new 时返回 Arc<Self>，
        // 并在注册时使用。但是 Flavor trait 方法是 &self。
        // 我们需要 clone 内部字段来 spawn。
        
        let root_dir = self.root_dir.clone();
        let net_tx = self.network_tx.clone();
        let read_only = self.read_only;
        
        // 构造一个临时的 Self 副本 (Lightweight clone) 用于 async task
        // 注意：这种 clone 只是路径和通道的拷贝，开销很小
        let worker = UltraFileServerFlavor {
            root_dir,
            network_tx: net_tx,
            read_only,
        };

        // 将 payload 拷贝一份 (Vec<u8>)
        let data_vec = payload.to_vec();

        tokio::spawn(async move {
            let res = match cmd {
                CMD_LIST_REQ => {
                    let path_str = String::from_utf8_lossy(&data_vec).to_string();
                    worker.handle_list(peer, path_str).await
                },
                CMD_GET_REQ => {
                    if data_vec.len() < 8 { return; }
                    let offset_bytes: [u8; 8] = data_vec[0..8].try_into().unwrap();
                    let offset = u64::from_be_bytes(offset_bytes);
                    let path_str = String::from_utf8_lossy(&data_vec[8..]).to_string();
                    worker.handle_get(peer, path_str, offset).await
                },
                CMD_PUT_REQ => {
                    // [Offset(8)][PathLen(2)][Path][Data]
                    if data_vec.len() < 10 { return; }
                    let offset = u64::from_be_bytes(data_vec[0..8].try_into().unwrap());
                    let path_len = u16::from_be_bytes(data_vec[8..10].try_into().unwrap()) as usize;
                    
                    if data_vec.len() < 10 + path_len { return; }
                    let path_str = String::from_utf8_lossy(&data_vec[10..10+path_len]).to_string();
                    let file_data = data_vec[10+path_len..].to_vec();
                    
                    worker.handle_put(peer, path_str, offset, file_data).await
                },
                CMD_DEL_REQ => {
                    let path_str = String::from_utf8_lossy(&data_vec).to_string();
                    worker.handle_del(peer, path_str).await
                },
                CMD_INFO_REQ => {
                    let path_str = String::from_utf8_lossy(&data_vec).to_string();
                    worker.handle_info(peer, path_str).await
                },
                _ => Ok(()),
            };

            if let Err(e) = res {
                error!("UFS Worker Error: {}", e);
                let _ = worker.send_error(peer, &e.to_string()).await;
            }
        });

        true
    }

    fn on_connection_open(&self, _peer: SocketAddr) {
        // UFS 是被动响应的，连接建立时不需要主动发包
    }

    fn on_connection_close(&self, _peer: SocketAddr) {}
}
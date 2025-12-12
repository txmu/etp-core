// etp-core/src/plugin/flavors/fileshare.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error};
use parking_lot::{RwLock, Mutex};
use tokio::sync::mpsc;
use blake3;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

// --- 常量 ---
const FS_PROTO_VER: u8 = 0x01;
const CMD_MANIFEST_REQ: u8 = 0x01;
const CMD_MANIFEST_RESP: u8 = 0x02;
const CMD_CHUNK_REQ: u8 = 0x03;
const CMD_CHUNK_RESP: u8 = 0x04;

const CHUNK_SIZE: usize = 16 * 1024; // 16KB

/// 文件清单 (Torrent equivalent)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub chunk_count: u32,
    pub root_hash: [u8; 32], // Merkle Root
    pub chunk_hashes: Vec<[u8; 32]>, // Simplified: List of hashes
}

impl FileManifest {
    pub fn verify_chunk(&self, index: u32, data: &[u8]) -> bool {
        if index as usize >= self.chunk_hashes.len() { return false; }
        let hash = blake3::hash(data);
        hash.as_bytes() == &self.chunk_hashes[index as usize]
    }
}

/// 下载任务状态
struct DownloadTask {
    manifest: FileManifest,
    downloaded_chunks: HashSet<u32>, // Bitfield better, Set easier
    temp_path: PathBuf,
}

pub struct FileShareFlavor {
    storage_dir: PathBuf,
    // 已分享的文件: RootHash -> Manifest
    shared_files: RwLock<HashMap<[u8; 32], FileManifest>>,
    // 正在下载的任务: RootHash -> Task
    active_downloads: Arc<Mutex<HashMap<[u8; 32], DownloadTask>>>,
    // 网络发送通道
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

impl FileShareFlavor {
    pub fn new(
        storage_path: &str,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Result<Arc<Self>> {
        fs::create_dir_all(storage_path)?;
        Ok(Arc::new(Self {
            storage_dir: PathBuf::from(storage_path),
            shared_files: RwLock::new(HashMap::new()),
            active_downloads: Arc::new(Mutex::new(HashMap::new())),
            network_tx,
        }))
    }

    /// 分享本地文件
    pub fn share_file(&self, path: &Path) -> Result<[u8; 32]> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();
        let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
        
        let mut chunk_hashes = Vec::new();
        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut hasher = blake3::Hasher::new(); // For Root

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            let chunk_hash = blake3::hash(&buffer[..n]);
            chunk_hashes.push(*chunk_hash.as_bytes());
            hasher.update(chunk_hash.as_bytes());
        }

        let root_hash: [u8; 32] = hasher.finalize().into();
        
        let manifest = FileManifest {
            file_name,
            file_size,
            mime_type: "application/octet-stream".into(), // Detect logic omitted
            chunk_count: chunk_hashes.len() as u32,
            root_hash,
            chunk_hashes,
        };

        self.shared_files.write().insert(root_hash, manifest);
        
        // Ensure file is in storage dir or symlinked? 
        // For MVP, we assume we read from origin or copy to storage.
        // Copying to storage for simplicity.
        let dest = self.storage_dir.join(hex::encode(root_hash));
        fs::copy(path, dest)?;

        info!("FileShare: Shared {} (Root: {:?})", path.display(), hex::encode(root_hash));
        Ok(root_hash)
    }

    /// 开始下载文件
    pub async fn start_download(&self, root_hash: [u8; 32], peer: SocketAddr) -> Result<()> {
        // 1. 发送 Manifest 请求
        let mut req = vec![FS_PROTO_VER, CMD_MANIFEST_REQ];
        req.extend_from_slice(&root_hash);
        
        self.network_tx.send((peer, req)).await?;
        info!("FileShare: Requesting file {:?} from {}", hex::encode(root_hash), peer);
        Ok(())
    }

    // --- 内部 IO ---

    fn read_chunk(&self, root_hash: &[u8; 32], index: u32) -> Result<Vec<u8>> {
        let path = self.storage_dir.join(hex::encode(root_hash));
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start((index as usize * CHUNK_SIZE) as u64))?;
        
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = file.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write_chunk(&self, root_hash: &[u8; 32], index: u32, data: &[u8]) -> Result<()> {
        let path = self.storage_dir.join(format!("{}.part", hex::encode(root_hash)));
        // Open with create/write
        let mut file = fs::OpenOptions::new().create(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start((index as usize * CHUNK_SIZE) as u64))?;
        file.write_all(data)?;
        Ok(())
    }
}

impl CapabilityProvider for FileShareFlavor {
    fn capability_id(&self) -> String { "etp.flavor.fs.v1".into() }
}

impl Flavor for FileShareFlavor {
    fn priority(&self) -> u8 { 80 } // 文件传输优先级较低

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != FS_PROTO_VER { return false; }

        match data[1] {
            CMD_MANIFEST_REQ => {
                // [Hash(32)]
                if data.len() < 34 { return true; }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[2..34]);
                
                if let Some(manifest) = self.shared_files.read().get(&hash) {
                    if let Ok(bytes) = bincode::serialize(manifest) {
                        let mut resp = vec![FS_PROTO_VER, CMD_MANIFEST_RESP];
                        resp.extend(bytes);
                        let tx = self.network_tx.clone();
                        let addr = ctx.src_addr;
                        tokio::spawn(async move { let _ = tx.send((addr, resp)).await; });
                    }
                }
                true
            },
            CMD_MANIFEST_RESP => {
                if let Ok(manifest) = bincode::deserialize::<FileManifest>(&data[2..]) {
                    info!("FileShare: Received manifest for {}", manifest.file_name);
                    // Initialize Download Task
                    let path = self.storage_dir.join(format!("{}.part", hex::encode(manifest.root_hash)));
                    let task = DownloadTask {
                        manifest: manifest.clone(),
                        downloaded_chunks: HashSet::new(),
                        temp_path: path,
                    };
                    self.active_downloads.lock().insert(manifest.root_hash, task);
                    
                    // Start requesting chunks (First 5 for pipeline)
                    let tx = self.network_tx.clone();
                    let root = manifest.root_hash;
                    let addr = ctx.src_addr;
                    
                    tokio::spawn(async move {
                        for i in 0..manifest.chunk_count.min(5) {
                            let mut req = vec![FS_PROTO_VER, CMD_CHUNK_REQ];
                            req.extend_from_slice(&root);
                            req.extend_from_slice(&i.to_be_bytes());
                            let _ = tx.send((addr, req)).await;
                        }
                    });
                }
                true
            },
            CMD_CHUNK_REQ => {
                // [Hash(32)][Index(4)]
                if data.len() < 38 { return true; }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[2..34]);
                let idx_bytes: [u8; 4] = data[34..38].try_into().unwrap();
                let index = u32::from_be_bytes(idx_bytes);
                
                if let Ok(chunk_data) = self.read_chunk(&hash, index) {
                    let mut resp = vec![FS_PROTO_VER, CMD_CHUNK_RESP];
                    resp.extend_from_slice(&hash);
                    resp.extend_from_slice(&index.to_be_bytes());
                    resp.extend(chunk_data);
                    
                    let tx = self.network_tx.clone();
                    let addr = ctx.src_addr;
                    tokio::spawn(async move { let _ = tx.send((addr, resp)).await; });
                }
                true
            },
            CMD_CHUNK_RESP => {
                // [Hash(32)][Index(4)][Data...]
                if data.len() < 38 { return true; }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[2..34]);
                let idx_bytes: [u8; 4] = data[34..38].try_into().unwrap();
                let index = u32::from_be_bytes(idx_bytes);
                let chunk_data = &data[38..];
                
                let mut finished = false;
                let mut filename = String::new();
                
                {
                    let mut downloads = self.active_downloads.lock();
                    if let Some(task) = downloads.get_mut(&hash) {
                        // Verify
                        if task.manifest.verify_chunk(index, chunk_data) {
                            if let Ok(_) = self.write_chunk(&hash, index, chunk_data) {
                                task.downloaded_chunks.insert(index);
                                debug!("FileShare: Downloaded chunk {}/{}", index, task.manifest.chunk_count);
                                
                                // Request next chunk logic (Pipeline) would go here
                                
                                // Check completion
                                if task.downloaded_chunks.len() as u32 == task.manifest.chunk_count {
                                    finished = true;
                                    filename = task.manifest.file_name.clone();
                                }
                            }
                        } else {
                            warn!("FileShare: Chunk verification failed!");
                        }
                    }
                }
                
                if finished {
                    info!("FileShare: Download Complete! {}", filename);
                    let mut downloads = self.active_downloads.lock();
                    if let Some(task) = downloads.remove(&hash) {
                        // Rename .part to final
                        let final_path = self.storage_dir.join(filename);
                        let _ = fs::rename(task.temp_path, final_path);
                    }
                }
                
                true
            },
            _ => false,
        }
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}
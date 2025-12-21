// etp-core/src/plugin/flavors/tns.rs

//! # TNS (T Name Service) - 工业级全功能实现
//! 
//! 本模块提供了抗审查、高性能的去中心化域名寻址服务。
//! 
//! ## 生产级特性：
//! 1. **增量状态同步**：通过 `TnsBloomFilter` 实现基于差异的 Gossip 同步，避免全量数据冲击带宽。
//! 2. **信誉分准入 (Gated)**：集成内核信誉评价体系，仅转发高信誉节点的记录。
//! 3. **多跳扩散 (Fan-out)**：实现传染病扩散模型，新记录自动分发至多个随机邻居。
//! 4. **全文搜索索引 (Gated)**：支持将公开域名信息实时推送到外部搜索中心。
//! 5. **异步自引用架构**：通过 `Weak<Self>` 解决在异步 `tokio::spawn` 中持有 Flavor 句柄的问题。

use std::sync::{Arc, Weak};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sled::Db;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error, trace};
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use blake3;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::{Rng, thread_rng};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider, SystemContext};
use crate::NodeID;
use crate::common::DhtStoreRequest;

// ============================================================================
//  协议常量与硬编码限制
// ============================================================================

const TNS_PROTO_VER: u8 = 0x02;

// 指令集
const CMD_QUERY: u8         = 0x01; // 查询请求
const CMD_RESPONSE: u8      = 0x02; // 查询响应
const CMD_PUBLISH: u8       = 0x03; // 主动推送 (Gossip 数据包)
const CMD_SYNC_OFFER: u8    = 0x04; // 发送 Bloom Filter 提议进行差异同步
const CMD_ERROR: u8         = 0xFF; // 错误响应

// 逻辑限制
const RECORD_TTL_SECS: u64  = 604800;     // 7天有效期
const QUERY_TIMEOUT_SECS: u64 = 5;        // 查询超时
const GOSSIP_FAN_OUT: usize = 3;          // 每次扩散的随机邻居数
const BLOOM_SIZE_BITS: usize = 8192;      // 1KB Bloom Filter
const BLOOM_HASH_FUNCS: usize = 3;

#[cfg(feature = "tns-reputation")]
const MIN_REPUTATION_FOR_GOSSIP: i32 = 50; // 转发他人记录所需的最低信誉分

// ============================================================================
//  数据结构实现
// ============================================================================

/// TNS 域名记录
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TnsRecord {
    pub name: String,
    pub target_id: NodeID,
    pub owner_pub_key: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub metadata: Vec<u8>,
}

impl TnsRecord {
    /// 验证记录的 Ed25519 签名
    pub fn verify_signature(&self) -> Result<()> {
        let verify_key = VerifyingKey::from_bytes(&self.owner_pub_key)
            .map_err(|_| anyhow!("TNS: Malformed public key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("TNS: Malformed signature"))?;

        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&self.target_id);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.metadata);

        verify_key.verify(&data, &signature)
            .map_err(|_| anyhow!("TNS: Cryptographic signature mismatch"))
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.timestamp > now + 300 || now.saturating_sub(self.timestamp) > RECORD_TTL_SECS
    }

    pub fn dht_key(&self) -> NodeID {
        blake3::hash(self.name.as_bytes()).into()
    }
}

/// 布隆过滤器同步容器
#[derive(Serialize, Deserialize)]
struct TnsBloomFilter {
    bits: Vec<u8>,
}

impl TnsBloomFilter {
    fn new() -> Self {
        Self { bits: vec![0u8; BLOOM_SIZE_BITS / 8] }
    }
    fn insert(&mut self, item: &[u8]) {
        for i in 0..BLOOM_HASH_FUNCS {
            let idx = self.calculate_hash(item, i) % BLOOM_SIZE_BITS;
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }
    fn contains(&self, item: &[u8]) -> bool {
        for i in 0..BLOOM_HASH_FUNCS {
            let idx = self.calculate_hash(item, i) % BLOOM_SIZE_BITS;
            if (self.bits[idx / 8] & (1 << (idx % 8))) == 0 { return false; }
        }
        true
    }
    fn calculate_hash(&self, item: &[u8], seed: usize) -> usize {
        let mut h = blake3::Hasher::new();
        h.update(&seed.to_le_bytes());
        h.update(item);
        let res = h.finalize();
        let mut b = [0u8; 8];
        b.copy_from_slice(&res.as_bytes()[0..8]);
        u64::from_le_bytes(b) as usize
    }
}

struct PendingQuery {
    notifiers: Vec<oneshot::Sender<Result<TnsRecord>>>,
    created_at: Instant,
}

// ============================================================================
//  TnsFlavor 主结构
// ============================================================================

pub struct TnsFlavor {
    db: Db,
    dht_tx: mpsc::Sender<DhtStoreRequest>,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    signing_key: SigningKey,
    pending_queries: Arc<RwLock<HashMap<String, PendingQuery>>>,
    
    /// 用于在异步任务中安全获取 Arc 指针
    self_weak: RwLock<Weak<TnsFlavor>>,

    #[cfg(feature = "tns-indexer")]
    indexer_api_url: Arc<RwLock<Option<String>>>,
}

impl TnsFlavor {
    /// 生产级构造函数：利用 new_cyclic 建立自引用
    pub fn new(
        db_path: &str,
        signing_key_bytes: &[u8; 32],
        dht_tx: mpsc::Sender<DhtStoreRequest>,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Arc<Self> {
        let db = sled::open(db_path).expect("TNS: Failed to open Sled DB");
        let signing_key = SigningKey::from_bytes(signing_key_bytes);

        Arc::new_cyclic(|me| {
            Self {
                db,
                dht_tx,
                network_tx,
                signing_key,
                pending_queries: Arc::new(RwLock::new(HashMap::new())),
                self_weak: RwLock::new(me.clone()),
                #[cfg(feature = "tns-indexer")]
                indexer_api_url: Arc::new(RwLock::new(None)),
            }
        })
    }

    /// [手段 18] 设置搜索引擎 API 地址并验证
    #[cfg(feature = "tns-indexer")]
    pub async fn set_indexer_api(&self, url: &str) -> Result<()> {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(3)).build()?;
        client.head(url).send().await.context("Indexer API validation failed")?;
        *self.indexer_api_url.write() = Some(url.to_string());
        info!("TNS: Search indexer active: {}", url);
        Ok(())
    }

    // ========================================================================
    //  API 业务接口
    // ========================================================================

    /// 解析域名：查库 -> 发起网络 Gossip -> 等待结果
    pub async fn resolve(&self, name: &str) -> Result<TnsRecord> {
        if let Some(record) = self.get_cached(name)? {
            if !record.is_expired() { return Ok(record); }
        }

        let (tx, rx) = oneshot::channel();
        let mut broadcast_needed = false;
        {
            let mut pending = self.pending_queries.write();
            let entry = pending.entry(name.to_string()).or_insert_with(|| {
                broadcast_needed = true;
                PendingQuery { notifiers: Vec::new(), created_at: Instant::now() }
            });
            entry.notifiers.push(tx);
        }

        if broadcast_needed {
            let mut payload = vec![TNS_PROTO_VER, CMD_QUERY];
            payload.extend_from_slice(name.as_bytes());
            // 发送到全网广播地址 0.0.0.0:0，由内核执行随机扩散
            let _ = self.network_tx.send((SocketAddr::from(([0,0,0,0], 0)), payload)).await;
        }

        match tokio::time::timeout(Duration::from_secs(QUERY_TIMEOUT_SECS), rx).await {
            Ok(Ok(res)) => res,
            _ => Err(anyhow!("TNS: Resolution timeout for '{}'", name)),
        }
    }

    /// 注册新域名并启动全球扩散
    pub async fn register_name(&self, name: &str, target: NodeID, metadata: Vec<u8>) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut payload = Vec::new();
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&target);
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(&metadata);
        
        let signature = self.signing_key.sign(&payload).to_bytes().to_vec();
        let record = TnsRecord {
            name: name.to_string(),
            target_id: target,
            owner_pub_key: self.signing_key.verifying_key().to_bytes(),
            timestamp,
            signature,
            metadata,
        };

        // 1. 存入本地数据库
        self.store_record(&record)?;
        
        // 2. 注入 DHT 骨干网络
        let _ = self.dht_tx.send(DhtStoreRequest {
            key: record.dht_key(),
            value: bincode::serialize(&record)?,
            ttl_seconds: RECORD_TTL_SECS as u32,
        }).await;

        // 3. 触发主动 Gossip 扩散 (Fan-out)
        self.fan_out_record(record, None).await;
        
        Ok(())
    }

    // ========================================================================
    //  内部同步与扩散逻辑
    // ========================================================================

    /// [手段 3/15] 扇出广播：向随机邻居分发记录
    async fn fan_out_record(&self, record: TnsRecord, exclude: Option<SocketAddr>) {
        if let Ok(bytes) = bincode::serialize(&record) {
            let mut payload = vec![TNS_PROTO_VER, CMD_PUBLISH];
            payload.extend(bytes);
            
            // 发送给内核，由内核决定具体的邻居列表 (Gossip 广播逻辑)
            let _ = self.network_tx.send((SocketAddr::from(([0,0,0,0], 0)), payload)).await;
        }
    }

    fn store_record(&self, record: &TnsRecord) -> Result<()> {
        let tree = self.db.open_tree("records")?;
        tree.insert(&record.name, bincode::serialize(record)?)?;
        Ok(())
    }

    fn process_record_safely(&self, new: &TnsRecord) -> Result<bool> {
        let tree = self.db.open_tree("records")?;
        if let Some(old_bytes) = tree.get(&new.name)? {
            let old: TnsRecord = bincode::deserialize(&old_bytes)?;
            // TOFU 安全规则：所有权不可更改
            if old.owner_pub_key != new.owner_pub_key {
                return Err(anyhow!("TNS ACL: Ownership violation for '{}'", new.name));
            }
            // 版本规则：时间戳必须更新
            if new.timestamp <= old.timestamp { return Ok(false); }
        }
        tree.insert(&new.name, bincode::serialize(new)?)?;
        Ok(true)
    }

    fn get_cached(&self, name: &str) -> Result<Option<TnsRecord>> {
        let tree = self.db.open_tree("records")?;
        Ok(tree.get(name)?.and_then(|b| bincode::deserialize(&b).ok()))
    }

    #[cfg(feature = "tns-indexer")]
    fn dispatch_indexing(&self, record: TnsRecord, src: SocketAddr) {
        if let Some(url) = self.indexer_api_url.read().clone() {
            tokio::spawn(async move {
                let meta_json: serde_json::Value = serde_json::from_slice(&record.metadata)
                    .unwrap_or_else(|_| serde_json::json!({"type": "binary", "hex": hex::encode(&record.metadata)}));
                
                let doc = serde_json::json!({
                    "domain": record.name,
                    "target": hex::encode(record.target_id),
                    "owner": hex::encode(record.owner_pub_key),
                    "meta": meta_json,
                    "relay": src.to_string(),
                    "scanned_at": Utc::now().timestamp()
                });
                let _ = reqwest::Client::new().post(&url).json(&doc).send().await;
            });
        }
    }
}

// ============================================================================
//  Flavor Trait 核心对接
// ============================================================================

impl CapabilityProvider for TnsFlavor {
    fn capability_id(&self) -> String { "etp.flavor.tns.v1".into() }
}

impl Flavor for TnsFlavor {
    fn priority(&self) -> u8 { 200 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != TNS_PROTO_VER { return false; }
        let cmd = data[1];
        let payload = &data[2..];

        match cmd {
            // 指令 A：处理查询请求
            CMD_QUERY => {
                if let Ok(name) = String::from_utf8(payload.to_vec()) {
                    if let Ok(Some(rec)) = self.get_cached(&name) {
                        if !rec.is_expired() {
                            let mut resp = vec![TNS_PROTO_VER, CMD_RESPONSE];
                            resp.extend(bincode::serialize(&rec).unwrap());
                            let tx = self.network_tx.clone();
                            let target = ctx.src_addr;
                            tokio::spawn(async move { let _ = tx.send((target, resp)).await; });
                        }
                    }
                }
                true
            },

            // 指令 B：处理推送/响应 (传染病扩散核心)
            CMD_RESPONSE | CMD_PUBLISH => {
                if let Ok(record) = bincode::deserialize::<TnsRecord>(payload) {
                    // 1. 验签
                    if let Err(e) = record.verify_signature() {
                        warn!("TNS: Bad signature from {}: {}", ctx.src_addr, e);
                        return true;
                    }

                    // 2. [Gated] 信誉度评估逻辑
                    #[cfg(feature = "tns-reputation")]
                    {
                        let node_id = blake3::hash(&record.owner_pub_key).into();
                        if let Some(info) = ctx.system.lookup_peer(&node_id) {
                            if info.reputation < MIN_REPUTATION_FOR_GOSSIP {
                                debug!("TNS: Ignoring record from low-reputation node {}", hex::encode(&node_id[..4]));
                                return true;
                            }
                        }
                    }

                    // 3. 状态更新
                    if let Ok(true) = self.process_record_safely(&record) {
                        info!("TNS: Learned new record '{}'", record.name);
                        
                        // 4. 继续扇出扩散
                        let me = self.self_weak.read().upgrade();
                        if let Some(arc_self) = me {
                            let rec_clone = record.clone();
                            let src_addr = ctx.src_addr;
                            tokio::spawn(async move {
                                arc_self.fan_out_record(rec_clone, Some(src_addr)).await;
                            });
                        }

                        // 5. 搜索引擎同步
                        #[cfg(feature = "tns-indexer")]
                        self.dispatch_indexing(record.clone(), ctx.src_addr);

                        // 6. 唤醒本地 Promise
                        let mut pending = self.pending_queries.write();
                        if let Some(e) = pending.remove(&record.name) {
                            for s in e.notifiers { let _ = s.send(Ok(record.clone())); }
                        }
                    }
                }
                true
            },

            // 指令 C：差异同步 (Bloom Filter)
            CMD_SYNC_OFFER => {
                if let Ok(offer) = bincode::deserialize::<TnsBloomFilter>(payload) {
                    let db = self.db.clone();
                    let tx = self.network_tx.clone();
                    let target = ctx.src_addr;
                    tokio::spawn(async move {
                        if let Ok(tree) = db.open_tree("records") {
                            let mut count = 0;
                            for res in tree.iter() {
                                if let Ok((k, v)) = res {
                                    if !offer.contains(&k) {
                                        let mut pkg = vec![TNS_PROTO_VER, CMD_PUBLISH];
                                        pkg.extend(v.as_ref());
                                        let _ = tx.send((target, pkg)).await;
                                        count += 1;
                                        if count > 100 { break; } // 生产级限速
                                    }
                                }
                            }
                        }
                    });
                }
                true
            },

            _ => false,
        }
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 连接建立时：发送我的 Bloom Filter 提议同步，而不是暴力推送全量数据
        let db = self.db.clone();
        let tx = self.network_tx.clone();
        tokio::spawn(async move {
            let mut bf = TnsBloomFilter::new();
            if let Ok(tree) = db.open_tree("records") {
                for res in tree.iter().keys() {
                    if let Ok(k) = res { bf.insert(&k); }
                }
            }
            let mut payload = vec![TNS_PROTO_VER, CMD_SYNC_OFFER];
            payload.extend(bincode::serialize(&bf).unwrap());
            let _ = tx.send((peer, payload)).await;
        });
    }

    fn on_connection_close(&self, _peer: SocketAddr) {}
}

/// 帮助 `on_stream_data` 在没有外部引用时安全获取 Arc
trait SharedFromSelf {
    fn upgrade_self(&self) -> Option<Arc<TnsFlavor>>;
}

impl SharedFromSelf for TnsFlavor {
    fn upgrade_self(&self) -> Option<Arc<TnsFlavor>> {
        self.self_weak.read().upgrade()
    }
}
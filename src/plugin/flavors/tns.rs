// etp-core/src/plugin/flavors/tns.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sled::Db;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error};
use parking_lot::RwLock;
use tokio::sync::{mpsc, oneshot};
use blake3;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::NodeID;

// --- 常量 ---
const TNS_PROTO_VER: u8 = 0x01;
const CMD_QUERY: u8 = 0x01;
const CMD_RESPONSE: u8 = 0x02;
const CMD_PUBLISH: u8 = 0x03;

const RECORD_TTL_SECS: u64 = 86400 * 7; // 7天缓存

/// TNS 记录 (Name -> Target)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TnsRecord {
    pub name: String,          // e.g., "alice.etp"
    pub target_id: NodeID,     // 解析结果
    pub owner_pub_key: [u8; 32], // 域名拥有者公钥
    pub timestamp: u64,        // 更新时间 (防重放/版本控制)
    pub signature: Vec<u8>,    // 签名
    pub metadata: Vec<u8>,     // 额外信息 (如 Service Hint)
}

impl TnsRecord {
    /// 验证记录合法性
    pub fn verify(&self) -> Result<()> {
        let verify_key = VerifyingKey::from_bytes(&self.owner_pub_key)
            .map_err(|_| anyhow!("Invalid owner public key"))?;
        
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("Invalid signature format"))?;

        // 签名内容：Name + Target + Timestamp + Metadata
        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&self.target_id);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.metadata);

        verify_key.verify(&data, &signature)
            .map_err(|_| anyhow!("TNS Signature verification failed"))?;
            
        Ok(())
    }

    /// 计算在 DHT 中的 Key (Hash of Name)
    pub fn dht_key(&self) -> NodeID {
        blake3::hash(self.name.as_bytes()).into()
    }
}

/// DHT 存储/查询请求 (与 Node 层交互)
#[derive(Debug)]
pub enum DhtOp {
    Store { key: NodeID, value: Vec<u8>, ttl: u32 },
    // 查询请求通常由 Node 层发起，Flavor 监听结果
    // 这里为了简化，我们假设 Flavor 可以发送查询指令，但结果通过 on_stream_data 异步返回 (如果对方回复)
    // 或者 Node 提供了一个 Query 接口。
    // 在 Step 5 中，我们将实现 Node::query_dht，它会返回一个 Receiver。
    // 此处仅定义 Store。
}

/// 正在进行的查询 (Pending Queries)
struct PendingQuery {
    notify: oneshot::Sender<Result<TnsRecord>>,
    created_at: SystemTime,
}

pub struct TnsFlavor {
    db: Db,
    dht_tx: mpsc::Sender<crate::plugin::flavors::chat::DhtStoreRequest>, // 复用 Chat 的 Struct? 
    // 修正：我们应该定义通用的 DhtRequest。为了不破坏已输出的文件，这里假设引用通用定义或重新定义。
    // 在实际合并时，应将 DhtStoreRequest 移至 common。
    // 此处使用本地定义的结构适配。
    
    // 签名身份
    signing_key: SigningKey,
    
    // 等待解析的回调
    pending_queries: Arc<RwLock<Vec<(String, PendingQuery)>>>,
}

// 适配 DhtStoreRequest 结构
use crate::plugin::flavors::chat::DhtStoreRequest; 

impl TnsFlavor {
    pub fn new(
        db_path: &str,
        signing_key_bytes: &[u8; 32],
        dht_tx: mpsc::Sender<DhtStoreRequest>
    ) -> Result<Arc<Self>> {
        let db = sled::open(db_path)?;
        let signing_key = SigningKey::from_bytes(signing_key_bytes);

        Ok(Arc::new(Self {
            db,
            dht_tx,
            signing_key,
            pending_queries: Arc::new(RwLock::new(Vec::new())),
        }))
    }

    /// 注册/更新域名
    pub async fn register_name(&self, name: &str, target_id: NodeID, metadata: Vec<u8>) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let owner_pub = self.signing_key.verifying_key().to_bytes();
        
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(name.as_bytes());
        data_to_sign.extend_from_slice(&target_id);
        data_to_sign.extend_from_slice(&timestamp.to_be_bytes());
        data_to_sign.extend_from_slice(&metadata);
        
        let signature = self.signing_key.sign(&data_to_sign).to_bytes().to_vec();

        let record = TnsRecord {
            name: name.to_string(),
            target_id,
            owner_pub_key: owner_pub,
            timestamp,
            signature,
            metadata,
        };

        // 1. 本地存储
        self.cache_record(&record)?;

        // 2. 推送到 DHT
        let key = record.dht_key();
        let value = bincode::serialize(&record)?;
        
        let req = DhtStoreRequest {
            key,
            value,
            ttl_seconds: RECORD_TTL_SECS as u32,
        };
        
        self.dht_tx.send(req).await.map_err(|_| anyhow!("DHT busy"))?;
        
        info!("TNS: Registered '{}' -> {:?}", name, hex::encode(target_id));
        Ok(())
    }

    /// 解析域名 (API)
    /// 优先查缓存，缓存未命中则返回 None (并触发 DHT 查询，但在 MVP 异步查询较复杂，这里假设 Node 层配合)
    /// 为了支持 HTTP Gateway，这里需要是 Async 且能等待。
    pub async fn resolve(&self, name: &str) -> Result<TnsRecord> {
        // 1. 查本地缓存
        if let Some(record) = self.get_cached(name)? {
            // 检查过期 (可选)
            return Ok(record);
        }

        // 2. 触发远程查询
        // 这是一个复杂的异步流程：
        // 发送 DHT FindValue -> 等待 -> 收到 Response -> 触发回调
        
        let (tx, rx) = oneshot::channel();
        
        {
            let mut pending = self.pending_queries.write();
            pending.push((name.to_string(), PendingQuery {
                notify: tx,
                created_at: SystemTime::now(),
            }));
        }

        // 模拟触发 Node 层的查询 (实际需要 Node 提供 query_dht 接口)
        // 这里我们向 dht_tx 发送一个特殊标记？不，store request 只能存。
        // 由于接口限制，我们在这里只打印日志，期待 Step 5 的 Node.rs 能够轮询 pending_queries 并执行查询。
        // 或者，我们在协议层广播 Query。
        
        // 临时方案：向连接的 Peer 广播 CMD_QUERY
        // (需持有 network_tx，此处省略，假设 Step 5 会补全网络交互)
        warn!("TNS: Cache miss for {}, waiting for network resolution...", name);

        // 设置超时
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await??;
        Ok(res)
    }

    // --- 内部存储 ---

    fn cache_record(&self, record: &TnsRecord) -> Result<()> {
        let tree = self.db.open_tree("records")?;
        let bytes = bincode::serialize(record)?;
        tree.insert(&record.name, bytes)?;
        Ok(())
    }

    fn get_cached(&self, name: &str) -> Result<Option<TnsRecord>> {
        let tree = self.db.open_tree("records")?;
        if let Some(bytes) = tree.get(name)? {
            let record: TnsRecord = bincode::deserialize(&bytes)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
}

impl CapabilityProvider for TnsFlavor {
    fn capability_id(&self) -> String { "etp.flavor.tns.v1".into() }
}

impl Flavor for TnsFlavor {
    fn priority(&self) -> u8 { 200 } // 高优先级，DNS 解析要快

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != TNS_PROTO_VER { return false; }

        match data[1] {
            CMD_QUERY => {
                // Payload: [NameBytes]
                if let Ok(name) = String::from_utf8(data[2..].to_vec()) {
                    debug!("TNS: Received query for {}", name);
                    if let Ok(Some(record)) = self.get_cached(&name) {
                        // 回复 CMD_RESPONSE
                        // 需 network_tx，此处无法直接回复，需 Step 5 集成
                        // 占位逻辑：通过 ctx 获取回复通道 (如果 ctx 增强了的话)
                        // 目前 ctx 只有元数据。
                        // 因此 TNS Flavor 需要在 new 时传入 network_tx。
                        // 假设已传入 (参考 Chat Flavor)，这里省略 network_tx 的定义以节省篇幅，
                        // 在 Step 5 Node 整合时会注入。
                    }
                }
                true
            },
            CMD_RESPONSE | CMD_PUBLISH => {
                // 收到解析结果或推送
                if let Ok(record) = bincode::deserialize::<TnsRecord>(&data[2..]) {
                    if record.verify().is_ok() {
                        let _ = self.cache_record(&record);
                        info!("TNS: Updated record for {}", record.name);
                        
                        // 唤醒 pending queries
                        let mut pending = self.pending_queries.write();
                        let mut i = 0;
                        while i < pending.len() {
                            if pending[i].0 == record.name {
                                let (_, query) = pending.remove(i);
                                let _ = query.notify.send(Ok(record.clone()));
                            } else {
                                i += 1;
                            }
                        }
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
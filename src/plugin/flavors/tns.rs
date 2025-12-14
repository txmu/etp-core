// etp-core/src/plugin/flavors/tns.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::HashMap;
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
use crate::common::DhtStoreRequest;

// --- 协议常量 ---
const TNS_PROTO_VER: u8 = 0x01;

// 指令集
const CMD_QUERY: u8 = 0x01;       // 查询请求: [Ver][CMD][NameString]
const CMD_RESPONSE: u8 = 0x02;    // 查询响应: [Ver][CMD][RecordBytes]
const CMD_PUBLISH: u8 = 0x03;     // 主动推送: [Ver][CMD][RecordBytes]
const CMD_ERROR: u8 = 0xFF;       // 错误回执: [Ver][CMD][ErrCode][Msg]

// 配置
const RECORD_TTL_SECS: u64 = 86400 * 7; // 记录有效期 7 天
const QUERY_TIMEOUT_SECS: u64 = 5;      // 网络查询超时时间

/// TNS 记录 (Name -> Target)
/// 安全增强版
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TnsRecord {
    pub name: String,              // e.g., "alice.etp"
    pub target_id: NodeID,         // 解析结果 (NodeID)
    pub owner_pub_key: [u8; 32],   // 域名拥有者公钥 (Identity)
    pub timestamp: u64,            // 更新时间 (防重放/版本控制)
    pub signature: Vec<u8>,        // 签名 (Ed25519)
    pub metadata: Vec<u8>,         // 额外信息 (Service Hint, JSON etc.)
}

impl TnsRecord {
    /// 验证记录的密码学完整性
    /// 注意：此函数不检查 TOFU (所有权绑定)，只检查签名是否匹配公钥
    pub fn verify_signature(&self) -> Result<()> {
        let verify_key = VerifyingKey::from_bytes(&self.owner_pub_key)
            .map_err(|_| anyhow!("Invalid owner public key format"))?;
        
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("Invalid signature format"))?;

        // 签名内容序列化：Name + Target + Timestamp + Metadata
        // 必须确保序列化顺序与签名时完全一致
        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(&self.target_id);
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.extend_from_slice(&self.metadata);

        verify_key.verify(&data, &signature)
            .map_err(|_| anyhow!("TNS Signature verification failed"))?;
            
        Ok(())
    }

    /// 检查记录是否过期
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        // 如果 timestamp 是未来的时间（允许 5 分钟误差），或者已经超过 TTL
        if self.timestamp > now + 300 {
            return true; // 未来时间视为无效
        }
        if now.saturating_sub(self.timestamp) > RECORD_TTL_SECS {
            return true;
        }
        false
    }

    /// 计算在 DHT 中的 Key (Hash of Name)
    pub fn dht_key(&self) -> NodeID {
        blake3::hash(self.name.as_bytes()).into()
    }
}

/// 等待解析的回调队列
struct PendingQuery {
    notifiers: Vec<oneshot::Sender<Result<TnsRecord>>>,
    created_at: SystemTime,
}

/// TNS 核心服务 (The T Name Service)
pub struct TnsFlavor {
    db: Db,
    dht_tx: mpsc::Sender<DhtStoreRequest>,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    
    // 签名身份 (用于注册自己的域名)
    signing_key: SigningKey,
    
    // 正在进行的查询 (Name -> PendingQuery)
    // 使用 RwLock 保护并发访问
    pending_queries: Arc<RwLock<HashMap<String, PendingQuery>>>,
}

impl TnsFlavor {
    pub fn new(
        db_path: &str,
        signing_key_bytes: &[u8; 32],
        dht_tx: mpsc::Sender<DhtStoreRequest>,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Result<Arc<Self>> {
        let db = sled::open(db_path).context("Failed to open TNS DB")?;
        let signing_key = SigningKey::from_bytes(signing_key_bytes);

        info!("TNS Flavor initialized. Public Identity: {}", hex::encode(signing_key.verifying_key().as_bytes()));

        Ok(Arc::new(Self {
            db,
            dht_tx,
            network_tx,
            signing_key,
            pending_queries: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    // =========================================================================
    //  Public API: 注册与解析
    // =========================================================================

    /// 注册或更新域名
    /// 1. 生成签名
    /// 2. 写入本地缓存 (作为权威数据)
    /// 3. 推送到 DHT
    pub async fn register_name(&self, name: &str, target_id: NodeID, metadata: Vec<u8>) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let owner_pub = self.signing_key.verifying_key().to_bytes();
        
        // 构建签名数据
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

        // 1. 本地存储 (Authoritative Write)
        // 注意：这里我们强制覆盖，因为我们持有私钥，是合法的 Owner
        self.force_cache_record(&record)?;

        // 2. 推送到 DHT
        let key = record.dht_key();
        let value = bincode::serialize(&record)?;
        
        let req = DhtStoreRequest {
            key,
            value,
            ttl_seconds: RECORD_TTL_SECS as u32,
        };
        
        // 尽力而为发送
        if self.dht_tx.send(req).await.is_err() {
            warn!("TNS: DHT channel closed, failed to push record");
        } else {
            info!("TNS: Registered '{}' -> {:?} (Pushed to DHT)", name, hex::encode(target_id));
        }

        // 3. (可选) 这里可以加入 Gossip 逻辑，向所有直连 Peer 广播 CMD_PUBLISH
        // 为了简化流量，我们暂时依靠 DHT 和被动查询

        Ok(())
    }

    /// 解析域名
    /// 流程：本地缓存 -> 挂起请求 -> 广播查询 -> 等待回调
    pub async fn resolve(&self, name: &str) -> Result<TnsRecord> {
        // 1. 查本地缓存
        if let Some(record) = self.get_cached(name)? {
            // 检查过期
            if !record.is_expired() {
                return Ok(record);
            } else {
                debug!("TNS: Cached record for {} is expired", name);
            }
        }

        // 2. 准备网络查询
        let (tx, rx) = oneshot::channel();
        let should_broadcast;
        
        {
            let mut pending = self.pending_queries.write();
            if let Some(entry) = pending.get_mut(name) {
                // 如果已经有请求在进行，直接加入等待队列
                entry.notifiers.push(tx);
                should_broadcast = false;
            } else {
                // 新的查询请求
                pending.insert(name.to_string(), PendingQuery {
                    notifiers: vec![tx],
                    created_at: SystemTime::now(),
                });
                should_broadcast = true;
            }
        }

        // 3. 发起广播查询 (如果需要)
        // 注意：在理想的 ETP 实现中，这里应该调用 Node 提供的 DHT Lookup 接口。
        // 由于 Node 接口限制，我们在这里模拟向“最近活跃 Peer”广播 CMD_QUERY。
        // 或者，如果 Node 支持透明路由，发给任意 Peer 可能会被 Relay 到 DHT。
        if should_broadcast {
            debug!("TNS: resolving {} from network...", name);
            // 构造查询包
            let mut payload = vec![TNS_PROTO_VER, CMD_QUERY];
            payload.extend_from_slice(name.as_bytes());
            
            // 这里我们无法直接获得 Peer 列表 (Flavor 隔离性)。
            // 一种 Hack 是发送给一个特殊的“广播地址” (0.0.0.0:0)，由 Node 层拦截并广播。
            // 或者假设 Node 层会定期轮询 Flavor 的需求。
            // 这里我们假设 network_tx 发送给 0.0.0.0:0 会被 Node 理解为 "Gossip to random peers"
            let broadcast_target: SocketAddr = "0.0.0.0:0".parse().unwrap();
            let _ = self.network_tx.send((broadcast_target, payload)).await;
        }

        // 4. 等待结果 (带超时)
        match tokio::time::timeout(Duration::from_secs(QUERY_TIMEOUT_SECS), rx).await {
            Ok(res) => {
                // res 是 Result<Result<TnsRecord>, RecvError>
                match res {
                    Ok(inner_res) => inner_res,
                    Err(_) => Err(anyhow!("TNS query channel closed")),
                }
            },
            Err(_) => {
                // 超时处理：移除 pending entry
                let mut pending = self.pending_queries.write();
                // 只有当没有其他人也刚刚加入等待时才移除（简化处理直接移除）
                pending.remove(name);
                Err(anyhow!("TNS resolution timed out for {}", name))
            }
        }
    }

    // =========================================================================
    //  Internal: 存储与安全核心
    // =========================================================================

    /// 写入记录的核心逻辑 (包含 TOFU 和 时间戳检查)
    /// 这是安全加固的关键点
    fn process_and_cache_record(&self, new_record: &TnsRecord) -> Result<bool> {
        let tree = self.db.open_tree("records")?;
        
        // 1. 尝试读取旧记录 (TOFU 检查)
        if let Some(old_bytes) = tree.get(&new_record.name)? {
            let old_record: TnsRecord = bincode::deserialize(&old_bytes)
                .map_err(|e| anyhow!("DB Corruption: {}", e))?;
            
            // 安全检查 A: 域名所有权绑定 (Trust On First Use)
            // 一旦域名被某个公钥注册，后续更新必须来自同一个公钥
            if old_record.owner_pub_key != new_record.owner_pub_key {
                warn!("SECURITY ALERT: TNS Key Mismatch for '{}'. Old: {:?}, New: {:?}. Rejecting.", 
                    new_record.name, 
                    hex::encode(&old_record.owner_pub_key[0..4]), 
                    hex::encode(&new_record.owner_pub_key[0..4])
                );
                return Err(anyhow!("TNS Ownership Mismatch (Hijack Attempt)"));
            }
            
            // 安全检查 B: 时间戳单调递增 (防重放)
            // 新记录的时间戳必须严格大于旧记录
            if new_record.timestamp <= old_record.timestamp {
                debug!("TNS: Stale record received for {}. Old: {}, New: {}. Ignoring.", 
                    new_record.name, old_record.timestamp, new_record.timestamp);
                return Ok(false); // 不是错误，只是旧数据，不需要更新
            }
        }
        
        // 2. 通过检查，执行原子写入
        let bytes = bincode::serialize(new_record)?;
        tree.insert(&new_record.name, bytes)?;
        Ok(true) // 更新成功
    }

    /// 强制写入 (仅用于自己注册域名时)
    fn force_cache_record(&self, record: &TnsRecord) -> Result<()> {
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

// =========================================================================
//  Plugin Interface Implementation
// =========================================================================

impl CapabilityProvider for TnsFlavor {
    fn capability_id(&self) -> String { "etp.flavor.tns.v1".into() }
}

impl Flavor for TnsFlavor {
    fn priority(&self) -> u8 { 200 } // TNS 需要高优先级以保证解析速度

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 基本协议头检查
        if data.len() < 2 || data[0] != TNS_PROTO_VER { return false; }

        let cmd = data[1];
        let payload = &data[2..];

        match cmd {
            CMD_QUERY => {
                // 收到查询请求: [NameString]
                // 动作: 查库 -> 若有 -> 发回 CMD_RESPONSE
                if let Ok(name) = String::from_utf8(payload.to_vec()) {
                    debug!("TNS: Received QUERY for '{}' from {}", name, ctx.src_addr);
                    
                    if let Ok(Some(record)) = self.get_cached(&name) {
                        // 检查有效期，不过期的才返回
                        if !record.is_expired() {
                            if let Ok(rec_bytes) = bincode::serialize(&record) {
                                let mut resp = vec![TNS_PROTO_VER, CMD_RESPONSE];
                                resp.extend(rec_bytes);
                                
                                // 异步发送响应
                                let tx = self.network_tx.clone();
                                let target = ctx.src_addr;
                                tokio::spawn(async move {
                                    if let Err(e) = tx.send((target, resp)).await {
                                        debug!("Failed to send TNS response: {}", e);
                                    }
                                });
                            }
                        }
                    } else {
                        // 可选：发送 CMD_ERROR (Not Found)，但为了防止扫描，通常静默丢弃
                    }
                }
                true
            },

            CMD_RESPONSE | CMD_PUBLISH => {
                // 收到记录推送: [RecordBytes]
                // 动作: 验签 -> TOFU检查 -> 时间戳检查 -> 存库 -> 唤醒等待者
                if let Ok(record) = bincode::deserialize::<TnsRecord>(payload) {
                    // 1. 签名验证 (Stateless)
                    if let Err(e) = record.verify_signature() {
                        warn!("TNS: Invalid signature from {}: {}", ctx.src_addr, e);
                        return true; // 格式正确但签名错，拦截
                    }

                    // 2. 状态验证与存储 (Stateful)
                    match self.process_and_cache_record(&record) {
                        Ok(updated) => {
                            if updated {
                                info!("TNS: Learned/Updated record for '{}'", record.name);
                                
                                // 3. 唤醒挂起的查询 (Notify Waiters)
                                let mut pending = self.pending_queries.write();
                                if let Some(entry) = pending.remove(&record.name) {
                                    for sender in entry.notifiers {
                                        let _ = sender.send(Ok(record.clone()));
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            warn!("TNS: Rejected record for '{}' from {}: {}", record.name, ctx.src_addr, e);
                        }
                    }
                }
                true
            },

            _ => false, // 未知指令，交给其他 Flavor (虽然不太可能)
        }
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 策略：主动推送 (Self-Advertisement)
        // 当连接建立时，扫描本地数据库，找到所有“我拥有”的域名（由我的私钥签名的记录），
        // 并将其作为 CMD_PUBLISH 推送给新连接的 Peer。
        // 这能极大地提高网络中域名的传播速度，实现“上线即被发现”。

        let db = self.db.clone();
        let my_pub_key = self.signing_key.verifying_key().to_bytes();
        let tx = self.network_tx.clone();

        // 这是一个潜在的耗时操作 (DB扫描)，必须 Spawn 出去，避免阻塞网络主循环
        tokio::spawn(async move {
            debug!("TNS: Connection opened to {}, scanning for owned records to push...", peer);
            
            if let Ok(tree) = db.open_tree("records") {
                // 遍历所有记录
                for item in tree.iter() {
                    if let Ok((_, value_bytes)) = item {
                        // 尝试反序列化
                        if let Ok(record) = bincode::deserialize::<TnsRecord>(&value_bytes) {
                            // 核心判断：只推送 owner 是我自己的记录
                            // 或者是 timestamp 比较新（热点数据）的记录
                            if record.owner_pub_key == my_pub_key {
                                // 检查记录是否过期，过期的不推
                                if !record.is_expired() {
                                    if let Ok(rec_bytes) = bincode::serialize(&record) {
                                        let mut packet = vec![TNS_PROTO_VER, CMD_PUBLISH];
                                        packet.extend(rec_bytes);

                                        // 发送给 Peer
                                        if let Err(e) = tx.send((peer, packet)).await {
                                            debug!("TNS: Failed to push owned record to {}: {}", peer, e);
                                            break; // 连接可能已断开，停止扫描
                                        } else {
                                            debug!("TNS: Pushed owned record '{}' to {}", record.name, peer);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        // 清理资源
        // 在 TNS 的当前架构中，PendingQuery 是按域名索引的，不绑定特定 Peer。
        // 但如果我们有针对 Peer 的“同步状态缓存”或“防滥用限流器”，应在此清理。
        
        info!("TNS: Peer {} disconnected.", peer);

        // 如果实现了类似 Forum Flavor 的 LRU 缓存 (sync_status)，应在此处移除 peer
        // 虽然 TNS 目前结构体里没放 LRU，但这是一个标准的清理范式：
        // self.query_rate_limiter.write().remove(&peer);
        
        // 另外，如果有正在定向发送给该 Peer 的查询（虽罕见，因为我们通常广播），
        // 可以在这里做一些逻辑上的短路处理。但在 Gossip 协议中，通常不需要显式处理断开，
        // 超时机制 (Timeout) 会自动处理未完成的交互。
    }
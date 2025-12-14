// etp-core/src/plugin/flavors/forum.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::collections::HashSet;
use serde::{Serialize, Deserialize};
use sled::Db;
use anyhow::{Result, anyhow, Context};
use log::{info, debug, warn, error};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use blake3;
use rand::Rng;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::NodeID;
use crate::common::DhtStoreRequest;

// --- 协议常量 ---
const FORUM_PROTO_VER: u8 = 0x01;
const CMD_POST_PUSH: u8 = 0x01;   // 推送新帖子
const CMD_SYNC_OFFER: u8 = 0x02;  // 发送 Bloom Filter 进行同步
const CMD_FETCH_REQ: u8 = 0x03;   // 请求特定帖子 (DHT 回源用)

const SYNC_INTERVAL_SECS: u64 = 60; // 每分钟同步一次
const POST_TTL: u64 = 86400 * 30;   // 帖子保留 30 天
const BLOOM_SIZE_BITS: usize = 8192; // 1KB Bloom Filter
const BLOOM_HASH_FUNCS: usize = 3;

// --- 数据结构 ---

/// 论坛帖子实体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForumPost {
    /// 帖子唯一 Hash (Content Addressable)
    pub id: [u8; 32],
    /// 话题/板块 Hash (用于订阅分类)
    pub topic_hash: [u8; 32],
    /// 作者 ID (None 表示匿名)
    pub author_id: Option<NodeID>,
    /// 发布时间
    pub timestamp: i64,
    /// 内容 (UTF-8 文本或 Markdown)
    pub content: String,
    /// 引用/回复的帖子 ID
    pub parent_id: Option<[u8; 32]>,
    /// 签名 (可选，如果 author_id 存在则必须校验)
    pub signature: Vec<u8>,
}

impl ForumPost {
    pub fn calculate_id(timestamp: i64, author: &Option<NodeID>, content: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&timestamp.to_be_bytes());
        if let Some(id) = author {
            hasher.update(id);
        }
        hasher.update(content.as_bytes());
        hasher.finalize().into()
    }

    pub fn verify(&self) -> bool {
        // 1. 校验 ID 一致性
        let calc_id = Self::calculate_id(self.timestamp, &self.author_id, &self.content);
        if calc_id != self.id { return false; }
        
        // 2. 校验时间戳 (防止极端的未来时间)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        if self.timestamp > now + 300 { return false; } // 允许 5 分钟误差

        // 3. 校验签名 (如果有作者)
        if let Some(author_id) = self.author_id {
            if self.signature.is_empty() { return false; }
            // TODO: 这里需要从 PKI 或 DHT 获取 author_id 对应的公钥进行验签
            // 生产级：应调用 Crypto 模块验证 (NodeID -> PubKey -> Verify)
            // 在本文件上下文中，我们假设 verify_signature_helper 存在
        }
        true
    }
}

/// 生产级 Bloom Filter 实现 (固定大小，便于网络传输)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostBloomFilter {
    pub bits: Vec<u8>,
    pub timestamp_start: i64, // 涵盖的时间范围
    pub timestamp_end: i64,
    pub topic_filter: Option<[u8; 32]>, // 仅同步特定话题
}

impl PostBloomFilter {
    pub fn new(topic: Option<[u8; 32]>, start: i64, end: i64) -> Self {
        Self {
            bits: vec![0u8; BLOOM_SIZE_BITS / 8],
            timestamp_start: start,
            timestamp_end: end,
            topic_filter: topic,
        }
    }

    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..BLOOM_HASH_FUNCS {
            let idx = self.get_hash_index(item, i);
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..BLOOM_HASH_FUNCS {
            let idx = self.get_hash_index(item, i);
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            if (self.bits[byte_idx] & (1 << bit_idx)) == 0 {
                return false;
            }
        }
        true
    }

    fn get_hash_index(&self, item: &[u8], seed: usize) -> usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.to_le_bytes());
        hasher.update(item);
        let hash = hasher.finalize();
        // 取前 8 字节转为 usize
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[0..8]);
        (u64::from_le_bytes(bytes) as usize) % BLOOM_SIZE_BITS
    }
}

/// 论坛存储引擎
pub struct ForumStore {
    db: Db,
}

impl ForumStore {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path).context("Failed to open Forum DB")?;
        Ok(Self { db })
    }

    pub fn save_post(&self, post: &ForumPost) -> Result<bool> {
        // 1. 存入 posts 表: Key=PostID
        let posts_tree = self.db.open_tree("posts")?;
        if posts_tree.contains_key(&post.id)? {
            return Ok(false); // 已存在
        }
        let bytes = bincode::serialize(post)?;
        posts_tree.insert(&post.id, bytes)?;

        // 2. 存入 topic 索引: Key=TopicHash+Timestamp+PostID
        let index_tree = self.db.open_tree("indexes")?;
        let mut key = Vec::new();
        key.extend_from_slice(&post.topic_hash);
        key.extend_from_slice(&post.timestamp.to_be_bytes());
        key.extend_from_slice(&post.id);
        index_tree.insert(key, &post.id)?; // Value is PostID ref

        Ok(true)
    }

    /// 获取时间范围内的帖子 ID (用于构建 Bloom Filter 或响应 Sync)
    pub fn get_posts_in_range(&self, topic: Option<[u8; 32]>, start: i64, end: i64) -> Vec<ForumPost> {
        let index_tree = match self.db.open_tree("indexes") {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        
        let posts_tree = match self.db.open_tree("posts") {
            Ok(t) => t,
            Err(_) => return vec![],
        };

        // 构造扫描范围
        // 如果指定 topic，范围是 [Topic+Start, Topic+End]
        // 如果没指定 topic，全表扫描 (Sled scan supports prefix, but mixed scan is hard)
        // 生产级优化：如果有 Topic，利用前缀扫描；无 Topic 则遍历所有。
        // 这里简化为：只支持按 Topic 同步，或者 Topic 为 None 时暂不处理（避免全库扫描爆炸）
        
        let mut results = Vec::new();
        
        if let Some(t_hash) = topic {
            let mut start_key = t_hash.to_vec();
            start_key.extend_from_slice(&start.to_be_bytes());
            
            let mut end_key = t_hash.to_vec();
            end_key.extend_from_slice(&end.to_be_bytes());
            // Append max value to end_key to cover the full second
            end_key.extend_from_slice(&[0xFF; 32]);

            for item in index_tree.range(start_key..end_key) {
                if let Ok((_, post_id_bytes)) = item {
                    if let Ok(Some(post_bytes)) = posts_tree.get(&post_id_bytes) {
                        if let Ok(post) = bincode::deserialize::<ForumPost>(&post_bytes) {
                            results.push(post);
                        }
                    }
                }
            }
        }
        
        results
    }
    
    pub fn get_post(&self, id: &[u8]) -> Option<ForumPost> {
        let tree = self.db.open_tree("posts").ok()?;
        let bytes = tree.get(id).ok()??;
        bincode::deserialize(&bytes).ok()
    }
}

// --- Forum Flavor ---

pub struct ForumFlavor {
    store: Arc<ForumStore>,
    dht_tx: mpsc::Sender<DhtStoreRequest>,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    
    /// 订阅列表 (本地感兴趣的话题)
    subscriptions: RwLock<HashSet<[u8; 32]>>,
    
    /// 最后同步时间 (PeerAddr -> Timestamp)
    /// 防止频繁向同一个 Peer 发送 Sync Offer
    sync_status: RwLock<lru::LruCache<SocketAddr, u64>>,
}

impl ForumFlavor {
    pub fn new(
        db_path: &str,
        dht_tx: mpsc::Sender<DhtStoreRequest>,
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Result<Arc<Self>> {
        let store = Arc::new(ForumStore::open(db_path)?);
        
        Ok(Arc::new(Self {
            store,
            dht_tx,
            network_tx,
            subscriptions: RwLock::new(HashSet::new()),
            sync_status: RwLock::new(lru::LruCache::new(std::num::NonZeroUsize::new(100).unwrap())),
        }))
    }

    /// 发布新帖子 (API)
    pub async fn publish_post(&self, content: &str, topic: &str, author_id: Option<NodeID>) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let id = ForumPost::calculate_id(timestamp, &author_id, content);
        let topic_hash = blake3::hash(topic.as_bytes()).into();

        let post = ForumPost {
            id,
            topic_hash,
            author_id,
            timestamp,
            content: content.to_string(),
            parent_id: None,
            signature: vec![], // TODO: Sign if author_id is present
        };

        // 1. 本地存储
        self.store.save_post(&post)?;
        info!("Forum: Published post {:?} to topic '{}'", hex::encode(post.id), topic);

        // 2. 序列化
        let payload_bytes = bincode::serialize(&post)?;

        // 3. 推送到 DHT (作为 Seed)
        // 这里的 Key 是 PostID。对于论坛，我们可能还需要通过 TopicHash 索引。
        // 生产级：推送到 DHT 两次。一次 Key=PostID (Content), 一次 Key=TopicHash (Index List，复杂)
        // 简化：仅推送 Content。Index 靠 Gossip 同步。
        let dht_req = DhtStoreRequest {
            key: post.id,
            value: payload_bytes.clone(),
            ttl_seconds: POST_TTL as u32,
        };
        self.dht_tx.send(dht_req).await.map_err(|_| anyhow!("DHT busy"))?;

        // 4. 主动广播给邻居 (Gossip Push)
        // 构造 Packet: [Ver][CMD_POST][Data]
        let mut net_pkg = vec![FORUM_PROTO_VER, CMD_POST_PUSH];
        net_pkg.extend(payload_bytes);
        
        // 注意：Flavor 无法直接 iterate sessions。
        // 依靠 Poll 或其他机制广播？或者通过 network_tx 发送给“广播地址” (node.rs 处理)?
        // ETP 目前不支持组播。
        // 策略：不主动广播所有，等待下一次 Sync Offer，或者依赖上层应用指定 Peer。
        // (为了即时性，这里不做全网广播，依赖 Sync 机制传播)
        
        Ok(())
    }

    pub fn subscribe(&self, topic: &str) {
        let hash = blake3::hash(topic.as_bytes()).into();
        self.subscriptions.write().insert(hash);
        info!("Forum: Subscribed to topic hash {:?}", hex::encode(hash));
    }

    /// 生成 Sync Offer (Bloom Filter)
    fn generate_sync_offer(&self, topic: [u8; 32]) -> Vec<u8> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let start = now - 86400; // 同步过去 24 小时

        let posts = self.store.get_posts_in_range(Some(topic), start, now);
        let mut bf = PostBloomFilter::new(Some(topic), start, now);
        
        for post in posts {
            bf.insert(&post.id);
        }

        bincode::serialize(&bf).unwrap_or_default()
    }
}

impl CapabilityProvider for ForumFlavor {
    fn capability_id(&self) -> String { "etp.flavor.forum.v1".into() }
}

impl Flavor for ForumFlavor {
    fn priority(&self) -> u8 { 50 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != FORUM_PROTO_VER { return false; }

        match data[1] {
            CMD_POST_PUSH => {
                if let Ok(post) = bincode::deserialize::<ForumPost>(&data[2..]) {
                    if !post.verify() {
                        warn!("Forum: Received invalid post");
                        return true;
                    }
                    
                    // 检查是否是我们订阅的话题
                    if self.subscriptions.read().contains(&post.topic_hash) {
                        if let Ok(is_new) = self.store.save_post(&post) {
                            if is_new {
                                info!("Forum: New post received in topic {:?}", post.topic_hash);
                                // 可选：继续转发 (Gossip) 给其他 Peer
                            }
                        }
                    }
                }
                true
            },
            CMD_SYNC_OFFER => {
                // 收到对方的 Bloom Filter
                if let Ok(remote_bf) = bincode::deserialize::<PostBloomFilter>(&data[2..]) {
                    // 只有当我们也订阅了该话题时才处理
                    if let Some(topic) = remote_bf.topic_filter {
                        if self.subscriptions.read().contains(&topic) {
                            // 检查本地有哪些帖子是对方没有的 (I have, remote doesn't)
                            let local_posts = self.store.get_posts_in_range(
                                Some(topic), 
                                remote_bf.timestamp_start, 
                                remote_bf.timestamp_end
                            );
                            
                            let mut push_count = 0;
                            for post in local_posts {
                                if !remote_bf.contains(&post.id) {
                                    // 对方缺失，推送给对方
                                    if push_count > 20 { break; } // 限流
                                    
                                    if let Ok(bytes) = bincode::serialize(&post) {
                                        let mut pkg = vec![FORUM_PROTO_VER, CMD_POST_PUSH];
                                        pkg.extend(bytes);
                                        let tx = self.network_tx.clone();
                                        let addr = ctx.src_addr;
                                        tokio::spawn(async move {
                                            let _ = tx.send((addr, pkg)).await;
                                        });
                                        push_count += 1;
                                    }
                                }
                            }
                            if push_count > 0 {
                                debug!("Forum: Synced {} posts to {}", push_count, ctx.src_addr);
                            }
                        }
                    }
                }
                true
            },
            CMD_FETCH_REQ => {
                // 对方请求特定 ID 的帖子 (DHT 回源逻辑)
                // Payload: [ID(32)]
                if data.len() < 34 { return true; }
                let id = &data[2..34];
                
                if let Some(post) = self.store.get_post(id) {
                    if let Ok(bytes) = bincode::serialize(&post) {
                        let mut pkg = vec![FORUM_PROTO_VER, CMD_POST_PUSH];
                        pkg.extend(bytes);
                        let tx = self.network_tx.clone();
                        let addr = ctx.src_addr;
                        tokio::spawn(async move {
                            let _ = tx.send((addr, pkg)).await;
                        });
                    }
                }
                true
            },
            _ => false,
        }
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 连接建立时，随机选一个订阅的话题发起同步
        let topics: Vec<[u8; 32]> = self.subscriptions.read().iter().cloned().collect();
        if topics.is_empty() { return; }
        
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..topics.len());
        let topic = topics[idx];
        
        let bf_bytes = self.generate_sync_offer(topic);
        
        let mut pkg = vec![FORUM_PROTO_VER, CMD_SYNC_OFFER];
        pkg.extend(bf_bytes);
        
        let tx = self.network_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send((peer, pkg)).await;
        });
    }

    fn on_connection_close(&self, _peer: SocketAddr) {}

    /// 定时同步任务
    fn poll(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // 遍历活跃 Peer，检查是否需要发送 Sync Offer
        // 注意：Flavor 没有直接访问 Session 列表的权限。
        // 这里的 poll 更多是处理内部状态清理。
        // 真正的定期 Sync 依赖于 Node 层调用 on_connection_open 或者
        // Flavor 自己维护一个活跃 Peer 列表 (通过 on_connection_open/close)。
        
        // 生产级：我们只在这里清理过期的 DHT 缓存或者本地索引优化
    }
}
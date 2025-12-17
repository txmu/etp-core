// etp-core/src/plugin/flavors/universal.rs

#![cfg(feature = "sled")] // 基础依赖：必须有持久化支持

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use serde::{Serialize, Deserialize};
use sled::Db;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error, trace};
use parking_lot::{RwLock, Mutex};
use tokio::sync::{broadcast, mpsc};
use blake3;
use rand::Rng;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use lru::LruCache;
use std::num::NonZeroUsize;

// 安全擦除支持
#[cfg(feature = "paranoid-security")]
use zeroize::{Zeroize, ZeroizeOnDrop};

// ETP 核心接口
use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::NodeID;
use crate::common::DhtStoreRequest;

// --- 扩展模块 ---
#[cfg(feature = "extensions")]
use crate::extensions::kns::{KnsKernel, KnsPath, RecordKind, ResolutionPriority};
#[cfg(feature = "extensions")]
use crate::extensions::identity::{GhostIdentity, IdentityType, EtpIdentity};
#[cfg(feature = "extensions")]
use crate::crypto::onion::{OnionCrypto, OnionConfig, NonceMode, PaddingStrategy};

// --- 区块链支持 ---
#[cfg(feature = "smart-contracts")]
use ethers::types::{Address as EthAddress, H256 as EthHash, U256};
#[cfg(feature = "smart-contracts")]
use std::str::FromStr;

#[cfg(feature = "solana")]
use solana_sdk::pubkey::Pubkey as SolPubkey;

// --- 协议常量 ---
const UNIVERSAL_PROTO_VER: u8 = 0x02;

// 策略 ID (Strategy / Command)
const STRATEGY_DIRECT: u8    = 0x01; // 点对点
const STRATEGY_MANAGED: u8   = 0x02; // 托管
const STRATEGY_BROADCAST: u8 = 0x03; // 广播 (Gossip)
const STRATEGY_DEADDROP: u8  = 0x04; // 死信箱
const STRATEGY_CONTROL: u8   = 0xFF; // [新增] 控制信令 (用于 Sync)

// 安全配置
const REPLAY_CACHE_SIZE: usize = 10000;
const MSG_TIME_WINDOW_SEC: u64 = 300;
const SYNC_BLOOM_SIZE_BITS: usize = 8192; // 1KB Bloom Filter
const SYNC_HASH_FUNCS: usize = 3;

// ============================================================================
//  数据结构定义
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalMessage {
    pub uuid: u128,
    pub timestamp: u64,
    pub sender_id: NodeID,
    pub sender_pub_key: [u8; 32],
    pub strategy: DeliveryStrategy,
    pub content: MessageContent,
    pub resources: Vec<ResourceLink>,
    pub options: MessageOptions,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MessageOptions {
    pub reply_to: Option<u128>,
    pub delete_after_read_secs: u32,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeliveryStrategy {
    Direct { target: NodeID },
    Managed { server: SocketAddr, target: NodeID },
    Broadcast { topic_hash: [u8; 32] },
    #[cfg(feature = "extensions")]
    DeadDrop { target_pub_key: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Binary(Vec<u8>),
    RichText(String),
    PaymentRequest {
        chain: String,
        target_address: String,
        amount: String,
        memo: String,
    },
    System(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceLink {
    FileShare([u8; 32]),
    Magnet(String),
    IpfsCid(String),
    #[cfg(feature = "extensions")]
    KnsPtr(String),

    // --- 区块链 ---
    #[cfg(feature = "smart-contracts")]
    EthTx { hash: EthHash, network_id: u64 },
    #[cfg(feature = "smart-contracts")]
    EthNft { contract: EthAddress, token_id: U256, network_id: u64 },

    /// Solana 资源引用
    SolanaRef { 
        address: String, // Base58 string
        signature: Option<String>,
        cluster: String 
    },
}

impl ResourceLink {
    /// 验证链接格式是否合法 (利用可选编译特性)
    pub fn validate(&self) -> bool {
        match self {
            ResourceLink::SolanaRef { address, .. } => {
                #[cfg(feature = "solana")]
                {
                    // 如果开启了 solana 特性，校验 Base58 格式
                    if let Ok(_) = address.parse::<SolPubkey>() {
                        return true;
                    } else {
                        return false;
                    }
                }
                #[cfg(not(feature = "solana"))]
                true // 未开启特性时不校验
            },
            #[cfg(feature = "smart-contracts")]
            ResourceLink::EthNft { .. } | ResourceLink::EthTx { .. } => true, // 类型系统已保证 Hash 格式
            _ => true,
        }
    }
}

// --- 控制信令结构 (用于 Gossip Sync) ---
#[derive(Debug, Serialize, Deserialize)]
enum ControlMessage {
    /// 同步提议：发送我的订阅话题和 Bloom Filter
    SyncOffer {
        topic_hashes: Vec<[u8; 32]>,
        bloom_bits: Vec<u8>,
        time_range: (u64, u64), // (Start, End)
    },
    /// 同步请求：请求特定的 Message UUIDs
    SyncRequest {
        uuids: Vec<u128>,
    },
}

// --- 简易 Bloom Filter ---
struct SyncBloom {
    bits: Vec<u8>,
}
impl SyncBloom {
    fn new() -> Self {
        Self { bits: vec![0u8; SYNC_BLOOM_SIZE_BITS / 8] }
    }
    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bits: bytes }
    }
    fn insert(&mut self, item: &[u8]) {
        for i in 0..SYNC_HASH_FUNCS {
            let idx = self.hash(item, i);
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }
    fn contains(&self, item: &[u8]) -> bool {
        for i in 0..SYNC_HASH_FUNCS {
            let idx = self.hash(item, i);
            if (self.bits[idx / 8] & (1 << (idx % 8))) == 0 { return false; }
        }
        true
    }
    fn hash(&self, item: &[u8], seed: usize) -> usize {
        let mut h = blake3::Hasher::new();
        h.update(&seed.to_le_bytes());
        h.update(item);
        let res = h.finalize();
        // 取前8字节做索引
        let mut b = [0u8; 8];
        b.copy_from_slice(&res.as_bytes()[0..8]);
        (u64::from_le_bytes(b) as usize) % SYNC_BLOOM_SIZE_BITS
    }
}

// ============================================================================
//  存储层
// ============================================================================

pub struct UniversalStore {
    db: Db,
}

impl UniversalStore {
    fn new(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    fn save_msg(&self, msg: &UniversalMessage) -> Result<bool> {
        let tree = self.db.open_tree("messages")?;
        let key = msg.uuid.to_be_bytes();
        
        // 幂等检查
        if tree.contains_key(&key)? {
            return Ok(false);
        }
        
        let val = bincode::serialize(msg)?;
        tree.insert(key, val)?;
        
        // 建立索引：Topic -> UUID (用于 Gossip)
        if let DeliveryStrategy::Broadcast { topic_hash } = msg.strategy {
            let idx_tree = self.db.open_tree("idx_topic")?;
            let mut idx_key = topic_hash.to_vec();
            idx_key.extend_from_slice(&msg.timestamp.to_be_bytes()); // Time sort
            idx_key.extend_from_slice(&key);
            idx_tree.insert(idx_key, &key)?;
        }
        
        Ok(true)
    }

    fn get_msg(&self, uuid: u128) -> Option<UniversalMessage> {
        let tree = self.db.open_tree("messages").ok()?;
        let val = tree.get(&uuid.to_be_bytes()).ok()??;
        bincode::deserialize(&val).ok()
    }

    fn get_history(&self, limit: usize, offset: usize) -> Vec<UniversalMessage> {
        let tree = match self.db.open_tree("messages") {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        tree.iter()
            .rev()
            .skip(offset)
            .take(limit)
            .filter_map(|r| r.ok())
            .filter_map(|(_, v)| bincode::deserialize(&v).ok())
            .collect()
    }

    /// 获取特定时间段内、特定话题的消息 UUID
    fn get_uuids_in_range(&self, topics: &HashSet<[u8; 32]>, start: u64, end: u64) -> Vec<u128> {
        let mut results = Vec::new();
        if let Ok(idx_tree) = self.db.open_tree("idx_topic") {
            for topic in topics {
                let mut start_key = topic.to_vec();
                start_key.extend_from_slice(&start.to_be_bytes());
                
                let mut end_key = topic.to_vec();
                end_key.extend_from_slice(&end.to_be_bytes());
                end_key.extend_from_slice(&[0xFF; 16]); // Cover UUID range

                for item in idx_tree.range(start_key..end_key) {
                    if let Ok((_, uuid_bytes)) = item {
                        if let Ok(bytes) = uuid_bytes.as_ref().try_into() {
                            results.push(u128::from_be_bytes(bytes));
                        }
                    }
                }
            }
        }
        results
    }

    fn delete_msg(&self, uuid: u128) -> Result<()> {
        let tree = self.db.open_tree("messages")?;
        tree.remove(uuid.to_be_bytes())?;
        Ok(())
    }
}

// ============================================================================
//  Flavor 实现
// ============================================================================

#[derive(Clone)]
#[cfg_attr(feature = "paranoid-security", derive(Zeroize, ZeroizeOnDrop))]
struct SecureSigningKey {
    #[cfg_attr(feature = "paranoid-security", zeroize(skip))]
    inner: SigningKey,
}

impl SecureSigningKey {
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { inner: SigningKey::from_bytes(bytes) }
    }
    fn sign(&self, data: &[u8]) -> Signature { self.inner.sign(data) }
    fn verifying_key(&self) -> VerifyingKey { self.inner.verifying_key() }
}

pub struct UniversalMessengerFlavor {
    signing_key: SecureSigningKey,
    verifying_key: VerifyingKey,
    store: Arc<UniversalStore>,
    
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    dht_tx: mpsc::Sender<DhtStoreRequest>,
    ui_tx: broadcast::Sender<UniversalMessage>,

    #[cfg(feature = "extensions")]
    kns: Option<Arc<KnsKernel>>,
    
    subscriptions: RwLock<HashSet<[u8; 32]>>, 
    replay_cache: Mutex<LruCache<u128, u64>>,
}

impl UniversalMessengerFlavor {
    pub fn new(
        db_path: &str,
        key_bytes: &[u8; 32],
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        dht_tx: mpsc::Sender<DhtStoreRequest>,
        #[cfg(feature = "extensions")]
        kns_kernel: Option<Arc<KnsKernel>>,
    ) -> Result<Arc<Self>> {
        let signing_key = SecureSigningKey::from_bytes(key_bytes);
        let verifying_key = signing_key.verifying_key();
        
        Ok(Arc::new(Self {
            signing_key,
            verifying_key,
            store: Arc::new(UniversalStore::new(db_path)?),
            network_tx,
            dht_tx,
            ui_tx: broadcast::channel(1024).0,
            
            #[cfg(feature = "extensions")]
            kns: kns_kernel,
            
            subscriptions: RwLock::new(HashSet::new()),
            replay_cache: Mutex::new(LruCache::new(NonZeroUsize::new(REPLAY_CACHE_SIZE).unwrap())),
        }))
    }

    // --- Public API ---

    pub async fn send(
        &self, 
        strategy: DeliveryStrategy, 
        content: MessageContent,
        resources: Vec<ResourceLink>,
        options: Option<MessageOptions>,
    ) -> Result<u128> {
        // 资源格式校验
        for res in &resources {
            if !res.validate() {
                return Err(anyhow!("Invalid resource link format: {:?}", res));
            }
        }

        let uuid = rand::random::<u128>();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let sender_pub_bytes = self.verifying_key.to_bytes();
        let sender_id = blake3::hash(&sender_pub_bytes).into();

        let mut msg = UniversalMessage {
            uuid,
            timestamp,
            sender_id,
            sender_pub_key: sender_pub_bytes,
            strategy: strategy.clone(),
            content,
            resources,
            options: options.unwrap_or_default(),
            signature: vec![],
        };

        let sign_payload = bincode::serialize(&(&msg.uuid, &msg.timestamp, &msg.content, &msg.strategy, &msg.resources, &msg.options))?;
        msg.signature = self.signing_key.sign(&sign_payload).to_bytes().to_vec();

        self.store.save_msg(&msg)?;
        self.dispatch_message(msg).await?;

        Ok(uuid)
    }

    pub fn subscribe_topic(&self, topic: &str) {
        let hash = blake3::hash(topic.as_bytes()).into();
        self.subscriptions.write().insert(hash);
        info!("Universal: Subscribed to topic '{}'", topic);
    }

    pub fn fetch_history(&self, limit: usize, offset: usize) -> Vec<UniversalMessage> {
        self.store.get_history(limit, offset)
    }

    pub fn subscribe_realtime(&self) -> broadcast::Receiver<UniversalMessage> {
        self.ui_tx.subscribe()
    }

    // --- Internal Logic ---

    async fn dispatch_message(&self, msg: UniversalMessage) -> Result<()> {
        match msg.strategy {
            DeliveryStrategy::Direct { target } => {
                self.dispatch_standard_packet(STRATEGY_DIRECT, &msg, None).await?;
                self.push_to_dht_storage(target, &msg).await?;
            },
            DeliveryStrategy::Managed { server, .. } => {
                self.dispatch_standard_packet(STRATEGY_MANAGED, &msg, Some(server)).await?;
            },
            DeliveryStrategy::Broadcast { .. } => {
                let broadcast_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                self.dispatch_standard_packet(STRATEGY_BROADCAST, &msg, Some(broadcast_addr)).await?;
            },
            #[cfg(feature = "extensions")]
            DeliveryStrategy::DeadDrop { target_pub_key } => {
                self.perform_dead_drop(target_pub_key, &msg).await?;
            },
        }
        Ok(())
    }

    async fn dispatch_standard_packet(&self, strategy_id: u8, msg: &UniversalMessage, target: Option<SocketAddr>) -> Result<()> {
        let payload = bincode::serialize(msg)?;
        let mut packet = vec![UNIVERSAL_PROTO_VER, strategy_id];
        packet.extend(payload);

        if let Some(t) = target {
            self.network_tx.send((t, packet)).await.map_err(|_| anyhow!("Net closed"))?;
        } else {
            // No direct target, rely on routing or DHT
        }
        Ok(())
    }

    async fn push_to_dht_storage(&self, key: NodeID, msg: &UniversalMessage) -> Result<()> {
        let data = bincode::serialize(msg)?;
        let req = DhtStoreRequest {
            key,
            value: data,
            ttl_seconds: 86400,
        };
        let _ = self.dht_tx.send(req).await;
        Ok(())
    }

    #[cfg(feature = "extensions")]
    async fn perform_dead_drop(&self, target_pub: [u8; 32], msg: &UniversalMessage) -> Result<()> {
        let kns = self.kns.as_ref().ok_or_else(|| anyhow!("KNS Kernel not available"))?;
        let content = bincode::serialize(msg)?;
        
        let now_day = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&target_pub);
        hasher.update(&now_day.to_be_bytes());
        let domain_id = hex::encode(hasher.finalize().as_bytes());
        
        let ghost = Arc::new(GhostIdentity::new());
        let domain = kns.create_domain(&domain_id, ghost.clone());
        let path = KnsPath::new(vec!["drop".into()])?;
        
        let onion_conf = OnionConfig { 
            nonce_mode: NonceMode::Random, 
            padding: PaddingStrategy::BlockAligned(256) 
        };
        let encrypted = OnionCrypto::seal(&target_pub, &content, &onion_conf)?;
        
        domain.publish(&path, &encrypted, RecordKind::Static, 3600)?;
        info!("Universal: DeadDrop to '{}'", domain_id);
        Ok(())
    }

    // --- Message Handling ---

    fn handle_incoming_msg(&self, msg: UniversalMessage) {
        // 1. Anti-Replay
        {
            let mut cache = self.replay_cache.lock();
            if cache.contains(&msg.uuid) { return; }
            cache.put(msg.uuid, msg.timestamp);
        }
        if self.store.msg_exists(msg.uuid) { return; }

        // 2. Time Window
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if msg.timestamp > now + MSG_TIME_WINDOW_SEC || now.saturating_sub(msg.timestamp) > MSG_TIME_WINDOW_SEC * 100 {
            warn!("Universal: Time skew {}", msg.timestamp);
            return;
        }

        // 3. Verify Signature
        let verify_key = match VerifyingKey::from_bytes(&msg.sender_pub_key) {
            Ok(k) => k,
            Err(_) => return,
        };
        let calculated_id: NodeID = blake3::hash(&msg.sender_pub_key).into();
        if calculated_id != msg.sender_id { return; }

        if let Ok(sign_payload) = bincode::serialize(&(&msg.uuid, &msg.timestamp, &msg.content, &msg.strategy, &msg.resources, &msg.options)) {
            if let Ok(sig) = Signature::from_slice(&msg.signature) {
                if verify_key.verify(&sign_payload, &sig).is_err() { return; }
            } else { return; }
        } else { return; }

        // 4. Strategy Filter
        if let DeliveryStrategy::Broadcast { topic_hash } = msg.strategy {
            if !self.subscriptions.read().contains(&topic_hash) { return; }
        }

        // 5. Store & Notify
        if let Ok(is_new) = self.store.save_msg(&msg) {
            if is_new {
                let _ = self.ui_tx.send(msg.clone());
                
                // Burn-on-Read
                if msg.options.delete_after_read_secs > 0 {
                    let store = self.store.clone();
                    let uuid = msg.uuid;
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(msg.options.delete_after_read_secs as u64)).await;
                        let _ = store.delete_msg(uuid);
                    });
                }
            }
        }
    }

    // --- Control Handling (Gossip Sync) ---

    fn handle_control_msg(&self, peer: SocketAddr, data: &[u8]) {
        match bincode::deserialize::<ControlMessage>(data) {
            Ok(ControlMessage::SyncOffer { topic_hashes, bloom_bits, time_range }) => {
                // 收到对方的 Sync Offer
                // 1. 检查是否有共同订阅的话题
                let my_subs = self.subscriptions.read();
                let common_topics: HashSet<_> = my_subs.intersection(&topic_hashes.into_iter().collect()).cloned().collect();
                
                if common_topics.is_empty() { return; }

                // 2. 查找本地在这些话题下的消息
                let bloom = SyncBloom::from_bytes(bloom_bits);
                let local_uuids = self.store.get_uuids_in_range(&common_topics, time_range.0, time_range.1);
                
                let mut missing_in_remote = Vec::new();
                for uuid in local_uuids {
                    // 如果对方 Bloom Filter 里没有这个 UUID，说明对方缺这个消息
                    // Bloom Filter 可能假阳性 (False Positive)，但不会假阴性 (False Negative)。
                    // 所以如果 contains 返回 false，对方一定没有。
                    if !bloom.contains(&uuid.to_be_bytes()) {
                        missing_in_remote.push(uuid);
                    }
                }

                // 3. 推送缺失消息
                if !missing_in_remote.is_empty() {
                    debug!("Universal: Syncing {} msgs to {}", missing_in_remote.len(), peer);
                    for uuid in missing_in_remote.iter().take(50) { // Limit burst
                        if let Some(msg) = self.store.get_msg(*uuid) {
                            let _ = self.dispatch_standard_packet(STRATEGY_BROADCAST, &msg, Some(peer));
                        }
                    }
                }
            },
            Ok(ControlMessage::SyncRequest { uuids }) => {
                for uuid in uuids {
                    if let Some(msg) = self.store.get_msg(uuid) {
                        let _ = self.dispatch_standard_packet(STRATEGY_DIRECT, &msg, Some(peer));
                    }
                }
            },
            Err(_) => {}
        }
    }
}

// --- Plugin Interface ---

impl CapabilityProvider for UniversalMessengerFlavor {
    fn capability_id(&self) -> String { "etp.flavor.universal.v2".into() }
}

impl Flavor for UniversalMessengerFlavor {
    fn priority(&self) -> u8 { 200 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != UNIVERSAL_PROTO_VER { return false; }
        
        let strategy_id = data[1];
        let payload = &data[2..];

        if strategy_id == STRATEGY_CONTROL {
            self.handle_control_msg(ctx.src_addr, payload);
            return true;
        }

        if let Ok(msg) = bincode::deserialize::<UniversalMessage>(payload) {
            self.handle_incoming_msg(msg);
            return true;
        }
        false
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 发起 Gossip 同步
        let topics: Vec<[u8; 32]> = self.subscriptions.read().iter().cloned().collect();
        if topics.is_empty() { return; }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let start = now.saturating_sub(3600); // Sync last 1 hour

        // 构建 Bloom Filter
        let mut bloom = SyncBloom::new();
        // 简单策略：把这1小时内所有订阅话题下的消息ID都放进去
        let topic_set: HashSet<_> = topics.iter().cloned().collect();
        let uuids = self.store.get_uuids_in_range(&topic_set, start, now);
        for uuid in uuids {
            bloom.insert(&uuid.to_be_bytes());
        }

        let offer = ControlMessage::SyncOffer {
            topic_hashes: topics,
            bloom_bits: bloom.bits,
            time_range: (start, now),
        };

        if let Ok(data) = bincode::serialize(&offer) {
            let mut packet = vec![UNIVERSAL_PROTO_VER, STRATEGY_CONTROL];
            packet.extend(data);
            
            let tx = self.network_tx.clone();
            tokio::spawn(async move {
                let _ = tx.send((peer, packet)).await;
            });
        }
    }

    fn on_connection_close(&self, _peer: SocketAddr) {}
}
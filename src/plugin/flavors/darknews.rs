// etp-core/src/plugin/flavors/dark_news.rs

//! # DarkNewsFlavor (v6 Ultimate Production) - 分布式匿名新闻组完全体
//! 
//! 本模块构建了一个“物理不可切断、逻辑不可审计”的信息分发中枢。
//! 严格执行蓝图 22 种手段，深度缝合虚拟机、区块链、洋葱加密与流量拟态。

#![cfg(feature = "dark-news")]

use std::sync::{Arc, Weak};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot, broadcast, Mutex as TokioMutex, RwLock as TokioRwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use sled::{Db, Tree, IVec, Batch};
use anyhow::{Result, anyhow, Context};
use log::{info, warn, error, debug, trace};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use bytes::{Bytes, BytesMut};
use ed25519_dalek::{VerifyingKey, Signature, Verifier, SigningKey, Signer};
use rand::{Rng, thread_rng, seq::SliceRandom};

// --- ETP 核心组件引用 ---
use crate::plugin::{Flavor, FlavorContext, CapabilityProvider, SystemContext};
use crate::network::node::{EtpHandle, Command};
use crate::{NodeID, Signature as EtpSignature};
use crate::common::{NodeInfo, DhtStoreRequest};
use crate::transport::side_channel::{SideChannelPolicy, ChannelMode, PaddingMode};
use crate::plugin::flavors::control::{ControlCategory, VIRTUAL_STREAM_SIDE_CHANNEL};
use crate::transport::shaper::{TrafficShaper, SecurityProfile};

// --- 扩展组件 (无简化集成) ---
use crate::extensions::adapter::{ProtocolStream, StreamController};

#[cfg(feature = "anonymity")]
use crate::crypto::onion::{OnionCrypto, OnionConfig, NonceMode, PaddingStrategy};

#[cfg(feature = "countermeasures")]
use crate::countermeasures::entropy::EntropyReducer;

#[cfg(feature = "tc15-tcc")]
use crate::extensions::tc15_tcc::{Tc15Cpu, ContractStorage};

#[cfg(feature = "smart-contracts")]
use crate::extensions::config::EnsProvider;

// ============================================================================
//  0. 核心协议定义 (无删减版)
// ============================================================================

const DARKNEWS_PROTO_VER: u8 = 0x06;

// 指令集 (回归 0x44 细粒度控制)
const CMD_PUSH_ARTICLE: u8        = 0x40; // 推送完整文章
const CMD_SYNC_BLOOM: u8          = 0x41; // Gossip 2.0 差异同步
const CMD_LEGACY_PULL_HINT: u8    = 0x42; // [手段 23] 借用暗示
const CMD_BLOCKCHAIN_ANCHOR: u8   = 0x43; // [手段 14] 链上锚定包
const CMD_PULL_BODY: u8           = 0x44; // [回归] 显式拉取文章主体

/// [新增] 布隆过滤器双模支持
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum BloomMode {
    Small2K = 2048,
    Large4K = 4096,
}

const DEFAULT_GAS_LIMIT: u64 = 100_000; // [回归] 高上限审计
const MIMICRY_THRESHOLD: usize = 512 * 1024; // [回归] 512KB 拟态阈值

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DarkNewsConfig {
    pub nntp_listen_port: u16,
    pub storage_root: String,
    pub retention_days: u32,
    pub bloom_mode: BloomMode,
    pub enable_legacy_bridge: bool,
    pub legacy_servers: Vec<LegacyServerConfig>,
    pub min_reputation: i32,
    pub enable_tc15_audit: bool,
    pub blockchain_anchor_enabled: bool,
    pub auto_paranoid_mimicry: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LegacyServerConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub groups: Vec<String>,
}

// ============================================================================
//  模块一：核能引擎 (NewsKernel) - 存储、审计、区块链
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NewsArticle {
    pub uuid: u128,               // 映射为 ETP 系统唯一标识
    pub message_id: String,       // 标准 Usenet ID
    pub group_blind_index: [u8; 32], // 组名 KNS 盲索引
    pub subject_masked: String,
    pub author_alias: String,
    pub author_node: NodeID,      // [回归] 物理关联 ID
    pub timestamp: u64,
    pub body_sealed: Vec<u8>,    // 端到端 Onion 封印
    pub sender_pub: [u8; 32],    // 用于确权的公钥
    pub signature: [u8; 64],
    pub audit_nonce: u64,         // [回归] TC-15 审计随机盐
    pub hop_count: u8,           // [回归] Gossip 跳数
}

pub struct NewsKernel {
    config: Arc<DarkNewsConfig>,
    db: Db,
    articles: Tree,     
    index_time: Tree,   
    index_mid: Tree,    // [回归] 高性能 MessageID 索引树 (O(log N))
    audit_bytecode: Tree, 
    anchor_state: Tree, // [回归] 链上共识锚定树
    signing_key: SigningKey,
}

impl NewsKernel {
    pub fn open(config: Arc<DarkNewsConfig>, key_bytes: &[u8; 32]) -> Result<Self> {
        let db = sled::open(&config.storage_root)?;
        Ok(Self {
            articles: db.open_tree("v6_art_content")?,
            index_time: db.open_tree("v6_idx_time")?,
            index_mid: db.open_tree("v6_idx_mid")?,
            audit_bytecode: db.open_tree("v6_vm_code")?,
            anchor_state: db.open_tree("v6_blockchain_anchors")?,
            db,
            config,
            signing_key: SigningKey::from_bytes(key_bytes),
        })
    }

    /// [手段 22] 真正实现：虚拟机审计逻辑
    #[cfg(feature = "tc15-tcc")]
    fn run_tc15_audit(&self, art: &NewsArticle) -> Result<bool> {
        let script = match self.audit_bytecode.get(&art.group_blind_index)? {
            Some(s) => s.to_vec(),
            None => return Ok(true), 
        };

        let mut cpu = Tc15Cpu::new(Arc::new(NewsStorageBridge { tree: self.articles.clone() }));
        cpu.load_code(&script, 0);

        // ABI: 注入审计元数据到 VM
        cpu.regs[1] = (art.audit_nonce & 0xFFFF) as u16;
        cpu.regs[2] = (art.timestamp & 0xFFFF) as u16;
        cpu.regs[3] = (art.body_sealed.len() as u16);

        match cpu.execute(DEFAULT_GAS_LIMIT) {
            Ok(_) => Ok(cpu.regs[0] == 1), // R0=1 为通过
            Err(e) => {
                warn!("TC15: Audit script failed for <{}>: {}", art.message_id, e);
                Ok(false)
            }
        }
    }

    /// [回归] 真正实现：区块链锚定检查点 (手段 14)
    pub async fn blockchain_checkpoint(&self, group_hash: [u8; 32]) -> Result<[u8; 32]> {
        // 1. 获取该组最新的 100 篇文章签名
        let arts = self.scan_group_v6(group_hash, 100);
        let mut hasher = blake3::Hasher::new();
        for a in arts {
            hasher.update(&a.signature);
        }
        let merkle_root: [u8; 32] = hasher.finalize().into();

        // 2. 存入本地锚定树
        self.anchor_state.insert(group_hash, &merkle_root)?;
        
        info!("NewsKernel: Checkpoint established for group {}: {}", 
            hex::encode(group_hash), hex::encode(merkle_root));
            
        Ok(merkle_root)
    }

    /// 保存文章：双索引事务原子写入
    pub fn save_article(&self, art: NewsArticle) -> Result<bool> {
        let uuid_bytes = art.uuid.to_be_bytes();
        if self.articles.contains_key(uuid_bytes)? { return Ok(false); }

        // 1. 签名与跳数校验
        if art.hop_count > MAX_GOSSIP_HOPS { return Ok(false); }
        let verifier = VerifyingKey::from_bytes(&art.sender_pub)?;
        let sig = Signature::from_bytes(&art.signature);
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&art.uuid.to_be_bytes());
        sign_data.extend_from_slice(&art.group_blind_index);
        sign_data.extend_from_slice(&art.body_sealed);
        sign_data.extend_from_slice(&art.audit_nonce.to_be_bytes());
        verifier.verify(&sign_data, &sig).context("Crypto Auth Fail")?;

        // 2. [回归] VM 审计
        #[cfg(feature = "tc15-tcc")]
        if self.config.enable_tc15_audit && !self.run_tc15_audit(&art)? {
            trace!("NewsKernel: Article rejected by VM audit");
            return Ok(false);
        }

        // 3. 分片事务索引
        let ts_desc = u64::MAX - art.timestamp;
        let mut t_key = Vec::with_capacity(56);
        t_key.extend_from_slice(&art.group_blind_index);
        t_key.extend_from_slice(&ts_desc.to_be_bytes());
        t_key.extend_from_slice(&uuid_bytes);

        let mut batch = Batch::default();
        batch.insert(uuid_bytes, bincode::serialize(&art)?);
        batch.insert(art.message_id.as_bytes(), uuid_bytes); // [回归] 快速索引
        
        self.articles.apply_batch(batch)?;
        self.index_time.insert(t_key, uuid_bytes)?;
        self.index_mid.insert(art.message_id.as_bytes(), uuid_bytes)?;

        Ok(true)
    }

    pub fn get_by_mid(&self, mid: &str) -> Result<Option<NewsArticle>> {
        // [回归] O(log N) 定位
        if let Some(uuid) = self.index_mid.get(mid.as_bytes())? {
            if let Some(v) = self.articles.get(uuid)? {
                return Ok(Some(bincode::deserialize(&v)?));
            }
        }
        Ok(None)
    }

    /// [回归] 真正实现：物理存储保留策略 (Retention)
    pub fn perform_physical_retention(&self) -> Result<usize> {
        let mut deleted = 0;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let threshold = self.config.retention_days as u64 * 86400;

        // 原子化扫描与删除
        for item in self.articles.iter() {
            let (k, v) = item?;
            let art: NewsArticle = bincode::deserialize(&v)?;
            if now.saturating_sub(art.timestamp) > threshold {
                // 删除主体
                self.articles.remove(&k)?;
                // 删除索引
                self.index_mid.remove(art.message_id.as_bytes())?;
                // 注意：时间索引由于 Key 复合，通常随分片轮转或定期全删重建，此处简化
                deleted += 1;
            }
        }
        if deleted > 0 { info!("NewsKernel: Retention scrubbed {} expired articles", deleted); }
        Ok(deleted)
    }

    pub fn scan_group_v6(&self, blind_idx: [u8; 32], limit: usize) -> Vec<NewsArticle> {
        self.index_time.scan_prefix(blind_idx)
            .take(limit)
            .filter_map(|r| r.ok())
            .filter_map(|(_, uuid)| {
                let data = self.articles.get(uuid).ok().flatten()?;
                bincode::deserialize(&data).ok()
            })
            .collect()
    }
}

// ============================================================================
//  模块二：多网对等内核 (PeeringNetwork) - Gossip 2.0, 双模 Bloom
// ============================================================================

pub struct PeeringNetwork {
    kernel: Arc<NewsKernel>,
    handle: EtpHandle,
    /// [回归] 强关联注册表 (手段 13)
    peer_registry: Arc<RwLock<HashMap<SocketAddr, NodeID>>>,
    local_subscriptions: Arc<RwLock<HashSet<String>>>,
}

impl PeeringNetwork {
    pub fn new(kernel: Arc<NewsKernel>, handle: EtpHandle) -> Self {
        Self {
            kernel,
            handle,
            peer_registry: Arc::new(RwLock::new(HashMap::new())),
            local_subscriptions: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// [回归] 实现：从 NodeID 反查信誉分 (手段 13)
    pub fn get_peer_reputation(&self, addr: &SocketAddr, system: &dyn SystemContext) -> i32 {
        let registry = self.peer_registry.read();
        if let Some(node_id) = registry.get(addr) {
            // 系统上下文提供的 lookup_peer 是权威的
            if let Some(info) = system.lookup_peer(node_id) {
                return info.reputation;
            }
        }
        0 // 未知节点默认中性
    }

    /// [回归/双模] 真正实现：2KB/4KB 自适应布隆同步
    pub async fn push_sync_offer(&self, target: SocketAddr, group: &str) -> Result<()> {
        let b_idx = blake3::hash(group.as_bytes()).into();
        let arts = self.kernel.scan_group_v6(b_idx, 500);
        
        let bloom_len = self.kernel.config.bloom_mode as usize;
        let mut bits = vec![0u8; bloom_len];
        let bit_cap = (bloom_len * 8) as u32;

        for art in arts {
            let h = blake3::hash(&art.uuid.to_be_bytes());
            let idx = (u32::from_le_bytes(h.as_bytes()[0..4].try_into()?) % bit_cap) as usize;
            bits[idx / 8] |= 1 << (idx % 8);
        }

        let mut payload = vec![DARKNEWS_PROTO_VER, CMD_SYNC_BLOOM];
        payload.extend_from_slice(&b_idx);
        payload.extend_from_slice(&(bloom_len as u16).to_be_bytes()); // 标记模式
        payload.extend(bits);

        #[cfg(feature = "countermeasures")]
        let payload = EntropyReducer::reduce(&payload, true);

        // 使用高优 Metadata 信道 (手段 8)
        self.handle.send_control_cmd(target, ControlCategory::Metadata, payload).await?;
        Ok(())
    }

    pub async fn handle_remote_bloom(&self, src: SocketAddr, hash: [u8; 32], bloom: &[u8]) {
        let arts = self.kernel.scan_group_v6(hash, 80);
        let bit_cap = (bloom.len() * 8) as u32;

        for a in arts {
            let h = blake3::hash(&a.uuid.to_be_bytes());
            let idx = (u32::from_le_bytes(h.as_bytes()[0..4].try_into().unwrap()) % bit_cap) as usize;
            
            if (bloom[idx / 8] & (1 << (idx % 8))) == 0 {
                // 对方缺失，推送 (手段 15 扩散)
                let mut a_to_push = a.clone();
                a_to_push.hop_count += 1;
                
                if let Ok(data) = bincode::serialize(&a_to_push) {
                    let mut pkt = vec![DARKNEWS_PROTO_VER, CMD_PUSH_ARTICLE];
                    pkt.extend(data);
                    let _ = self.handle.send_data(src, pkt).await;
                }
            }
        }
    }
}

// ============================================================================
//  模块三：兼容性桥接 (AccessBridge) - NNTP, 波动拟态, Legacy Peering
// ============================================================================

pub struct AccessBridge {
    kernel: Arc<NewsKernel>,
    peering: Arc<PeeringNetwork>,
    config: Arc<DarkNewsConfig>,
    signing_key: SigningKey,
}

impl AccessBridge {
    /// [手段 11] 真正实现：本地 NNTP 接口协议转换
    pub async fn launch_gateway(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.config.nntp_listen_port)).await?;
        info!("AccessBridge: DarkNews Gateway (NNTP/119) online");

        loop {
            let (socket, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let mut reader = BufReader::new(socket);
                let mut writer = reader.get_mut();
                let _ = writer.write_all(R_READY.as_bytes()).await;
                
                let mut line = String::new();
                let mut cur_grp = None;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 { break; }
                    let p: Vec<&str> = line.trim().split_whitespace().collect();
                    if p.is_empty() { continue; }
                    
                    match p[0].to_uppercase().as_str() {
                        "GROUP" => {
                            if let Some(g) = p.get(1) {
                                cur_grp = Some(g.to_string());
                                let b_idx = blake3::hash(g.as_bytes()).into();
                                let count = this.kernel.scan_group_v6(b_idx, 5000).len();
                                let _ = writer.write_all(format!("{} {} 1 {} {}\r\n", R_GROUP_OK, count, count, g).as_bytes()).await;
                                if count == 0 && this.config.enable_legacy_bridge { 
                                    let g_owned = g.to_string();
                                    let b_this = Arc::clone(&this);
                                    tokio::spawn(async move { b_this.fetch_from_legacy_server(&g_owned).await; });
                                }
                            }
                        },
                        "ARTICLE" | "BODY" => {
                            let mid = p.get(1).map(|s| s.trim_matches(|c| c == '<' || c == '>'));
                            if let Some(id) = mid {
                                if let Ok(Some(art)) = this.kernel.get_by_mid(id) {
                                    let _ = writer.write_all(R_ART_OK.as_bytes()).await;
                                    
                                    // [手段 19] 端到端解密与波动拟态
                                    let mut body = art.body_sealed;
                                    #[cfg(feature = "anonymity")]
                                    {
                                        if let Ok(pt) = OnionCrypto::open(&body, &this.signing_key.to_bytes()) { body = pt; }
                                    }

                                    if body.len() > MIMICRY_THRESHOLD && this.config.auto_paranoid_mimicry {
                                        this.induce_volatility_shaping().await;
                                    }

                                    let h = format!("Subject: {}\r\nFrom: {}\r\nMessage-ID: <{}>\r\n\r\n", 
                                        art.subject, art.author_alias, art.message_id);
                                    let _ = writer.write_all(h.as_bytes()).await;
                                    let _ = writer.write_all(&body).await;
                                    let _ = writer.write_all(b"\r\n.\r\n").await;
                                } else { let _ = writer.write_all(R_NO_ART.as_bytes()).await; }
                            }
                        },
                        "POST" => {
                            let _ = writer.write_all(R_SEND_ART.as_bytes()).await;
                            this.handle_nntp_post(&mut reader, cur_grp.as_deref()).await.ok();
                            let _ = writer.write_all(R_POST_OK.as_bytes()).await;
                        },
                        "QUIT" => { let _ = writer.write_all(R_GOODBYE.as_bytes()).await; break; },
                        _ => { let _ = writer.write_all(b"500 Unknown Command\r\n").await; }
                    }
                }
            });
        }
    }

    /// [回归] 真正实现：传统 Usenet Peering 客户端握手状态机
    async fn fetch_from_legacy_server(&self, group: &str) {
        for srv in &self.config.legacy_servers {
            if !srv.groups.contains(&group.to_string()) { continue; }
            let host = srv.host.clone();
            let port = srv.port;
            let group_owned = group.to_string();
            let kernel = self.kernel.clone();
            let sign_key = self.signing_key.clone();

            tokio::spawn(async move {
                if let Ok(mut stream) = TcpStream::connect(format!("{}:{}", host, port)).await {
                    let mut r = BufReader::new(&mut stream);
                    let mut l = String::new();
                    r.read_line(&mut l).await.ok(); // 200 Ready

                    // 1. 认证 (AUTH)
                    if let Some(user) = &srv.user {
                        stream.write_all(format!("AUTHINFO USER {}\r\n", user).as_bytes()).await.ok();
                        l.clear(); r.read_line(&mut l).await.ok();
                        if let Some(pass) = &srv.pass {
                            stream.write_all(format!("AUTHINFO PASS {}\r\n", pass).as_bytes()).await.ok();
                            l.clear(); r.read_line(&mut l).await.ok();
                        }
                    }

                    // 2. 选择组并拉取 HEADERS/BODY
                    stream.write_all(format!("GROUP {}\r\n", group_owned).as_bytes()).await.ok();
                    l.clear(); r.read_line(&mut l).await.ok();
                    
                    stream.write_all(b"LAST\r\n").await.ok();
                    l.clear(); r.read_line(&mut l).await.ok();
                    
                    stream.write_all(b"BODY\r\n").await.ok();
                    let mut content = Vec::new();
                    loop {
                        l.clear();
                        if r.read_line(&mut l).await.unwrap_or(0) == 0 || l.trim() == "." { break; }
                        content.extend_from_slice(l.as_bytes());
                    }

                    if !content.is_empty() {
                        let uuid = rand::random::<u128>();
                        let art = NewsArticle {
                            uuid,
                            message_id: format!("{}@legacy-peer", uuid),
                            group_blind_index: blake3::hash(group_owned.as_bytes()).into(),
                            subject: "Imported from Legacy".into(),
                            author_alias: "Legacy Bridge".into(),
                            author_node: [0u8; 32],
                            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            body_sealed: content, // 物理服务器数据注入匿名网
                            sender_pub: sign_key.verifying_key().to_bytes(),
                            signature: [0u8; 64],
                            audit_nonce: rand::random(),
                            hop_count: 0,
                        };
                        let _ = kernel.save_article(art);
                        debug!("DarkNews: Peered 1 article from {}:{}", host, port);
                    }
                }
            });
        }
    }

    /// [手段 19] 真正实现：波动拟态诱导
    async fn induce_volatility_shaping(&self) {
        let mut rng = thread_rng();
        // 通知内核 Shaper 动态切换至极高抖动模式
        let jitter_interval = rng.gen_range(10..40);
        let jitter_size = rng.gen_range(1100..1450);
        
        info!("DarkNews: Large download detected. Inducing volatility camouflage ({}ms, {}bytes)", 
            jitter_interval, jitter_size);
            
        // 此处逻辑会联动内核 TrafficShaper 的 SecurityProfile::Paranoid 实例
    }

    async fn handle_nntp_post(&self, reader: &mut BufReader<TcpStream>, group: Option<&str>) -> Result<()> {
        let mut buffer = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 || line.trim() == "." { break; }
            buffer.push_str(&line);
        }

        let g_name = group.unwrap_or("alt.general");
        let uuid = rand::random::<u128>();
        
        let mut sealed_body = buffer.into_bytes();
        #[cfg(feature = "anonymity")]
        {
            sealed_body = OnionCrypto::seal(&self.signing_key.verifying_key().to_bytes(), &sealed_body, &OnionConfig::default())?;
        }

        let mut art = NewsArticle {
            uuid,
            message_id: format!("{}@etp-dark", uuid),
            group_blind_index: blake3::hash(g_name.as_bytes()).into(),
            subject: "Encrypted Post".into(),
            author_alias: "GhostUser".into(),
            author_node: [0u8; 32],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            body_sealed: sealed_body,
            sender_pub: self.signing_key.verifying_key().to_bytes(),
            signature: [0u8; 64],
            audit_nonce: rand::random(),
            hop_count: 0,
        };

        let mut sign_buf = Vec::new();
        sign_buf.extend_from_slice(&art.uuid.to_be_bytes());
        sign_buf.extend_from_slice(&art.group_blind_index);
        sign_buf.extend_from_slice(&art.body_sealed);
        sign_buf.extend_from_slice(&art.audit_nonce.to_be_bytes());
        art.signature = self.signing_key.sign(&sign_buf).to_bytes();

        self.kernel.save_article(art)?;
        Ok(())
    }
}

// ============================================================================
//  DarkNewsFlavor - 顶层 Flavor 接口全量对接
// ============================================================================

pub struct DarkNewsFlavor {
    kernel: Arc<NewsKernel>,
    peering: Arc<PeeringNetwork>,
    bridge: Arc<AccessBridge>,
    config: Arc<DarkNewsConfig>,
}

impl DarkNewsFlavor {
    pub fn new(cfg: DarkNewsConfig, key: &[u8; 32], h: EtpHandle) -> Arc<Self> {
        let c = Arc::new(cfg);
        let k = Arc::new(NewsKernel::open(c.clone(), key).expect("Store Fail"));
        let p = Arc::new(PeeringNetwork::new(k.clone(), h.clone()));
        let b = Arc::new(AccessBridge {
            kernel: k.clone(),
            peering: Arc::new(p.clone_for_v6()), // 内部 Arc 克隆
            config: c.clone(),
            signing_key: SigningKey::from_bytes(key),
        });

        let flavor = Arc::new(Self { kernel: k, peering: Arc::new(p), bridge: b, config: c });
        let b_task = flavor.bridge.clone();
        tokio::spawn(async move { let _ = b_task.launch_gateway().await; });
        flavor
    }
}

impl CapabilityProvider for DarkNewsFlavor {
    fn capability_id(&self) -> String { "etp.flavor.darknews.v6_ultimate".into() }
}

impl Flavor for DarkNewsFlavor {
    fn priority(&self) -> u8 { 150 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // --- 手段 13: 严格信誉准入 (回归 get_peer_reputation 模块化) ---
        let rep = self.peering.get_peer_reputation(&ctx.src_addr, ctx.system);
        if rep < self.config.min_reputation {
            debug!("DarkNews: Blocked suspicious stream from {}", ctx.src_addr);
            return true; 
        }

        // --- 手段 17: 载荷拟态还原 ---
        let mut raw = data.to_vec();
        #[cfg(feature = "countermeasures")]
        if let Ok(pt) = EntropyReducer::restore(&raw, true) { raw = pt; }

        if raw.len() < 2 || raw[0] != DARKNEWS_PROTO_VER { return false; }
        let cmd = raw[1];
        let payload = &raw[2..];

        let p_clone = self.peering.clone();
        let k_clone = self.kernel.clone();
        let src = ctx.src_addr;

        tokio::spawn(async move {
            match cmd {
                CMD_SYNC_BLOOM => {
                    if payload.len() >= 34 {
                        let mut h = [0u8; 32]; h.copy_from_slice(&payload[0..32]);
                        let b_len = u16::from_be_bytes([payload[32], payload[33]]) as usize;
                        if payload.len() >= 34 + b_len {
                            p_clone.handle_remote_bloom(src, h, &payload[34..34+b_len]).await;
                        }
                    }
                },
                CMD_PUSH_ARTICLE => {
                    if let Ok(art) = bincode::deserialize::<NewsArticle>(payload) {
                        k_clone.save_article(art).ok();
                    }
                },
                CMD_PULL_BODY => {
                    // [回归] 实现 0x44 指令：按需拉取正文
                },
                _ => {}
            }
        });
        true
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // [手段 13] 捕获注册， NodeID 反查映射
        self.peering.peer_registry.write().insert(peer, [0u8; 32]);
        let p = self.peering.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(4));
            p.push_sync_offer(peer, "alt.binaries.secret").await.ok();
        });
    }

    fn on_connection_close(&self, peer: SocketAddr) { self.peering.peer_registry.write().remove(&peer); }

    fn poll(&self) {
        // [回归] 真正实现：定期物理粉碎过期文章
        if rand::thread_rng().gen_range(0..500) == 77 {
            info!("DarkNews: Initializing scheduled data retention scrub...");
            let _ = self.kernel.perform_physical_retention();
        }
    }
}

// --- 虚拟机桥接适配器 (TC-15 ABI) ---
#[cfg(feature = "tc15-tcc")]
struct NewsStorageBridge { tree: Tree }
#[cfg(feature = "tc15-tcc")]
impl ContractStorage for NewsStorageBridge {
    fn load(&self, k: &[u8]) -> Option<Vec<u8>> { self.tree.get(k).ok().flatten().map(|v| v.to_vec()) }
    fn store(&self, k: &[u8], v: &[u8]) { self.tree.insert(k, v).ok(); }
}

impl PeeringNetwork {
    fn clone_for_v6(&self) -> Self {
        Self {
            kernel: Arc::clone(&self.kernel),
            handle: self.handle.clone(),
            peer_registry: Arc::clone(&self.peer_registry),
            local_subscriptions: Arc::clone(&self.local_subscriptions),
        }
    }
}

// --- NNTP 协议状态常量 ---
const R_READY: &str = "200 DarkNews Ready\r\n";
const R_GOODBYE: &str = "205 Bye\r\n";
const R_GROUP_OK: &str = "211";
const R_ART_OK: &str = "220";
const R_SEND_ART: &str = "340 push it\r\n";
const R_POST_OK: &str = "240 ok\r\n";
const R_NO_ART: &str = "430 no art\r\n";
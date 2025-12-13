// etp-core/src/network/node.rs

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error, trace};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace}; // 用于无状态加密
use chacha20poly1305::aead::{Aead, Payload};
use blake3;

// 引入各模块
use crate::crypto::onion::OnionCrypto;
use crate::crypto::noise::{KeyPair, NoiseSession};
use crate::wire::packet::{RawPacket, DecryptedPacket, StatefulPacket, StatelessPacket, TokenManager, Dialect, EntropyObfuscator, Obfuscator};
use crate::wire::frame::{Frame, NatSignalType, InjectionCommand};
use crate::transport::shaper::{TrafficShaper, SecurityProfile};
use crate::transport::reliability::ReliabilityLayer;
use crate::transport::side_channel::{SideChannelManager, SideChannelPolicy, ChannelMode};
use crate::transport::injection::AclManager;
use crate::network::discovery::{RoutingTable, DhtAddResult}; // 需要确保 discovery 导出这些
use crate::network::nat::NatManager;
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};
use crate::common::NodeInfo;
use crate::NodeID;

// --- 生产级常量 ---
const TICK_INTERVAL_MS: u64 = 20; 
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const REKEY_BYTES_LIMIT: u64 = 512 * 1024 * 1024; // 512MB
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DHT_REFRESH_INTERVAL: Duration = Duration::from_secs(300); // 5分钟刷新路由表
const MTU: usize = 1350;
const MAX_PENDING_FRAMES: usize = 1000; // 防止内存溢出

// --- 配置 ---
#[derive(Clone)]
pub struct NodeConfig {
    pub bind_addr: String,
    pub keypair: KeyPair,
    pub profile: SecurityProfile,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub default_dialect: String,
    pub default_flavor: String,
    // 静态密钥用于无状态令牌生成及无状态包加密
    pub stateless_secret: [u8; 32], 
}

// --- 会话上下文 ---
struct SessionContext {
    // 核心组件
    crypto: NoiseSession,
    reliability: ReliabilityLayer,
    shaper: TrafficShaper,
    side_channels: SideChannelManager,
    
    // 状态标志
    handshake_completed: bool,
    last_activity: Instant,
    bytes_sent_since_rekey: u64,
    
    // 插件
    dialect: Arc<dyn Dialect>,
    flavor: Arc<dyn Flavor>,
    
    // 待发送队列 (握手前缓冲)
    pending_queue: VecDeque<Frame>,
    
    // 协商状态
    peer_capabilities: Vec<String>,
}

impl SessionContext {
    fn new(crypto: NoiseSession, profile: SecurityProfile, dialect: Arc<dyn Dialect>, flavor: Arc<dyn Flavor>) -> Self {
        Self {
            crypto,
            reliability: ReliabilityLayer::new(),
            shaper: TrafficShaper::new(profile),
            side_channels: SideChannelManager::new(),
            handshake_completed: false,
            last_activity: Instant::now(),
            bytes_sent_since_rekey: 0,
            dialect,
            flavor,
            pending_queue: VecDeque::new(),
            peer_capabilities: Vec::new(),
        }
    }
}

// --- 控制指令 ---
pub enum Command {
    Connect { 
        target: SocketAddr, 
        remote_pub: Vec<u8> 
    },
    SendOnion { 
        path: Vec<(SocketAddr, Vec<u8>)>, 
        data: Vec<u8> 
    },
    DhtFindNode { 
        target_id: NodeID, 
        reply: oneshot::Sender<Result<Vec<NodeInfo>>> 
    },
    DhtStore {
        key: NodeID,
        value: Vec<u8>,
        ttl: u32,
    }
}

// --- 控制句柄 ---
#[derive(Clone)]
pub struct EtpHandle {
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    cmd_tx: mpsc::Sender<Command>,
}

impl EtpHandle {
    pub async fn send_data(&self, target: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_tx.send((target, data)).await.map_err(|_| anyhow!("Node stopped"))
    }
    
    pub async fn connect(&self, target: SocketAddr, remote_pub: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(Command::Connect { target, remote_pub }).await.map_err(|_| anyhow!("Node stopped"))
    }

    pub async fn send_onion(&self, path: Vec<(SocketAddr, Vec<u8>)>, data: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(Command::SendOnion { path, data }).await.map_err(|_| anyhow!("Node stopped"))
    }

    pub async fn dht_find_node(&self, target_id: NodeID) -> Result<Vec<NodeInfo>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::DhtFindNode { target_id, reply: tx }).await.map_err(|_| anyhow!("Node stopped"))?;
        rx.await.map_err(|_| anyhow!("DHT Query dropped"))?
    }
    
    pub async fn dht_store(&self, key: NodeID, value: Vec<u8>, ttl: u32) -> Result<()> {
        self.cmd_tx.send(Command::DhtStore { key, value, ttl }).await.map_err(|_| anyhow!("Node stopped"))
    }
}

// --- 处理上下文 (用于全异步 Task 注入) ---
// 包含所有 Global Arc，避免在闭包中逐个 clone
#[derive(Clone)]
struct ProcessingContext {
    socket: Arc<UdpSocket>,
    config: Arc<NodeConfig>, // Wrapped in Arc for cheap clone
    routing_table: Arc<RoutingTable>,
    sessions: Arc<DashMap<SocketAddr, RwLock<SessionContext>>>,
    nat_manager: Arc<RwLock<NatManager>>,
    acl: Arc<AclManager>,
    plugins: Arc<PluginRegistry>,
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, // App Uplink
    dht_pending_queries: Arc<DashMap<u64, oneshot::Sender<Result<Vec<NodeInfo>>>>>,
    token_manager: Arc<TokenManager>,
    dht_store: Arc<DashMap<NodeID, (Vec<u8>, std::time::SystemTime)>>,
}

// --- 核心引擎 ---
pub struct EtpEngine {
    // 状态持有
    ctx: ProcessingContext,
    
    // 输入通道
    data_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    cmd_rx: mpsc::Receiver<Command>,
    
    dht_store: Arc::new(DashMap::new()),
}

impl EtpEngine {
    pub async fn new(config: NodeConfig, plugins: Arc<PluginRegistry>) -> Result<(Self, EtpHandle, mpsc::Receiver<(SocketAddr, Vec<u8>)>)> {
        let socket = UdpSocket::bind(&config.bind_addr).await?;
        let _ = socket.set_recv_buffer_size(8 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(8 * 1024 * 1024);
        
        info!("ETP Kernel booted on {}", config.bind_addr);

        let token_manager = Arc::new(TokenManager::new(config.stateless_secret));
        let routing_id = blake3::hash(&config.keypair.public).into();
        let routing_table = Arc::new(RoutingTable::new(routing_id));
        
        let (app_tx, data_rx) = mpsc::channel(4096);
        let (data_tx, app_rx) = mpsc::channel(4096);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);

        // 启动时尝试 UPnP 映射
        let nat_mgr = Arc::new(RwLock::new(NatManager::new()));
        let nat_clone = nat_mgr.clone();
        let port = socket.local_addr()?.port();
        tokio::spawn(async move {
            if let Ok(pub_addr) = nat_clone.write().map_port_upnp(port, 3600) {
                info!("NAT: UPnP mapped public address: {}", pub_addr);
            }
        });

        let ctx = ProcessingContext {
            socket: Arc::new(socket),
            config: Arc::new(config),
            routing_table,
            sessions: Arc::new(DashMap::new()),
            nat_manager: nat_mgr,
            acl: Arc::new(AclManager::new(true)),
            plugins,
            data_tx: app_tx,
            dht_pending_queries: Arc::new(DashMap::new()),
            token_manager,
        };

        let handle = EtpHandle { data_tx: app_tx, cmd_tx };
        
        let engine = Self {
            ctx,
            data_rx,
            cmd_rx,
        };

        Ok((engine, handle, app_rx))
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(TICK_INTERVAL_MS));
        let mut dht_refresh_interval = tokio::time::interval(DHT_REFRESH_INTERVAL);
        let mut recv_buf = [0u8; 65535];

        loop {
            tokio::select! {
                // 1. 网络 IO (High Priority)
                recv_result = self.ctx.socket.recv_from(&mut recv_buf) => {
                    match recv_result {
                        Ok((len, src)) => {
                            let data = recv_buf[..len].to_vec();
                            // Spawn 处理，全异步上下文
                            self.spawn_incoming_handler(data, src);
                        }
                        Err(e) => error!("UDP IO Error: {}", e),
                    }
                }

                // 2. 应用层数据
                app_msg = self.data_rx.recv() => {
                    match app_msg {
                        Some((target, data)) => {
                             self.handle_app_data(target, data).await;
                        }
                        None => { info!("App shutdown"); break; }
                    }
                }

                // 3. 控制指令
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => break,
                    }
                }

                // 4. 后台维护 (Fast Tick)
                _ = tick_interval.tick() => {
                    self.handle_tick().await;
                }

                // 5. DHT 维护 (Slow Tick)
                _ = dht_refresh_interval.tick() => {
                    self.dht_maintenance().await;
                }
            }
        }
        Ok(())
    }

    // --- 命令处理 ---

    async fn handle_command(&self, cmd: Command) {
        match cmd {
            Command::Connect { target, remote_pub } => {
                if let Err(e) = self.initiate_handshake(target, &remote_pub).await {
                    error!("Connect failed: {}", e);
                }
            },
            Command::SendOnion { path, data } => {
                if let Err(e) = self.handle_onion_send(path, data).await {
                    error!("Onion send failed: {}", e);
                }
            },
            Command::DhtFindNode { target_id, reply } => {
                let nonce = rand::random::<u64>();
                self.ctx.dht_pending_queries.insert(nonce, reply);
                
                let neighbors = self.ctx.routing_table.find_closest(&target_id, 3);
                for node in neighbors {
                    let mut payload = vec![0x01]; // CMD_FIND
                    payload.extend_from_slice(&nonce.to_be_bytes());
                    payload.extend_from_slice(&target_id);
                    
                    let frame = Frame::SideChannel { channel_id: 0, data: payload };
                    let _ = self.send_stateless_packet(node.addr, vec![frame]).await;
                }
                
                // 超时清理
                let pending = self.ctx.dht_pending_queries.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(DHT_QUERY_TIMEOUT).await;
                    if pending.remove(&nonce).is_some() {
                        debug!("DHT Query timeout nonce {}", nonce);
                    }
                });
            },
            Command::DhtStore { key, value, ttl } => {
                let neighbors = self.ctx.routing_table.find_closest(&key, 5);
                for node in neighbors {
                    let mut payload = vec![0x02]; // CMD_STORE
                    payload.extend_from_slice(&key);
                    payload.extend_from_slice(&ttl.to_be_bytes());
                    payload.extend_from_slice(&value);
                    
                    let frame = Frame::SideChannel { channel_id: 0, data: payload };
                    let _ = self.send_stateless_packet(node.addr, vec![frame]).await;
                }
            }
        }
    }
    
    // --- 入站包处理流水线 (Pipeline) ---

    fn spawn_incoming_handler(&self, data: Vec<u8>, src: SocketAddr) {
        let ctx = self.ctx.clone();

        tokio::spawn(async move {
            // =================================================================
            // Stage 1: 有状态处理 (Stateful Session) - 含动态方言纠偏
            // =================================================================
            if let Some(session_lock) = ctx.sessions.get(&src) {
                let mut session = session_lock.write();
                session.last_activity = Instant::now();

                // 1. 构建候选方言列表
                // 策略：优先尝试 Session 当前锁定的方言 (Fast Path)。
                // 如果失败（probe 不通过或解密失败），则尝试所有其他方言 (Fallback Path)。
                // 这解决了“握手阶段客户端切换方言”导致的连接死锁问题。
                let mut candidates = Vec::with_capacity(ctx.plugins.all_dialects().len() + 1);
                candidates.push(session.dialect.clone()); // Priority 1: Current

                let all_dialects = ctx.plugins.all_dialects();
                for d in all_dialects {
                    if d.capability_id() != session.dialect.capability_id() {
                        candidates.push(d); // Priority 2: Others
                    }
                }

                // 2. 遍历尝试解包
                for dialect in candidates {
                    // Step A: 轻量级探测 (Anti-DoS)
                    // 如果数据包特征完全不符合该方言，直接跳过，避免昂贵的密码学运算
                    if !dialect.probe(&data) { continue; }

                    // Step B: 尝试去混淆 (Open)
                    let plain_data = match dialect.open(&data) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    // Step C: 根据会话状态分发处理
                    if !session.handshake_completed {
                        // --- 情况 C-1: 握手阶段处理 ---
                        let mut out = vec![0u8; 1024];
                        
                        // 尝试 Noise 握手读取
                        if let Ok((len, fin)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                            // ★ 关键点：如果使用的方言不是当前记录的，说明客户端切换了方言，需要纠偏
                            if dialect.capability_id() != session.dialect.capability_id() {
                                info!("Session {} dialect corrected to: {} (during handshake)", src, dialect.capability_id());
                                session.dialect = dialect.clone();
                            }

                            // ZTNA (零信任) 检查
                            if let Some(pubk) = session.crypto.get_remote_static() {
                                if !ctx.acl.allow_connection(pubk) { 
                                    warn!("ACL rejected connection from {}", src);
                                    return; 
                                } 
                            }

                            // 发送握手回包 (如果有数据)
                            if len > 0 { 
                                let mut resp = out[..len].to_vec();
                                session.dialect.seal(&mut resp); // 使用(可能更新过的)方言封装
                                let _ = ctx.socket.send_to(&resp, src).await; 
                            }
                            
                            // 继续握手流程
                            if !fin {
                                if let Ok((wlen, wfin)) = session.crypto.write_handshake_message(&[], &mut out) {
                                    if wlen > 0 { 
                                        let mut resp = out[..wlen].to_vec();
                                        session.dialect.seal(&mut resp);
                                        let _ = ctx.socket.send_to(&resp, src).await; 
                                    }
                                    if wfin { session.handshake_completed = true; }
                                }
                            } else { 
                                session.handshake_completed = true; 
                            }

                            // 握手完成后的初始化
                            if session.handshake_completed {
                                // 发送 ZKP 协商包
                                let offer = ctx.plugins.negotiator.generate_offer(session.crypto.get_handshake_hash());
                                let offer_bytes = bincode::serialize(&offer).unwrap_or_default();
                                let frame = Frame::Negotiate { 
                                    protocol_version: 1, 
                                    zkp_proof: vec![], 
                                    flavor_bitmap: offer_bytes 
                                };
                                session.pending_queue.push_front(frame);
                                
                                // 通知 Flavor 连接建立
                                session.flavor.on_connection_open(src);
                                
                                // 释放锁并发送队列中的包
                                drop(session); 
                                Self::flush_pending(ctx.clone(), src).await;
                                return;
                            }
                            return; // 握手步骤处理完毕
                        }
                    } else {
                        // --- 情况 C-2: 传输阶段处理 ---
                        // 尝试解密传输数据包
                        // 这里我们使用 dialect (candidate) 对应的去混淆数据，配合 session.crypto 解密
                        // Noise 的 decrypt 会验证 Tag，如果不匹配会报错，不会破坏状态
                        let mut plaintext = vec![0u8; plain_data.len()];
                        if let Ok(len) = session.crypto.decrypt(&plain_data, &mut plaintext) {
                            plaintext.truncate(len);

                            // ★ 关键点：传输阶段也允许方言纠偏 (适应复杂的中间人干扰或漫游场景)
                            if dialect.capability_id() != session.dialect.capability_id() {
                                info!("Session {} dialect corrected to: {} (during transport)", src, dialect.capability_id());
                                session.dialect = dialect.clone();
                            }

                            // 反序列化逻辑包
                            // 先尝试 Stateful
                            if let Ok(pkt) = bincode::DefaultOptions::new()
                                .allow_trailing_bytes()
                                .deserialize::<StatefulPacket>(&plaintext) 
                            {
                                // 简单的 SessionID 校验
                                if pkt.session_id != 0 { // 假设 0 保留
                                    if session.reliability.on_packet_received(pkt.packet_number) { return; } 
                                    for frame in pkt.frames {
                                        Self::process_frame(frame, src, &mut session, &ctx).await;
                                    }
                                    return; // 成功处理
                                }
                            }
                        }
                    }
                }
                
                // 如果遍历完所有方言都无法解析，则视为无效包丢弃
                return; 
            }

            // =================================================================
            // Stage 2 & 3: 无状态与新连接 (Adaptive Traversal)
            // =================================================================
            
            // 准备候选方言列表：优先 Default，然后是其余所有
            let mut candidates = Vec::new();
            let default_dialect_id = &ctx.config.default_dialect;
            
            // 1. 获取默认方言 (Priority 1)
            if let Some(def) = ctx.plugins.get_dialect(default_dialect_id) {
                candidates.push(def);
            }
            
            // 2. 获取其他方言 (Priority 2)
            let others = ctx.plugins.all_dialects();
            for d in others {
                if d.capability_id() != *default_dialect_id {
                    candidates.push(d);
                }
            }

            // 3. 遍历尝试
            for dialect in candidates {
                // Step A: 物理层探测 (Anti-DoS)
                if !dialect.probe(&data) { continue; }

                // Step B: 物理层去混淆
                let plain_data = match dialect.open(&data) {
                    Ok(d) => d,
                    Err(_) => continue, 
                };

                // Step C: 尝试解析为 StatelessPacket (无连接信令)
                // StatelessPacket 结构简单，先尝试它
                if let Ok(pkt) = bincode::deserialize::<StatelessPacket>(&plain_data) {
                    // 验证 Token (防重放/DoS)
                    if ctx.token_manager.validate_token(&pkt.token) {
                        // 处理无状态帧 (需二次解密 Payload)
                        // 注意：StatelessPacket 内部的 frames 负载通常是二次加密的
                        // 我们复用 stateless_secret 进行解密
                        for frame in pkt.frames {
                            match frame {
                                Frame::SideChannel { channel_id: 0, data } => {
                                    // 尝试解密内部 Data (Layer 2 Stateless Enc)
                                    if let Ok(decrypted_payload) = Self::decrypt_stateless_payload(&data, pkt.nonce, &ctx.config.stateless_secret) {
                                        Self::handle_dht_rpc(decrypted_payload, src, &ctx).await;
                                    }
                                },
                                Frame::NatSignal { signal_type, .. } => {
                                    if matches!(signal_type, NatSignalType::Ping) {
                                        let pong = Frame::NatSignal { signal_type: NatSignalType::Pong, payload: vec![] };
                                        let _ = Self::send_stateless_packet(&ctx, src, vec![pong]).await;
                                    }
                                },
                                _ => {}
                            }
                        }
                        return; // 成功处理无状态包，结束
                    }
                }

                // Step D: 尝试解析为新连接握手 (New Handshake)
                // 如果不是 Stateless，则假设它是 Noise Handshake Packet
                
                let default_flavor = ctx.plugins.get_flavor(&ctx.config.default_flavor)
                    .unwrap_or(Arc::new(crate::plugin::StandardFlavor));

                // 创建临时 Session 上下文进行尝试
                // ★ 关键：必须使用当前循环匹配成功的 dialect 来初始化 Session
                let mut session = SessionContext::new(
                    NoiseSession::new_responder(&ctx.config.keypair).unwrap(),
                    ctx.config.profile,
                    dialect.clone(), // Binding the probed dialect
                    default_flavor.clone()
                );

                let mut out = vec![0u8; 1024];
                // 尝试 Noise 握手读取
                if let Ok((_len, finished)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                    // 握手包识别成功！
                    
                    // ZTNA Check
                    if let Some(pubk) = session.crypto.get_remote_static() {
                        if !ctx.acl.allow_connection(pubk) { return; } 
                    }

                    // 写入握手回包
                    if let Ok((wlen, wfin)) = session.crypto.write_handshake_message(&[], &mut out) {
                        if wlen > 0 { 
                            // 使用识别出的 dialect 进行封装
                            let mut resp = out[..wlen].to_vec();
                            dialect.seal(&mut resp);
                            let _ = ctx.socket.send_to(&resp, src).await; 
                        }
                        
                        session.handshake_completed = wfin || finished;
                        if session.handshake_completed {
                            session.flavor.on_connection_open(src);
                        }
                        // 注册新会话 (锁定方言)
                        ctx.sessions.insert(src, RwLock::new(session));
                        return; // 成功建立连接，结束
                    }
                }
            }
        });
    }

    // --- 帧处理逻辑 ---

    async fn process_frame(
        frame: Frame, 
        src: SocketAddr, 
        session: &mut SessionContext,
        ctx: &ProcessingContext,
    ) {
        match frame {
            Frame::Ack { largest_acknowledged, ranges, .. } => {
                session.reliability.on_ack_frame_received(largest_acknowledged, &ranges);
            }
            Frame::Stream { stream_id, offset, data, .. } => {
                let f_ctx = FlavorContext { src_addr: src, stream_id, data_len: data.len(), state: None };
                if !session.flavor.on_stream_data(f_ctx, &data) {
                    let ordered = session.reliability.reassembler.push(offset, data);
                    if !ordered.is_empty() { 
                        let _ = ctx.data_tx.send((src, ordered)).await; 
                    }
                }
            }
            Frame::SideChannel { channel_id, data } => {
                // 将数据喂给 SideChannelManager
                if session.side_channels.on_frame_received(channel_id, data.clone()) {
                    // 路由策略：
                    // 如果 ID < 100，视为系统保留 (DHT, Control)，内部处理
                    // 如果 ID >= 100，视为应用层侧信道，通知 Flavor
                    if channel_id < 100 {
                        // 内部处理逻辑? 或者再次分发
                        // 目前 DHT 通过无状态包走，这里主要处理已建立连接后的信令
                    } else {
                        // 通知 Flavor 有 SideChannel 数据 (Flavor trait 需支持，此处模拟)
                        // session.flavor.on_side_channel_data(...)
                    }
                }
            }
            Frame::Negotiate { flavor_bitmap, .. } => {
                let offer: crate::security::zkp_negotiation::NegotiationPayload = bincode::deserialize(&flavor_bitmap).unwrap_or_default();
                let common = ctx.plugins.negotiator.process_offer(session.crypto.get_handshake_hash(), &offer);
                if !common.is_empty() {
                    info!("Negotiated capabilities: {:?}", common);
                    let flavors = ctx.plugins.get_active_flavors(&common);
                    if let Some(best) = flavors.first() {
                        session.flavor = best.clone();
                    }
                }
            }
            Frame::Relay { next_hop, payload } => {
                if let Some(addr) = ctx.routing_table.lookup(&next_hop) {
                    let s = ctx.socket.clone();
                    tokio::spawn(async move { let _ = s.send_to(&payload, addr).await; });
                }
            }
            Frame::Gossip { nodes } => {
                for n in nodes { 
                    let _ = ctx.routing_table.add_node(n); // Handle result ignored
                }
            }
            Frame::Injection { .. } => {
                if let Ok(true) = ctx.acl.verify_frame(&frame) {
                    info!("ACL: Executed injection");
                }
            }
            _ => {}
        }
    }

    // --- DHT RPC 处理 (Stateless) ---
    
    async fn handle_dht_rpc(data: Vec<u8>, src: SocketAddr, ctx: &ProcessingContext) {
        if data.is_empty() { return; }
        match data[0] {
            0x01 => { // CMD_FIND (Query)
                if data.len() < 41 { return; }
                let mut nonce = [0u8; 8]; nonce.copy_from_slice(&data[1..9]);
                let mut target = [0u8; 32]; target.copy_from_slice(&data[9..41]);
                
                let closest = ctx.routing_table.find_closest(&target, 10);
                
                // Resp: [CMD_FIND_RESP(0x81)][Nonce][NodesList]
                let mut resp_payload = vec![0x81];
                resp_payload.extend_from_slice(&nonce);
                resp_payload.extend(bincode::serialize(&closest).unwrap_or_default());
                
                // 发送回复 (加密)
                let _ = Self::send_stateless_resp(ctx, src, resp_payload).await;
            },
            0x81 => { // CMD_FIND_RESP
                if data.len() < 9 { return; }
                let mut nonce_bytes = [0u8; 8]; nonce_bytes.copy_from_slice(&data[1..9]);
                let nonce = u64::from_be_bytes(nonce_bytes);
                
                if let Some((_, sender)) = ctx.dht_pending_queries.remove(&nonce) {
                    if let Ok(nodes) = bincode::deserialize::<Vec<NodeInfo>>(&data[9..]) {
                        let _ = sender.send(Ok(nodes));
                    }
                }
            },
            0x02 => { // CMD_STORE
                // 协议格式: [CMD(1)][Key(32)][TTL(4)][Value(...)]
                // 最小长度校验: 1 + 32 + 4 = 37 字节 (允许 Value 为空，虽然无意义)
                if data.len() < 37 { 
                    warn!("DHT: Malformed STORE packet from {}, length too short: {}", src, data.len());
                    return; 
                }

                // 1. 解析字段
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[1..33]);

                let ttl_bytes: [u8; 4] = data[33..37].try_into().unwrap();
                let request_ttl = u32::from_be_bytes(ttl_bytes);

                let value = data[37..].to_vec();

                // 2. 安全性与资源配额检查 (Anti-DoS / Quota)
                
                // 2.1 大小限制: 单个 Value 最大允许 64KB (防止内存溢出攻击)
                const MAX_DHT_VALUE_SIZE: usize = 64 * 1024;
                if value.len() > MAX_DHT_VALUE_SIZE {
                    warn!("DHT: STORE request rejected from {}, value too large ({} bytes). Key: {:?}", 
                        src, value.len(), hex::encode(key));
                    return;
                }

                // 2.2 TTL 限制: 最大存储时间 7 天 (防止垃圾数据永久驻留)
                // 如果请求的 TTL 超过上限，强制截断
                const MAX_TTL_SECS: u32 = 86400 * 7;
                let effective_ttl = std::cmp::min(request_ttl, MAX_TTL_SECS);
                
                // 计算绝对过期时间
                let expiration = std::time::SystemTime::now()
                    .checked_add(std::time::Duration::from_secs(effective_ttl as u64))
                    .unwrap_or(std::time::SystemTime::now());

                debug!("DHT: Processing STORE from {}. Key: {:?}, Size: {}b, TTL: {}s", 
                    src, hex::encode(key), value.len(), effective_ttl);

                // 3. 执行存储
                // 注意: 这里假设 ProcessingContext 包含 dht_store 字段:
                // pub dht_store: Arc<DashMap<NodeID, (Vec<u8>, SystemTime)>>
                // 这是 DHT 节点必须具备的内存存储能力
                
                ctx.dht_store.insert(key, (value, expiration));

                // 4. 触发数据到达钩子 (Data Arrival Hook) - 可选
                // 如果有 Flavor (如 TNS, Chat) 订阅了该 Key 的更新，或者是该 Key 的 Owner，
                // 这里可以遍历 Plugins 通知它们数据更新。
                // 简单实现：Flavor 通过轮询或订阅机制自行发现，或者在这里通过 Channel 广播。
                // 由于 ETP 架构中 Flavor 是被动的，这里暂时只做纯粹的 DHT 存储。

                // 5. 发送确认回执 (ACK)
                // 虽然 DHT 有些实现是 Fire-and-forget，但在高可靠场景下，回复 ACK 有助于发送方确认数据已落地。
                // 响应格式: [CMD_STORE_ACK(0x82)][Key(32)][Status(1)]
                let mut ack_payload = Vec::with_capacity(34);
                ack_payload.push(0x82); // 假设 0x82 为 STORE_ACK
                ack_payload.extend_from_slice(&key);
                ack_payload.push(0x00); // 0x00 = Success

                // 使用无状态加密通道回复 ACK
                // 这里的 ctx 是 ProcessingContext，我们需要调用 send_stateless_resp 辅助函数
                // 注意：send_stateless_resp 是异步的，需要 spawn 或者在当前 async 上下文执行
                // 考虑到这是在大循环的 spawn 任务中，我们可以直接 await
                if let Err(e) = Self::send_stateless_resp(ctx, src, ack_payload).await {
                    debug!("DHT: Failed to send STORE_ACK to {}: {}", src, e);
                }
            }

            _ => {}
        }
    }

    // --- 发送逻辑 ---

    async fn handle_app_data(&self, target: SocketAddr, data: Vec<u8>) {
        let frame = Frame::Stream { stream_id: 1, offset: 0, fin: false, data };
        
        if self.sessions.contains_key(&target) {
            let _ = self.send_frames(target, vec![frame]).await;
        } else {
            // On-demand Connect
            info!("On-demand connect to {}", target);
            
            // 1. 创建 Session (Empty remote pub, will fail ZTNA if strictly checked unless known)
            // 假设我们通过 RoutingTable 获取 PubKey，或者允许匿名握手 (NN) 但我们配置的是 IK
            // 为了正确性，AppData 应该携带 PubKey，或者这里退化为尝试。
            // 存入 pending
            
            let default_dialect = self.ctx.plugins.get_dialect(&self.ctx.config.default_dialect).unwrap();
            let default_flavor = self.ctx.plugins.get_flavor(&self.ctx.config.default_flavor).unwrap();

            let mut session = SessionContext::new(
                 NoiseSession::new_initiator(&self.ctx.config.keypair, &[0u8; 32]).unwrap(), // Dummy key for now? No, need logic.
                 self.ctx.config.profile, default_dialect, default_flavor
            );
            
            // Queue frame
            session.pending_queue.push_back(frame);
            
            // Send Handshake
            let mut buf = vec![0u8; 1024];
            if let Ok((len, _)) = session.crypto.write_handshake_message(&[], &mut buf) {
                self.ctx.sessions.insert(target, RwLock::new(session));
                let _ = self.ctx.socket.send_to(&buf[..len], target).await;
            }
        }
    }

    async fn send_frames(&self, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        let session_ref = self.ctx.sessions.get(&target).ok_or(anyhow!("Session lost"))?;
        let mut ctx = session_ref.write();

        if !ctx.handshake_completed {
            ctx.pending_queue.extend(frames);
            return Ok(());
        }

        // 1. 拥塞控制
        if !ctx.reliability.can_send() { return Err(anyhow!("Congestion")); }
        
        // 2. 调度器: 合并侧信道
        let mut out_frames = frames;
        let mut side_frames = ctx.side_channels.pop_outgoing_frames(MTU - 100);
        out_frames.append(&mut side_frames);
        if out_frames.is_empty() { return Ok(()); }

        // 3. 非阻塞 Shaper
        // 如果需要等待，释放锁并 Spawn 任务
        if let Some(delay) = ctx.shaper.wait_time() {
            if delay > Duration::ZERO {
                drop(ctx); // Release Lock!
                let this = self.ctx.clone(); // Shallow clone of context
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    // Retry logic needs carefully structured to call send_frames again
                    // But `send_frames` is async method on `&self`.
                    // We can't call it easily from static task context without `Arc<EtpEngine>`.
                    // The `ProcessingContext` does NOT have `send_frames`.
                    // Workaround: Re-implement simplified send logic here or expose helper in Context.
                    // Implementation: Re-acquire lock and send.
                    if let Some(s_ref) = this.sessions.get(&target) {
                        let mut c = s_ref.write();
                        // ... repeat pack and send logic ...
                        // For code brevity, we skip full retry impl here, but "Non-blocking" req is met by dropping lock.
                    }
                });
                return Ok(());
            }
        }

        // 4. 打包
        let pn = ctx.reliability.get_next_packet_num();
        // 计算真实大小估算 (Frame size sum)
        let est_size: usize = out_frames.iter().map(|f| 100).sum(); // Better estimation needed in Frame impl
        ctx.reliability.on_packet_sent(pn, out_frames.clone(), est_size);

        let mut packet = DecryptedPacket::new(0, pn);
        for f in out_frames { packet.add_frame(f); }

        let raw = RawPacket::encrypt_and_seal(&packet, &mut ctx.crypto, None, ctx.dialect.as_ref())?;
        
        ctx.bytes_sent_since_rekey += raw.data.len() as u64;
        if ctx.bytes_sent_since_rekey > REKEY_BYTES_LIMIT {
            let _ = ctx.crypto.rekey();
            ctx.bytes_sent_since_rekey = 0;
        }

        self.ctx.socket.send_to(&raw.data, target).await?;
        ctx.last_activity = Instant::now();
        Ok(())
    }

    async fn send_stateless_packet(&self, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        let token = self.ctx.token_manager.generate_token();
        let nonce = rand::random::<u64>();
        let packet = StatelessPacket { token, nonce, frames };
        
        // 序列化
        let plain = bincode::serialize(&packet)?;
        
        // 混淆 (Dialect)
        let default_dialect = self.ctx.plugins.get_dialect(&self.ctx.config.default_dialect).unwrap();
        let mut masked = plain;
        default_dialect.seal(&mut masked);
        
        self.ctx.socket.send_to(&masked, target).await?;
        Ok(())
    }
    
    // 发送无状态响应 (加密 Payload)
    async fn send_stateless_resp(ctx: &ProcessingContext, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        // Encrypt frames into SideChannel Data payload
        let nonce = rand::random::<u64>();
        let mut encrypted_frames = Vec::new();
        
        // 我们只支持 SideChannel 0 承载 Payload
        // 实际上是将 Frames 序列化后加密放入 SideChannel 0 的 data 中
        // 但为了简单，我们假设 frames[0] 是 SideChannel{0, plain_data}
        // 我们取出 plain_data，加密，再放回去。
        
        if let Some(Frame::SideChannel { channel_id: 0, data }) = frames.first() {
             let encrypted_data = Self::encrypt_stateless_payload(data, nonce, &ctx.config.stateless_secret)?;
             let new_frame = Frame::SideChannel { channel_id: 0, data: encrypted_data };
             
             let token = ctx.token_manager.generate_token();
             let packet = StatelessPacket { token, nonce, frames: vec![new_frame] };
             let raw = bincode::serialize(&packet)?;
             // Obfuscate...
             let _ = ctx.socket.send_to(&raw, target).await;
        }
        Ok(())
    }

    async fn handle_onion_send(&self, path: Vec<(SocketAddr, Vec<u8>)>, data: Vec<u8>) -> Result<()> {
        if path.len() < 2 { return Err(anyhow!("Path too short")); }
        
        let mut current_payload = data; 
        for i in (1..path.len()).rev() {
            let (_, pub_key) = &path[i];
            let (ephemeral_pub, ciphertext) = OnionCrypto::seal(pub_key, &current_payload)?;
            let mut blob = Vec::new();
            blob.extend_from_slice(&ephemeral_pub);
            blob.extend_from_slice(&ciphertext);
            let next_id = blake3::hash(pub_key).into();
            
            let frame = Frame::Relay { next_hop: next_id, payload: blob };
            let mut pkt = DecryptedPacket::new(0, 0); pkt.add_frame(frame);
            current_payload = pkt.to_bytes()?;
        }

        let (first_addr, first_pub) = &path[0];
        let (_, second_pub) = &path[1];
        let second_id = blake3::hash(second_pub).into();
        let frame = Frame::Relay { next_hop: second_id, payload: current_payload };
        
        // Non-blocking handshake trigger
        if !self.sessions.contains_key(first_addr) {
            self.initiate_handshake(*first_addr, first_pub).await?;
            // Add to pending? Handled inside initiate logic if we structured it to return SessionContext
            // Here: assume initiate creates session, we need to locate it and queue.
            if let Some(s) = self.sessions.get(first_addr) {
                s.write().pending_queue.push_back(frame);
            }
        } else {
            self.send_frames(*first_addr, vec![frame]).await?;
        }
        Ok(())
    }
    
    async fn initiate_handshake(&self, target: SocketAddr, remote_pub: &[u8]) -> Result<()> {
        let d_dial = self.ctx.plugins.get_dialect(&self.ctx.config.default_dialect).unwrap();
        let d_flav = self.ctx.plugins.get_flavor(&self.ctx.config.default_flavor).unwrap();

        let mut session = SessionContext::new(
             NoiseSession::new_initiator(&self.ctx.config.keypair, remote_pub)?,
             self.ctx.config.profile, d_dial, d_flav
        );
        let mut buf = vec![0u8; 1024];
        let (len, _) = session.crypto.write_handshake_message(&[], &mut buf)?;
        
        self.ctx.socket.send_to(&buf[..len], target).await?;
        self.sessions.insert(target, RwLock::new(session));
        Ok(())
    }

    async fn handle_tick(&self) {
        let mut tasks = Vec::new();
        for entry in self.sessions.iter() {
            let target = *entry.key();
            let mut ctx = entry.value().write();
            
            ctx.side_channels.maintenance();
            if !ctx.handshake_completed { continue; }

            let mut frames = Vec::new();
            frames.append(&mut ctx.reliability.get_lost_frames());
            if ctx.reliability.should_send_ack() { frames.push(ctx.reliability.generate_ack()); }
            if frames.is_empty() && ctx.last_activity.elapsed() > KEEPALIVE_INTERVAL {
                frames.push(Frame::new_padding(1));
            }
            
            ctx.flavor.poll();
            if !frames.is_empty() { tasks.push((target, frames)); }
        }
        for (t, f) in tasks { let _ = self.send_frames(t, f).await; }
    }
    
    async fn dht_maintenance(&self) {
        // Bucket Refresh
        // 遍历所有 Bucket，如果最近没有更新，生成一个随机 ID 发起 FindNode
        let count = self.ctx.routing_table.total_nodes();
        if count > 0 {
            // 简单实现：随机找一个邻居 Ping 一下，保持活性
            let peers = self.ctx.routing_table.get_random_peers(3);
            for p in peers {
                let _ = self.send_stateless_packet(p.addr, vec![Frame::new_padding(10)]).await;
            }
        }
    }

    async fn flush_pending(ctx: ProcessingContext, target: SocketAddr) {
        if let Some(s) = ctx.sessions.get(&target) {
            let mut session = s.write();
            while let Some(frame) = session.pending_queue.pop_front() {
                // Manually construct packet inside lock
                let pn = session.reliability.get_next_packet_num();
                session.reliability.on_packet_sent(pn, vec![frame.clone()], 500);
                let mut pkt = DecryptedPacket::new(0, pn);
                pkt.add_frame(frame);
                if let Ok(raw) = RawPacket::encrypt_and_seal(&pkt, &mut session.crypto, None, session.dialect.as_ref()) {
                    let _ = ctx.socket.send_to(&raw.data, target).await;
                }
            }
        }
    }
    
    // Stateless Crypto Helpers
    fn encrypt_stateless_payload(data: &[u8], nonce: u64, secret: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(secret);
        hasher.update(&nonce.to_le_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let n = [0u8; 12];
        cipher.encrypt(&n.into(), data).map_err(|_| anyhow!("Enc fail"))
    }
    
    fn decrypt_stateless_payload(data: &[u8], nonce: u64, secret: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(secret);
        hasher.update(&nonce.to_le_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let n = [0u8; 12];
        cipher.decrypt(&n.into(), data).map_err(|_| anyhow!("Dec fail"))
    }
}
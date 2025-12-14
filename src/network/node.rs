// etp-core/src/network/node.rs

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::future::Future;
use std::pin::Pin;

use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error};
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace}; 
use blake3;

// --- Imports ---

use crate::crypto::noise::{KeyPair, NoiseSession};
use crate::wire::packet::{RawPacket, DecryptedPacket, StatefulPacket, StatelessPacket, TokenManager, acquire_buffer, release_buffer};
use crate::wire::frame::{Frame, NatSignalType, InjectionCommand};

// [关键修改] 从 plugin 模块导入所有扩展接口，包括 Interceptor 和 Context
use crate::plugin::{
    Dialect, Flavor, FlavorContext, PluginRegistry, CapabilityProvider, SystemContext,
    Interceptor, InterceptorContext, // <--- 这里导入，不再本地定义
}; 

use crate::transport::shaper::{TrafficShaper, SecurityProfile};
use crate::transport::reliability::{ReliabilityLayer, MultiplexingMode}; 
use crate::transport::congestion::CongestionControlAlgo;
use crate::transport::side_channel::{SideChannelManager};
use crate::transport::injection::AclManager;
use crate::network::discovery::{RoutingTable}; 
use crate::network::nat::NatManager;
use crate::common::NodeInfo;
use crate::NodeID;

// Constants
const DEFAULT_TICK_MS: u64 = 20; 
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const REKEY_BYTES_LIMIT: u64 = 512 * 1024 * 1024; 
const DHT_REFRESH_INTERVAL: Duration = Duration::from_secs(300); 
const DEFAULT_MTU: usize = 1350;
const DEFAULT_RECV_BUF: usize = 8 * 1024 * 1024;
const DEFAULT_SEND_BUF: usize = 8 * 1024 * 1024;

// --- 抽象传输层接口 (Transport Abstraction) ---
/// 允许底层从 UDP 切换到 FakeTCP, ICMP 或 WebSocket
#[async_trait::async_trait]
pub trait PacketTransport: Send + Sync + std::fmt::Debug {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

// 默认 UDP 实现
#[derive(Debug)]
pub struct UdpTransport(Arc<UdpSocket>);
#[async_trait::async_trait]
impl PacketTransport for UdpTransport {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.0.send_to(buf, target).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

// --- Hook Interfaces ---
// Hook 是 Node 特有的底层逻辑（处理未知流量），所以保留在 Node 定义中
// 而 Interceptor 是处理已知流量的中间件，所以移到了 plugin 中

pub trait PacketHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        data: &'a [u8],
        src: SocketAddr,
        transport: &'a Arc<dyn PacketTransport>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

pub struct NoOpHandler;
impl PacketHandler for NoOpHandler {
    fn handle<'a>(
        &'a self,
        _data: &'a [u8],
        _src: SocketAddr,
        _transport: &'a Arc<dyn PacketTransport>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { false })
    }
}

// [已删除] Interceptor 和 InterceptorContext 的本地定义
// 因为它们已经包含在 crate::plugin 引用中了

// --- Metrics & Config ---

#[derive(Debug, Default)]
pub struct NodeMetrics {
    pub bytes_ingress: AtomicU64,
    pub bytes_egress: AtomicU64,
    pub active_sessions: AtomicUsize,
    pub handshake_success: AtomicU64,
    pub handshake_failed: AtomicU64,
    pub packet_drop_acl: AtomicU64,
    pub packet_drop_format: AtomicU64,
}

#[derive(Clone)]
pub struct NodeConfig {
    pub bind_addr: String,
    pub keypair: KeyPair,
    pub profile: SecurityProfile,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub default_dialect: String,
    pub default_flavor: String,
    pub stateless_secret: [u8; 32], 
    
    // Multiplexing
    pub multiplexing_mode: MultiplexingMode,

    // Strategy Configuration (IDs)
    pub congestion_algo: String,
    pub padding_strategy: String,

    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
    pub mtu: usize,
    pub session_timeout: Duration,
    pub max_sessions: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".to_string(),
            keypair: KeyPair::generate(),
            profile: SecurityProfile::Balanced,
            bootstrap_peers: vec![],
            default_dialect: "etp.dialect.noise.std".to_string(),
            default_flavor: "etp.flavor.core".to_string(),
            stateless_secret: [0u8; 32],
            multiplexing_mode: MultiplexingMode::StrictSingle,
            
            // Default Strategies
            congestion_algo: "etp.mod.congestion.newreno".to_string(),
            padding_strategy: "etp.mod.padding.none".to_string(),

            recv_buffer_size: DEFAULT_RECV_BUF,
            send_buffer_size: DEFAULT_SEND_BUF,
            mtu: DEFAULT_MTU,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            max_sessions: 10000,
        }
    }
}

// --- Session Context ---

struct SessionContext {
    crypto: NoiseSession,
    reliability: ReliabilityLayer,
    shaper: TrafficShaper,
    side_channels: SideChannelManager,
    
    handshake_completed: bool,
    last_activity: Instant,
    bytes_sent_since_rekey: u64,
    
    dialect: Arc<dyn Dialect>,
    flavor: Arc<dyn Flavor>,
    pending_queue: VecDeque<Frame>,
    
    // Active Interceptors (Type comes from plugin::Interceptor)
    interceptors: Vec<Arc<dyn Interceptor>>,
}

impl SessionContext {
    fn new(
        crypto: NoiseSession,
        config: &NodeConfig,
        dialect: Arc<dyn Dialect>,
        flavor: Arc<dyn Flavor>,
        interceptors: Vec<Arc<dyn Interceptor>>,
        registry: &Arc<PluginRegistry>, // Access to Mods
    ) -> Self {
        let mut reliability = ReliabilityLayer::new(config.multiplexing_mode);

        // Inject Strategies (Mods)
        if let Some(algo) = registry.create_congestion_algo(&config.congestion_algo) {
            reliability.set_congestion_algo(algo);
        } else {
            debug!("Using default congestion algo, ID '{}' not found", config.congestion_algo);
        }

        if let Some(strategy) = registry.create_padding_strategy(&config.padding_strategy) {
            reliability.set_padding_strategy(strategy);
        } else {
            debug!("Using default padding strategy, ID '{}' not found", config.padding_strategy);
        }

        Self {
            crypto,
            reliability,
            shaper: TrafficShaper::new(config.profile),
            side_channels: SideChannelManager::new(),
            handshake_completed: false,
            last_activity: Instant::now(),
            bytes_sent_since_rekey: 0,
            dialect,
            flavor,
            pending_queue: VecDeque::new(),
            interceptors,
        }
    }

    // Interceptor Pipeline
    fn run_ingress_interceptors(&self, stream_id: u32, mut data: Vec<u8>) -> Option<Vec<u8>> {
        let ctx = InterceptorContext { stream_id, is_handshake: self.handshake_completed };
        for interceptor in &self.interceptors {
            match interceptor.on_ingress(&ctx, data) {
                Ok(Some(d)) => data = d,
                Ok(None) => return None, // Dropped by interceptor
                Err(e) => {
                    error!("Interceptor {} ingress error: {}", interceptor.capability_id(), e);
                    return None;
                }
            }
        }
        Some(data)
    }

    fn run_egress_interceptors(&self, stream_id: u32, mut data: Vec<u8>) -> Option<Vec<u8>> {
        let ctx = InterceptorContext { stream_id, is_handshake: self.handshake_completed };
        for interceptor in &self.interceptors {
            match interceptor.on_egress(&ctx, data) {
                Ok(Some(d)) => data = d,
                Ok(None) => return None,
                Err(e) => {
                    error!("Interceptor {} egress error: {}", interceptor.capability_id(), e);
                    return None;
                }
            }
        }
        Some(data)
    }
}

// --- Commands ---

pub enum Command {
    // Legacy support (Stream 1)
    SendData { target: SocketAddr, data: Vec<u8> },
    // New: Explicit Stream Support
    SendStream { target: SocketAddr, stream_id: u32, data: Vec<u8> },
    Connect { target: SocketAddr, remote_pub: Vec<u8> },
    SendOnion { path: Vec<(SocketAddr, Vec<u8>)>, data: Vec<u8> },
    DhtFindNode { target_id: NodeID, reply: oneshot::Sender<Result<Vec<NodeInfo>>> },
    DhtStore { key: NodeID, value: Vec<u8>, ttl: u32 },
    GetStats { reply: oneshot::Sender<String> },
    Shutdown,
}

// --- Handle ---

#[derive(Clone)]
pub struct EtpHandle {
    // Fast path for legacy stream 1
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, 
    cmd_tx: mpsc::Sender<Command>,
}

impl EtpHandle {
    pub async fn send_data(&self, target: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_tx.send((target, data)).await.map_err(|_| anyhow!("Node stopped"))
    }
    
    pub async fn send_stream(&self, target: SocketAddr, id: u32, data: Vec<u8>) -> Result<()> {
        self.cmd_tx.send(Command::SendStream { target, stream_id: id, data }).await.map_err(|_| anyhow!("Node stopped"))
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

    pub async fn get_stats(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(Command::GetStats { reply: tx }).await.map_err(|_| anyhow!("Node stopped"))?;
        rx.await.map_err(|_| anyhow!("Stats dropped"))
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.cmd_tx.send(Command::Shutdown).await.map_err(|_| anyhow!("Node stopped"))
    }
}

// --- Processing Context ---

#[derive(Clone)]
struct ProcessingContext {
    transport: Arc<dyn PacketTransport>, // Abstracted
    config: Arc<NodeConfig>, 
    routing_table: Arc<RoutingTable>,
    sessions: Arc<DashMap<SocketAddr, RwLock<SessionContext>>>,
    nat_manager: Arc<RwLock<NatManager>>,
    acl: Arc<AclManager>,
    plugins: Arc<PluginRegistry>,
    data_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, 
    dht_pending_queries: Arc<DashMap<u64, oneshot::Sender<Result<Vec<NodeInfo>>>>>,
    token_manager: Arc<TokenManager>,
    dht_store: Arc<DashMap<NodeID, (Vec<u8>, std::time::SystemTime)>>,
    metrics: Arc<NodeMetrics>,

    default_handler: Option<Arc<dyn PacketHandler>>,
    fallback_handler: Option<Arc<dyn PacketHandler>>,
}

impl SystemContext for ProcessingContext {
    fn lookup_peer(&self, node_id: &NodeID) -> Option<SocketAddr> {
        self.routing_table.lookup(node_id)
    }
    fn is_connected(&self, addr: SocketAddr) -> bool {
        self.sessions.contains_key(&addr)
    }
    fn my_node_id(&self) -> NodeID {
        blake3::hash(&self.config.keypair.public).into()
    }
}

// --- Engine ---

pub struct EtpEngine {
    ctx: ProcessingContext,
    data_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    cmd_rx: mpsc::Receiver<Command>,
}

impl EtpEngine {
    pub async fn new(mut config: NodeConfig, plugins: Arc<PluginRegistry>) -> Result<(Self, EtpHandle, mpsc::Receiver<(SocketAddr, Vec<u8>)>)> {
        if config.recv_buffer_size == 0 { config.recv_buffer_size = DEFAULT_RECV_BUF; }
        if config.send_buffer_size == 0 { config.send_buffer_size = DEFAULT_SEND_BUF; }
        if config.mtu == 0 { config.mtu = DEFAULT_MTU; }

        // Initialize Transport (UDP Default, Ready for FakeTCP)
        let socket = UdpSocket::bind(&config.bind_addr).await?;
        let _ = socket.set_recv_buffer_size(config.recv_buffer_size);
        let _ = socket.set_send_buffer_size(config.send_buffer_size);
        let transport = Arc::new(UdpTransport(Arc::new(socket)));
        
        info!("ETP Kernel booted on {}. Mode: {:?}. MTU: {}", config.bind_addr, config.multiplexing_mode, config.mtu);

        let token_manager = Arc::new(TokenManager::new(config.stateless_secret));
        let routing_id = blake3::hash(&config.keypair.public).into();
        let routing_table = Arc::new(RoutingTable::new(routing_id));
        
        let (app_tx, data_rx) = mpsc::channel(4096);
        let (data_tx, app_rx) = mpsc::channel(4096);
        let (cmd_tx, cmd_rx) = mpsc::channel(256);

        let nat_mgr = Arc::new(RwLock::new(NatManager::new()));
        
        let ctx = ProcessingContext {
            transport,
            config: Arc::new(config),
            routing_table,
            sessions: Arc::new(DashMap::new()),
            nat_manager: nat_mgr,
            acl: Arc::new(AclManager::new(true)),
            plugins,
            data_tx: app_tx,
            dht_pending_queries: Arc::new(DashMap::new()),
            token_manager,
            dht_store: Arc::new(DashMap::new()),
            metrics: Arc::new(NodeMetrics::default()),
            default_handler: None,
            fallback_handler: None,
        };

        let handle = EtpHandle { data_tx: app_tx, cmd_tx };
        
        let engine = Self {
            ctx,
            data_rx,
            cmd_rx,
        };

        Ok((engine, handle, app_rx))
    }

    pub fn set_default_handler(&mut self, handler: Arc<dyn PacketHandler>) {
        self.ctx.default_handler = Some(handler);
    }

    pub fn set_fallback_handler(&mut self, handler: Arc<dyn PacketHandler>) {
        self.ctx.fallback_handler = Some(handler);
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(DEFAULT_TICK_MS));
        let mut dht_refresh_interval = tokio::time::interval(DHT_REFRESH_INTERVAL);
        let mut recv_buf = vec![0u8; 65535]; 

        loop {
            tokio::select! {
                recv_result = self.ctx.transport.recv_from(&mut recv_buf) => {
                    match recv_result {
                        Ok((len, src)) => {
                            self.ctx.metrics.bytes_ingress.fetch_add(len as u64, Ordering::Relaxed);
                            let data = recv_buf[..len].to_vec();
                            self.spawn_incoming_handler(data, src);
                        }
                        Err(e) => error!("Transport IO Error: {}", e),
                    }
                }
                app_msg = self.data_rx.recv() => {
                    match app_msg {
                        Some((target, data)) => self.handle_app_data(target, 1, data).await, // Stream 1 Default
                        None => break,
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            if matches!(cmd, Command::Shutdown) {
                                self.handle_shutdown().await;
                                break;
                            }
                            self.handle_command(cmd).await;
                        },
                        None => break,
                    }
                }
                _ = tick_interval.tick() => self.handle_tick().await,
                _ = dht_refresh_interval.tick() => self.dht_maintenance().await,
            }
        }
        Ok(())
    }

    fn spawn_incoming_handler(&self, data: Vec<u8>, src: SocketAddr) {
        let ctx = self.ctx.clone();
        tokio::spawn(async move {
            if let Some(handler) = &ctx.default_handler {
                if handler.handle(&data, src, &ctx.transport).await { return; }
            }
            if ctx.sessions.contains_key(&src) {
                Self::process_existing_session(ctx, data, src).await;
            } else {
                Self::process_new_connection_or_fallback(ctx, data, src).await;
            }
        });
    }

    async fn process_existing_session(ctx: ProcessingContext, data: Vec<u8>, src: SocketAddr) {
        let session_lock = match ctx.sessions.get(&src) {
            Some(s) => s,
            None => return,
        };

        let mut session = session_lock.write();
        session.last_activity = Instant::now();

        if session.dialect.probe(&data) {
            if let Ok(plain_data) = session.dialect.open(&data) {
                if !session.handshake_completed {
                    let mut out = acquire_buffer();
                    out.resize(1024, 0);
                    
                    if let Ok((len, fin)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                        if let Some(pubk) = session.crypto.get_remote_static() {
                            if !ctx.acl.allow_connection(pubk) { 
                                ctx.metrics.packet_drop_acl.fetch_add(1, Ordering::Relaxed);
                                return; 
                            }
                        }
                        if len > 0 {
                            let mut resp = out[..len].to_vec();
                            session.dialect.seal(&mut resp);
                            let _ = ctx.transport.send_to(&resp, src).await;
                        }
                        if !fin {
                            if let Ok((wlen, wfin)) = session.crypto.write_handshake_message(&[], &mut out) {
                                if wlen > 0 {
                                    let mut resp = out[..wlen].to_vec();
                                    session.dialect.seal(&mut resp);
                                    let _ = ctx.transport.send_to(&resp, src).await;
                                }
                                if wfin { session.handshake_completed = true; }
                            }
                        } else {
                            session.handshake_completed = true;
                        }
                        if session.handshake_completed {
                            ctx.metrics.handshake_success.fetch_add(1, Ordering::Relaxed);
                            session.flavor.on_connection_open(src);
                            let pending = std::mem::take(&mut session.pending_queue);
                            drop(session);
                            release_buffer(out);
                            Self::flush_pending_frames(ctx, src, pending).await;
                            return;
                        }
                    }
                    release_buffer(out);
                    return;
                } 
                
                let mut plaintext_buf = acquire_buffer();
                plaintext_buf.resize(plain_data.len(), 0);

                if let Ok(len) = session.crypto.decrypt(&plain_data, &mut plaintext_buf) {
                    plaintext_buf.truncate(len);
                    if let Ok(pkt) = bincode::DefaultOptions::new().allow_trailing_bytes().deserialize::<StatefulPacket>(&plaintext_buf) {
                        if pkt.session_id != 0 {
                            // Reliability Layer returns reassembled chunks with StreamID
                            let (dup, chunks) = session.reliability.on_packet_received(pkt.packet_number, pkt.frames.clone());
                            if dup { 
                                release_buffer(plaintext_buf);
                                return; 
                            }
                            
                            // Process NON-Stream Frames first
                            for frame in pkt.frames {
                                match frame {
                                    Frame::Ack { largest_acknowledged, ranges, .. } => session.reliability.on_ack_frame_received(largest_acknowledged, &ranges),
                                    Frame::Close { .. } => info!("Session closed by {}", src),
                                    Frame::Injection { .. } => {
                                        if ctx.acl.verify_frame(&frame).unwrap_or(false) {}
                                    }
                                    _ => {}
                                }
                            }

                            // Process Stream Data via Interceptors then Flavor
                            for (stream_id, chunk_data) in chunks {
                                if let Some(processed) = session.run_ingress_interceptors(stream_id, chunk_data) {
                                    let f_ctx = FlavorContext { 
                                        src_addr: src, 
                                        stream_id, 
                                        data_len: processed.len(), 
                                        system: &ctx 
                                    };
                                    if !session.flavor.on_stream_data(f_ctx, &processed) {
                                        // Legacy: Stream 1 fallback to channel
                                        if stream_id == 1 {
                                            let _ = ctx.data_tx.send((src, processed)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                release_buffer(plaintext_buf);
                return;
            }
        }
        ctx.metrics.packet_drop_format.fetch_add(1, Ordering::Relaxed);
    }

    async fn process_new_connection_or_fallback(ctx: ProcessingContext, data: Vec<u8>, src: SocketAddr) {
        let mut handled = false;
        let mut candidates = Vec::new();
        if let Some(def) = ctx.plugins.get_dialect(&ctx.config.default_dialect) {
            candidates.push(def);
        }
        let others = ctx.plugins.all_dialects();
        for d in others {
            if d.capability_id() != ctx.config.default_dialect {
                candidates.push(d);
            }
        }

        for dialect in candidates {
            if !dialect.probe(&data) { continue; }
            let plain_data = match dialect.open(&data) { Ok(d) => d, Err(_) => continue };

            if let Ok(pkt) = bincode::deserialize::<StatelessPacket>(&plain_data) {
                if ctx.token_manager.validate_token(&pkt.token) {
                    Self::handle_stateless_packet(pkt, src, &ctx).await;
                    handled = true;
                    break;
                }
            }

            if ctx.sessions.len() >= ctx.config.max_sessions { return; }

            let default_flavor = ctx.plugins.get_flavor(&ctx.config.default_flavor).unwrap_or(Arc::new(crate::plugin::StandardFlavor));
            
            // Load Default Interceptors
            let interceptors = ctx.plugins.get_default_interceptors();

            let mut session = SessionContext::new(
                NoiseSession::new_responder(&ctx.config.keypair).unwrap(),
                &ctx.config,
                dialect.clone(), 
                default_flavor.clone(),
                interceptors,
                &ctx.plugins
            );

            let mut out = acquire_buffer();
            out.resize(1024, 0);

            if let Ok((_len, finished)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                if let Some(pubk) = session.crypto.get_remote_static() {
                    if !ctx.acl.allow_connection(pubk) {
                        ctx.metrics.packet_drop_acl.fetch_add(1, Ordering::Relaxed);
                        release_buffer(out);
                        return;
                    }
                }
                if let Ok((wlen, wfin)) = session.crypto.write_handshake_message(&[], &mut out) {
                    if wlen > 0 {
                        let mut resp = out[..wlen].to_vec();
                        dialect.seal(&mut resp);
                        let _ = ctx.transport.send_to(&resp, src).await;
                    }
                    session.handshake_completed = wfin || finished;
                    if session.handshake_completed {
                        ctx.metrics.handshake_success.fetch_add(1, Ordering::Relaxed);
                        session.flavor.on_connection_open(src);
                    }
                    ctx.sessions.insert(src, RwLock::new(session));
                    ctx.metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
                    handled = true;
                    release_buffer(out);
                    break;
                }
            }
            release_buffer(out);
        }

        if handled { return; }
        if let Some(handler) = &ctx.fallback_handler {
            handler.handle(&data, src, &ctx.transport).await;
        }
    }

    async fn handle_stateless_packet(pkt: StatelessPacket, src: SocketAddr, ctx: &ProcessingContext) {
        for frame in pkt.frames {
            match frame {
                Frame::SideChannel { channel_id: 0, data } => {
                    if let Ok(decrypted_payload) = Self::decrypt_stateless_payload(&data, pkt.nonce, &ctx.config.stateless_secret) {
                        Self::handle_dht_rpc(decrypted_payload, src, ctx).await;
                    }
                },
                Frame::NatSignal { signal_type: NatSignalType::Ping, .. } => {
                    let pong = Frame::NatSignal { signal_type: NatSignalType::Pong, payload: vec![] };
                    let _ = Self::send_stateless_packet_internal(ctx, src, vec![pong]).await;
                },
                _ => {}
            }
        }
    }

    async fn handle_command(&self, cmd: Command) {
        match cmd {
            Command::SendData { target, data } => self.handle_app_data(target, 1, data).await,
            Command::SendStream { target, stream_id, data } => self.handle_app_data(target, stream_id, data).await,
            Command::Connect { target, remote_pub } => {
                let _ = self.initiate_handshake(target, &remote_pub).await;
            },
            Command::SendOnion { path, data } => {
                let _ = self.handle_onion_send(path, data).await;
            },
            Command::DhtFindNode { target_id, reply } => {
                let nonce = rand::random::<u64>();
                self.ctx.dht_pending_queries.insert(nonce, reply);
                let neighbors = self.ctx.routing_table.find_closest(&target_id, 3);
                for node in neighbors {
                    let mut payload = vec![0x01]; 
                    payload.extend_from_slice(&nonce.to_be_bytes());
                    payload.extend_from_slice(&target_id);
                    let frame = Frame::SideChannel { channel_id: 0, data: payload };
                    let _ = Self::send_stateless_packet_internal(&self.ctx, node.addr, vec![frame]).await;
                }
            },
            Command::DhtStore { key, value, ttl } => {
                let neighbors = self.ctx.routing_table.find_closest(&key, 5);
                for node in neighbors {
                    let mut payload = vec![0x02]; 
                    payload.extend_from_slice(&key);
                    payload.extend_from_slice(&ttl.to_be_bytes());
                    payload.extend_from_slice(&value);
                    let frame = Frame::SideChannel { channel_id: 0, data: payload };
                    let _ = Self::send_stateless_packet_internal(&self.ctx, node.addr, vec![frame]).await;
                }
            },
            Command::GetStats { reply } => {
                let m = &self.ctx.metrics;
                let s = format!("Sessions: {}", m.active_sessions.load(Ordering::Relaxed));
                let _ = reply.send(s);
            },
            Command::Shutdown => {} 
        }
    }

    async fn handle_shutdown(&self) {
        info!("Shutting down...");
        for entry in self.ctx.sessions.iter() {
            let addr = *entry.key();
            let frame = Frame::Close { error_code: 0, reason: "Shutdown".into() };
            let _ = self.send_frames(addr, vec![frame]).await;
        }
    }

    async fn handle_app_data(&self, target: SocketAddr, stream_id: u32, data: Vec<u8>) {
        let frame = Frame::Stream { stream_id, offset: 0, fin: false, data };
        
        if self.ctx.sessions.contains_key(&target) {
            let _ = self.send_frames(target, vec![frame]).await;
        } else {
            if let Err(_) = self.initiate_handshake(target, &[0u8; 32]).await {
               warn!("Auto-connect failed");
            } else {
                if let Some(s) = self.ctx.sessions.get(&target) {
                    s.write().pending_queue.push_back(frame);
                }
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

        if !ctx.reliability.can_send() { return Err(anyhow!("Congestion")); }
        
        // Apply Egress Interceptors
        let mut processed_frames = Vec::new();
        for frame in frames {
            match frame {
                Frame::Stream { stream_id, offset, fin, data } => {
                    if let Some(mod_data) = ctx.run_egress_interceptors(stream_id, data) {
                        processed_frames.push(Frame::Stream { stream_id, offset, fin, data: mod_data });
                    }
                },
                _ => processed_frames.push(frame),
            }
        }

        let mut side_frames = ctx.side_channels.pop_outgoing_frames(self.ctx.config.mtu - 100);
        processed_frames.append(&mut side_frames);
        if processed_frames.is_empty() { return Ok(()); }

        // Pacing & Padding
        if let Some(delay) = ctx.shaper.wait_for_slot().await {
             if delay > 0 {
                 processed_frames.push(Frame::new_padding(delay));
             }
        } else {
             // Dynamic Padding Strategy (Mod)
             let current_size: usize = processed_frames.iter().map(|_| 100).sum();
             let padding_size = ctx.reliability.calculate_padding(current_size);
             if padding_size > 0 {
                 processed_frames.push(Frame::new_padding(padding_size));
             }
        }

        let pn = ctx.reliability.get_next_packet_num();
        let est_size: usize = processed_frames.iter().map(|_| 100).sum();
        ctx.reliability.on_packet_sent(pn, processed_frames.clone(), est_size);

        let packet = DecryptedPacket::Stateful(StatefulPacket {
            session_id: 1, 
            packet_number: pn,
            frames: processed_frames,
        });

        let raw = RawPacket::encrypt_and_seal(&packet, &mut ctx.crypto, None, ctx.dialect.as_ref())?;
        
        ctx.bytes_sent_since_rekey += raw.data.len() as u64;
        if ctx.bytes_sent_since_rekey > REKEY_BYTES_LIMIT {
            let _ = ctx.crypto.rekey();
            ctx.bytes_sent_since_rekey = 0;
        }

        self.ctx.transport.send_to(&raw.data, target).await?;
        self.ctx.metrics.bytes_egress.fetch_add(raw.data.len() as u64, Ordering::Relaxed);
        ctx.last_activity = Instant::now();
        Ok(())
    }

    async fn initiate_handshake(&self, target: SocketAddr, remote_pub: &[u8]) -> Result<()> {
        let d_dial = self.ctx.plugins.get_dialect(&self.ctx.config.default_dialect).unwrap();
        let d_flav = self.ctx.plugins.get_flavor(&self.ctx.config.default_flavor).unwrap();
        let interceptors = self.ctx.plugins.get_default_interceptors();
        
        let mut session = SessionContext::new(
             NoiseSession::new_initiator(&self.ctx.config.keypair, remote_pub)?,
             &self.ctx.config, d_dial, d_flav, interceptors, &self.ctx.plugins
        );
        let mut buf = acquire_buffer();
        buf.resize(1024, 0);
        let (len, _) = session.crypto.write_handshake_message(&[], &mut buf)?;
        
        self.ctx.transport.send_to(&buf[..len], target).await?;
        self.ctx.sessions.insert(target, RwLock::new(session));
        self.ctx.metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
        release_buffer(buf);
        Ok(())
    }

    async fn flush_pending_frames(ctx: ProcessingContext, target: SocketAddr, mut frames: VecDeque<Frame>) {
        if let Some(s) = ctx.sessions.get(&target) {
            let mut session = s.write();
            let mut batch = Vec::new();
            while let Some(f) = frames.pop_front() {
                batch.push(f);
                if batch.len() >= 5 {
                    let pn = session.reliability.get_next_packet_num();
                    session.reliability.on_packet_sent(pn, batch.clone(), 500);
                    let pkt = DecryptedPacket::Stateful(StatefulPacket { session_id: 1, packet_number: pn, frames: batch.clone() });
                    if let Ok(raw) = RawPacket::encrypt_and_seal(&pkt, &mut session.crypto, None, session.dialect.as_ref()) {
                        let _ = ctx.transport.send_to(&raw.data, target).await;
                    }
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                 let pn = session.reliability.get_next_packet_num();
                 session.reliability.on_packet_sent(pn, batch.clone(), 500);
                 let pkt = DecryptedPacket::Stateful(StatefulPacket { session_id: 1, packet_number: pn, frames: batch });
                 if let Ok(raw) = RawPacket::encrypt_and_seal(&pkt, &mut session.crypto, None, session.dialect.as_ref()) {
                     let _ = ctx.transport.send_to(&raw.data, target).await;
                 }
            }
        }
    }

    async fn send_stateless_packet_internal(ctx: &ProcessingContext, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        let token = ctx.token_manager.generate_token();
        let nonce = rand::random::<u64>();
        let packet = StatelessPacket { token, nonce, frames };
        let plain = bincode::serialize(&packet)?;
        let default_dialect = ctx.plugins.get_dialect(&ctx.config.default_dialect).unwrap();
        let mut masked = plain;
        default_dialect.seal(&mut masked);
        ctx.transport.send_to(&masked, target).await?;
        Ok(())
    }

    async fn handle_dht_rpc(data: Vec<u8>, _src: SocketAddr, _ctx: &ProcessingContext) {
        if data.is_empty() { return; }
    }

    async fn handle_onion_send(&self, _path: Vec<(SocketAddr, Vec<u8>)>, _data: Vec<u8>) -> Result<()> {
        Ok(())
    }

    async fn handle_tick(&self) {
        let mut remove_list = Vec::new();
        let mut tasks = Vec::new();
        let timeout = self.ctx.config.session_timeout;

        for entry in self.ctx.sessions.iter() {
            let target = *entry.key();
            if entry.value().read().last_activity.elapsed() > timeout {
                remove_list.push(target);
                continue;
            }
            let mut ctx = entry.value().write();
            ctx.side_channels.maintenance();
            if !ctx.handshake_completed { continue; }

            let mut frames = Vec::new();
            frames.append(&mut ctx.reliability.get_lost_frames());
            if ctx.reliability.should_send_ack() { frames.push(ctx.reliability.generate_ack()); }
            
            if frames.is_empty() && ctx.last_activity.elapsed() > DEFAULT_KEEPALIVE {
                frames.push(Frame::new_padding(10));
            }
            
            ctx.flavor.poll();
            if !frames.is_empty() { tasks.push((target, frames)); }
        }

        for target in remove_list {
            self.ctx.sessions.remove(&target);
            self.ctx.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }

        for (t, f) in tasks { let _ = self.send_frames(t, f).await; }
    }
    
    async fn dht_maintenance(&self) {}

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
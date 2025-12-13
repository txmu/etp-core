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
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace}; 
use chacha20poly1305::aead::{Aead, Payload};
use blake3;

// 引入各模块
use crate::crypto::onion::OnionCrypto;
use crate::crypto::noise::{KeyPair, NoiseSession};
use crate::wire::packet::{RawPacket, DecryptedPacket, StatefulPacket, StatelessPacket, TokenManager};
// Dialect 定义已移至 plugin
use crate::plugin::{Dialect, Flavor, FlavorContext, PluginRegistry, CapabilityProvider, SystemContext}; 
use crate::wire::frame::{Frame, NatSignalType, InjectionCommand};
use crate::transport::shaper::{TrafficShaper, SecurityProfile};
use crate::transport::reliability::ReliabilityLayer;
use crate::transport::side_channel::{SideChannelManager, SideChannelPolicy, ChannelMode};
use crate::transport::injection::AclManager;
use crate::network::discovery::{RoutingTable, DhtAddResult}; 
use crate::network::nat::NatManager;
use crate::common::NodeInfo;
use crate::NodeID;

// --- 生产级常量 ---
const TICK_INTERVAL_MS: u64 = 20; 
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const REKEY_BYTES_LIMIT: u64 = 512 * 1024 * 1024; // 512MB
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const DHT_REFRESH_INTERVAL: Duration = Duration::from_secs(300); 
const MTU: usize = 1350;
const MAX_PENDING_FRAMES: usize = 1000; 

// --- 配置 ---
#[derive(Clone)]
pub struct NodeConfig {
    pub bind_addr: String,
    pub keypair: KeyPair,
    pub profile: SecurityProfile,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub default_dialect: String,
    pub default_flavor: String,
    pub stateless_secret: [u8; 32], 
}

// --- 会话上下文 ---
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

// --- 处理上下文 (实现 SystemContext) ---
#[derive(Clone)]
struct ProcessingContext {
    socket: Arc<UdpSocket>,
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
}

// ★ 实现 SystemContext Trait，赋能 Flavor
impl SystemContext for ProcessingContext {
    fn lookup_peer(&self, node_id: &NodeID) -> Option<SocketAddr> {
        self.routing_table.lookup(node_id)
    }

    fn is_connected(&self, addr: SocketAddr) -> bool {
        self.sessions.contains_key(&addr)
    }
    
    fn my_node_id(&self) -> NodeID {
        // 计算自己的 NodeID (通常应缓存，这里实时计算以简化状态)
        blake3::hash(&self.config.keypair.public).into()
    }
}

// --- 核心引擎 ---
pub struct EtpEngine {
    ctx: ProcessingContext,
    data_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    cmd_rx: mpsc::Receiver<Command>,
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
            dht_store: Arc::new(DashMap::new()),
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
                recv_result = self.ctx.socket.recv_from(&mut recv_buf) => {
                    match recv_result {
                        Ok((len, src)) => {
                            let data = recv_buf[..len].to_vec();
                            self.spawn_incoming_handler(data, src);
                        }
                        Err(e) => error!("UDP IO Error: {}", e),
                    }
                }
                app_msg = self.data_rx.recv() => {
                    match app_msg {
                        Some((target, data)) => self.handle_app_data(target, data).await,
                        None => { info!("App shutdown"); break; }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => break,
                    }
                }
                _ = tick_interval.tick() => self.handle_tick().await,
                _ = dht_refresh_interval.tick() => self.dht_maintenance().await,
            }
        }
        Ok(())
    }

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
    
    fn spawn_incoming_handler(&self, data: Vec<u8>, src: SocketAddr) {
        let ctx = self.ctx.clone();

        tokio::spawn(async move {
            if let Some(session_lock) = ctx.sessions.get(&src) {
                let mut session = session_lock.write();
                session.last_activity = Instant::now();

                let mut candidates = Vec::with_capacity(ctx.plugins.all_dialects().len() + 1);
                candidates.push(session.dialect.clone()); 

                let all_dialects = ctx.plugins.all_dialects();
                for d in all_dialects {
                    if d.capability_id() != session.dialect.capability_id() {
                        candidates.push(d); 
                    }
                }

                for dialect in candidates {
                    if !dialect.probe(&data) { continue; }

                    let plain_data = match dialect.open(&data) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    if !session.handshake_completed {
                        let mut out = vec![0u8; 1024];
                        if let Ok((len, fin)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                            if dialect.capability_id() != session.dialect.capability_id() {
                                info!("Session {} dialect corrected to: {} (handshake)", src, dialect.capability_id());
                                session.dialect = dialect.clone();
                            }

                            if let Some(pubk) = session.crypto.get_remote_static() {
                                if !ctx.acl.allow_connection(pubk) { 
                                    warn!("ACL rejected connection from {}", src);
                                    return; 
                                } 
                            }

                            if len > 0 { 
                                let mut resp = out[..len].to_vec();
                                session.dialect.seal(&mut resp);
                                let _ = ctx.socket.send_to(&resp, src).await; 
                            }
                            
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

                            if session.handshake_completed {
                                let offer = ctx.plugins.negotiator.generate_offer(session.crypto.get_handshake_hash());
                                let offer_bytes = bincode::serialize(&offer).unwrap_or_default();
                                let frame = Frame::Negotiate { 
                                    protocol_version: 1, 
                                    zkp_proof: vec![], 
                                    flavor_bitmap: offer_bytes 
                                };
                                session.pending_queue.push_front(frame);
                                session.flavor.on_connection_open(src);
                                drop(session); 
                                Self::flush_pending(ctx.clone(), src).await;
                                return;
                            }
                            return;
                        }
                    } else {
                        let mut plaintext = vec![0u8; plain_data.len()];
                        if let Ok(len) = session.crypto.decrypt(&plain_data, &mut plaintext) {
                            plaintext.truncate(len);

                            if dialect.capability_id() != session.dialect.capability_id() {
                                info!("Session {} dialect corrected to: {} (transport)", src, dialect.capability_id());
                                session.dialect = dialect.clone();
                            }

                            if let Ok(pkt) = bincode::DefaultOptions::new()
                                .allow_trailing_bytes()
                                .deserialize::<StatefulPacket>(&plaintext) 
                            {
                                if pkt.session_id != 0 {
                                    if session.reliability.on_packet_received(pkt.packet_number) { return; } 
                                    for frame in pkt.frames {
                                        Self::process_frame(frame, src, &mut session, &ctx).await;
                                    }
                                    return; 
                                }
                            }
                        }
                    }
                }
                return; 
            }

            let mut candidates = Vec::new();
            let default_dialect_id = &ctx.config.default_dialect;
            if let Some(def) = ctx.plugins.get_dialect(default_dialect_id) {
                candidates.push(def);
            }
            let others = ctx.plugins.all_dialects();
            for d in others {
                if d.capability_id() != *default_dialect_id {
                    candidates.push(d);
                }
            }

            for dialect in candidates {
                if !dialect.probe(&data) { continue; }

                let plain_data = match dialect.open(&data) {
                    Ok(d) => d,
                    Err(_) => continue, 
                };

                if let Ok(pkt) = bincode::deserialize::<StatelessPacket>(&plain_data) {
                    if ctx.token_manager.validate_token(&pkt.token) {
                        for frame in pkt.frames {
                            match frame {
                                Frame::SideChannel { channel_id: 0, data } => {
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
                        return;
                    }
                }

                let default_flavor = ctx.plugins.get_flavor(&ctx.config.default_flavor)
                    .unwrap_or(Arc::new(crate::plugin::StandardFlavor));

                let mut session = SessionContext::new(
                    NoiseSession::new_responder(&ctx.config.keypair).unwrap(),
                    ctx.config.profile,
                    dialect.clone(), 
                    default_flavor.clone()
                );

                let mut out = vec![0u8; 1024];
                if let Ok((_len, finished)) = session.crypto.read_handshake_message(&plain_data, &mut out) {
                    if let Some(pubk) = session.crypto.get_remote_static() {
                        if !ctx.acl.allow_connection(pubk) { return; } 
                    }

                    if let Ok((wlen, wfin)) = session.crypto.write_handshake_message(&[], &mut out) {
                        if wlen > 0 { 
                            let mut resp = out[..wlen].to_vec();
                            dialect.seal(&mut resp);
                            let _ = ctx.socket.send_to(&resp, src).await; 
                        }
                        
                        session.handshake_completed = wfin || finished;
                        if session.handshake_completed {
                            session.flavor.on_connection_open(src);
                        }
                        ctx.sessions.insert(src, RwLock::new(session));
                        return;
                    }
                }
            }
        });
    }

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
                // ★ 注入 SystemContext
                let f_ctx = FlavorContext { 
                    src_addr: src, 
                    stream_id, 
                    data_len: data.len(), 
                    system: ctx // 传入 ProcessingContext
                };
                if !session.flavor.on_stream_data(f_ctx, &data) {
                    let ordered = session.reliability.reassembler.push(offset, data);
                    if !ordered.is_empty() { 
                        let _ = ctx.data_tx.send((src, ordered)).await; 
                    }
                }
            }
            Frame::SideChannel { channel_id, data } => {
                if session.side_channels.on_frame_received(channel_id, data.clone()) {
                    if channel_id < 100 {
                    } else {
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
                    let _ = ctx.routing_table.add_node(n); 
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
    
    async fn handle_dht_rpc(data: Vec<u8>, src: SocketAddr, ctx: &ProcessingContext) {
        if data.is_empty() { return; }
        match data[0] {
            0x01 => { // CMD_FIND (Query)
                if data.len() < 41 { return; }
                let mut nonce = [0u8; 8]; nonce.copy_from_slice(&data[1..9]);
                let mut target = [0u8; 32]; target.copy_from_slice(&data[9..41]);
                
                let closest = ctx.routing_table.find_closest(&target, 10);
                
                let mut resp_payload = vec![0x81];
                resp_payload.extend_from_slice(&nonce);
                resp_payload.extend(bincode::serialize(&closest).unwrap_or_default());
                
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
                if data.len() < 37 { 
                    warn!("DHT: Malformed STORE packet from {}", src);
                    return; 
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[1..33]);
                let ttl_bytes: [u8; 4] = data[33..37].try_into().unwrap();
                let request_ttl = u32::from_be_bytes(ttl_bytes);
                let value = data[37..].to_vec();

                const MAX_DHT_VALUE_SIZE: usize = 64 * 1024;
                if value.len() > MAX_DHT_VALUE_SIZE { return; }

                const MAX_TTL_SECS: u32 = 86400 * 7;
                let effective_ttl = std::cmp::min(request_ttl, MAX_TTL_SECS);
                let expiration = std::time::SystemTime::now()
                    .checked_add(std::time::Duration::from_secs(effective_ttl as u64))
                    .unwrap_or(std::time::SystemTime::now());

                ctx.dht_store.insert(key, (value, expiration));

                let mut ack_payload = Vec::with_capacity(34);
                ack_payload.push(0x82); 
                ack_payload.extend_from_slice(&key);
                ack_payload.push(0x00); 

                if let Err(e) = Self::send_stateless_resp(ctx, src, ack_payload).await {
                    debug!("DHT: Failed to send STORE_ACK to {}: {}", src, e);
                }
            }
            _ => {}
        }
    }

    async fn handle_app_data(&self, target: SocketAddr, data: Vec<u8>) {
        let frame = Frame::Stream { stream_id: 1, offset: 0, fin: false, data };
        
        if self.sessions.contains_key(&target) {
            let _ = self.send_frames(target, vec![frame]).await;
        } else {
            info!("On-demand connect to {}", target);
            let default_dialect = self.ctx.plugins.get_dialect(&self.ctx.config.default_dialect).unwrap();
            let default_flavor = self.ctx.plugins.get_flavor(&self.ctx.config.default_flavor).unwrap();

            let mut session = SessionContext::new(
                 NoiseSession::new_initiator(&self.ctx.config.keypair, &[0u8; 32]).unwrap(), 
                 self.ctx.config.profile, default_dialect, default_flavor
            );
            session.pending_queue.push_back(frame);
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

        if !ctx.reliability.can_send() { return Err(anyhow!("Congestion")); }
        
        let mut out_frames = frames;
        let mut side_frames = ctx.side_channels.pop_outgoing_frames(MTU - 100);
        out_frames.append(&mut side_frames);
        if out_frames.is_empty() { return Ok(()); }

        if let Some(delay) = ctx.shaper.wait_time() {
            if delay > Duration::ZERO {
                drop(ctx); 
                let this = self.ctx.clone(); 
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Some(s_ref) = this.sessions.get(&target) {
                        let _c = s_ref.write();
                    }
                });
                return Ok(());
            }
        }

        let pn = ctx.reliability.get_next_packet_num();
        let est_size: usize = out_frames.iter().map(|_| 100).sum(); 
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
        let _ = self.send_stateless_packet_internal(&self.ctx, target, frames).await;
        Ok(())
    }
    
    // Internal helper that takes context explicitly
    async fn send_stateless_packet_internal(ctx: &ProcessingContext, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        let token = ctx.token_manager.generate_token();
        let nonce = rand::random::<u64>();
        let packet = StatelessPacket { token, nonce, frames };
        
        let plain = bincode::serialize(&packet)?;
        
        let default_dialect = ctx.plugins.get_dialect(&ctx.config.default_dialect).unwrap();
        let mut masked = plain;
        default_dialect.seal(&mut masked);
        
        ctx.socket.send_to(&masked, target).await?;
        Ok(())
    }
    
    async fn send_stateless_resp(ctx: &ProcessingContext, target: SocketAddr, frames: Vec<Frame>) -> Result<()> {
        let nonce = rand::random::<u64>();
        
        if let Some(Frame::SideChannel { channel_id: 0, data }) = frames.first() {
             let encrypted_data = Self::encrypt_stateless_payload(data, nonce, &ctx.config.stateless_secret)?;
             let new_frame = Frame::SideChannel { channel_id: 0, data: encrypted_data };
             
             let token = ctx.token_manager.generate_token();
             let packet = StatelessPacket { token, nonce, frames: vec![new_frame] };
             let raw = bincode::serialize(&packet)?;
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
        
        if !self.sessions.contains_key(first_addr) {
            self.initiate_handshake(*first_addr, first_pub).await?;
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
        let count = self.ctx.routing_table.total_nodes();
        if count > 0 {
            let peers = self.ctx.routing_table.get_random_peers(3);
            for p in peers {
                let _ = Self::send_stateless_packet_internal(&self.ctx, p.addr, vec![Frame::new_padding(10)]).await;
            }
        }
    }

    async fn flush_pending(ctx: ProcessingContext, target: SocketAddr) {
        if let Some(s) = ctx.sessions.get(&target) {
            let mut session = s.write();
            while let Some(frame) = session.pending_queue.pop_front() {
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
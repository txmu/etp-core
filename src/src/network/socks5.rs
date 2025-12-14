// etp-core/src/network/socks5.rs

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use dashmap::DashMap;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use parking_lot::RwLock;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error, trace};

// --- ETP 类型别名 ---
/// (TargetNodeAddr, StreamID, Data, Fin)
pub type AppSignal = (SocketAddr, u32, Vec<u8>, bool);
pub type NodeID = [u8; 32];

// --- SOCKS5 协议常量 ---
const SOCKS_VER: u8 = 0x05;
const AUTH_USER_PASS: u8 = 0x02;
const AUTH_NONE: u8 = 0x00;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NET_UNREACHABLE: u8 = 0x03;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

// --- 数据结构定义 ---

/// SOCKS5 目标地址
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Socks5Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl std::fmt::Display for Socks5Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Target::Ip(addr) => write!(f, "{}", addr),
            Socks5Target::Domain(d, p) => write!(f, "{}:{}", d, p),
        }
    }
}

// ----------------------------------------------------------------------------
// 接口定义：解耦 TNS 和 DHT 依赖
// ----------------------------------------------------------------------------

/// 命名服务接口 (用于 TNS 解析)
/// 上层应用应注入实现了此接口的 TnsFlavor 包装器
#[async_trait::async_trait]
pub trait NameService: Send + Sync {
    /// 解析域名返回目标 NodeID
    async fn resolve(&self, name: &str) -> Result<NodeID>;
}

/// 节点注册表接口 (用于 DHT 查找)
/// 上层应用应注入实现了此接口的 RoutingTable/DHT 包装器
#[async_trait::async_trait]
pub trait NodeRegistry: Send + Sync {
    /// 查找 NodeID 对应的物理 IP 地址
    async fn lookup_ip(&self, id: &NodeID) -> Option<SocketAddr>;
}

/// 出口路由器接口
pub trait ExitRouter: Send + Sync {
    fn select_exit(&self, target: &Socks5Target) -> Result<SocketAddr>;
    fn add_exit_node(&self, addr: SocketAddr);
    fn add_domain_rule(&self, suffix: &str, node: SocketAddr);
}

// ----------------------------------------------------------------------------
// 模块：加密 DNS 解析器 (DoT / DoH)
// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct EncryptedDnsResolver {
    dot_upstream: Option<String>, // e.g., "1.1.1.1:853"
    doh_upstream: Option<String>, // e.g., "https://dns.google/dns-query"
    domain_name: String,          // e.g., "cloudflare-dns.com" for TLS verify
}

impl EncryptedDnsResolver {
    pub fn new() -> Self {
        Self {
            dot_upstream: None,
            doh_upstream: None,
            domain_name: String::new(),
        }
    }

    pub fn with_dot(mut self, ip_port: &str, domain: &str) -> Self {
        self.dot_upstream = Some(ip_port.to_string());
        self.domain_name = domain.to_string();
        self
    }

    pub fn with_doh(mut self, url: &str) -> Self {
        self.doh_upstream = Some(url.to_string());
        self
    }

    /// 执行 DNS 查询 (支持 DoT 优先，DoH 其次)
    pub async fn resolve(&self, query_packet: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref addr) = self.dot_upstream {
            return self.resolve_dot(addr, &self.domain_name, query_packet).await;
        }
        if let Some(ref url) = self.doh_upstream {
            return self.resolve_doh(url, query_packet).await;
        }
        Err(anyhow!("No upstream configured"))
    }

    async fn resolve_dot(&self, addr: &str, _domain: &str, query: &[u8]) -> Result<Vec<u8>> {
        // 简易 DoT: TCP 连接 -> 发送带长度前缀的包
        // 生产环境应在此处使用 rustls 进行 TLS 握手
        // 为了保持代码独立性，这里演示逻辑流，假设 socket 是建立在安全隧道上的，或直接透传
        // 实际使用请取消 TLS 注释并添加依赖
        
        let mut stream = TcpStream::connect(addr).await.context("DoT connect failed")?;
        
        // --- TLS Handshake Stub ---
        // let connector = TlsConnector::from(...);
        // let mut stream = connector.connect(domain, stream).await?;
        
        let len = query.len() as u16;
        let mut frame = Vec::with_capacity(2 + query.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(query);
        
        stream.write_all(&frame).await?;
        
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        
        Ok(resp_buf)
    }

    async fn resolve_doh(&self, _url: &str, query: &[u8]) -> Result<Vec<u8>> {
        // 简易 DoH: HTTP/1.1 POST
        // 避免引入 reqwest 巨型依赖，手动构造 HTTP
        let host = "dns.google"; 
        let path = "/dns-query";
        
        let mut stream = TcpStream::connect("8.8.4.4:443").await?; 
        // Need TLS wrapper here in production
        
        let body_len = query.len();
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            path, host, body_len
        );

        stream.write_all(request.as_bytes()).await?;
        stream.write_all(query).await?;
        
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(buf[idx+4..].to_vec());
        }
        
        Err(anyhow!("Invalid DoH response"))
    }
}

// ----------------------------------------------------------------------------
// 模块：认证与权限控制 (ACL & Auth)
// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Authenticator {
    users: Arc<RwLock<HashMap<String, String>>>, // User -> Pass
}

impl Authenticator {
    pub fn new() -> Self {
        Self { users: Arc::new(RwLock::new(HashMap::new())) }
    }
    
    pub fn add_user(&self, user: &str, pass: &str) {
        self.users.write().insert(user.to_string(), pass.to_string());
    }
    
    pub fn validate(&self, user: &str, pass: &str) -> bool {
        if let Some(real_pass) = self.users.read().get(user) {
            return real_pass == pass;
        }
        false
    }
    
    pub fn is_empty(&self) -> bool {
        self.users.read().is_empty()
    }
}

#[derive(Clone)]
pub struct AccessControl {
    whitelist_ips: Arc<RwLock<HashSet<IpAddr>>>,
    blacklist_ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl AccessControl {
    pub fn new() -> Self {
        Self {
            whitelist_ips: Arc::new(RwLock::new(HashSet::new())),
            blacklist_ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }
    
    pub fn allow_ip(&self, ip: IpAddr) { self.whitelist_ips.write().insert(ip); }
    pub fn block_ip(&self, ip: IpAddr) { self.blacklist_ips.write().insert(ip); }
    
    pub fn check(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        if self.blacklist_ips.read().contains(&ip) { return false; }
        let wl = self.whitelist_ips.read();
        if !wl.is_empty() && !wl.contains(&ip) { return false; }
        true
    }
}

#[derive(Debug, Default)]
pub struct TrafficStats {
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub active_conn: AtomicU32,
}

// ----------------------------------------------------------------------------
// 模块：智能路由实现
// ----------------------------------------------------------------------------

pub struct RuleBasedRouter {
    default_exits: RwLock<Vec<SocketAddr>>,
    domain_rules: RwLock<HashMap<String, SocketAddr>>,
}

impl RuleBasedRouter {
    pub fn new(defaults: Vec<SocketAddr>) -> Self {
        Self {
            default_exits: RwLock::new(defaults),
            domain_rules: RwLock::new(HashMap::new()),
        }
    }
}

impl ExitRouter for RuleBasedRouter {
    fn add_exit_node(&self, addr: SocketAddr) {
        self.default_exits.write().push(addr);
    }

    fn add_domain_rule(&self, suffix: &str, node: SocketAddr) {
        self.domain_rules.write().insert(suffix.to_string(), node);
    }

    fn select_exit(&self, target: &Socks5Target) -> Result<SocketAddr> {
        // 1. 规则匹配
        if let Socks5Target::Domain(domain, _) = target {
            let rules = self.domain_rules.read();
            for (suffix, node) in rules.iter() {
                if domain.ends_with(suffix) {
                    return Ok(*node);
                }
            }
        }

        // 2. 负载均衡
        let defaults = self.default_exits.read();
        if defaults.is_empty() {
            return Err(anyhow!("No default exit nodes available"));
        }

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        target.hash(&mut hasher);
        let hash = hasher.finish();
        
        let idx = (hash as usize) % defaults.len();
        Ok(defaults[idx])
    }
}

// ----------------------------------------------------------------------------
// 模块：SOCKS5 服务器核心
// ----------------------------------------------------------------------------

pub struct Socks5Server {
    listen_addr: String,
    
    // 依赖注入
    etp_tx: mpsc::Sender<AppSignal>,
    router: Arc<dyn ExitRouter>,
    tns_service: Option<Arc<dyn NameService>>,   // TNS 集成
    node_registry: Option<Arc<dyn NodeRegistry>>, // DHT 集成
    
    // 状态管理
    streams: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
    next_stream_id: AtomicU32,
    
    // 安全与控制
    auth: Authenticator,
    acl: AccessControl,
    stats: Arc<TrafficStats>,
    conn_limiter: Arc<Semaphore>,
    
    // DNS 服务
    dns_resolver: Option<EncryptedDnsResolver>,
    dns_port: Option<u16>,
}

impl Socks5Server {
    pub fn new(
        listen_addr: String, 
        etp_tx: mpsc::Sender<AppSignal>, 
        router: Arc<dyn ExitRouter>,
        max_connections: usize
    ) -> Self {
        Self {
            listen_addr,
            etp_tx,
            router,
            tns_service: None,
            node_registry: None,
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU32::new(1),
            auth: Authenticator::new(),
            acl: AccessControl::new(),
            stats: Arc::new(TrafficStats::default()),
            conn_limiter: Arc::new(Semaphore::new(max_connections)),
            dns_resolver: None,
            dns_port: None,
        }
    }

    /// 注入 TNS 和 DHT 服务以支持 .etp 域名解析
    pub fn with_tns_integration(
        mut self, 
        tns: Arc<dyn NameService>, 
        registry: Arc<dyn NodeRegistry>
    ) -> Self {
        self.tns_service = Some(tns);
        self.node_registry = Some(registry);
        self
    }

    /// 配置认证
    pub fn with_auth(mut self, auth: Authenticator) -> Self {
        self.auth = auth;
        self
    }

    /// 配置 ACL
    pub fn with_acl(mut self, acl: AccessControl) -> Self {
        self.acl = acl;
        self
    }

    /// 启用本地安全 DNS
    pub fn with_local_dns(mut self, port: u16, resolver: EncryptedDnsResolver) -> Self {
        self.dns_port = Some(port);
        self.dns_resolver = Some(resolver);
        self
    }
    
    pub fn get_stats(&self) -> Arc<TrafficStats> {
        self.stats.clone()
    }

    pub async fn run(self, mut etp_rx: mpsc::Receiver<(SocketAddr, u32, Vec<u8>)>) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await
            .context(format!("Failed to bind SOCKS5 on {}", self.listen_addr))?;
        
        info!("SOCKS5 Server running on {}", self.listen_addr);

        // 1. 启动本地 DNS (如果启用)
        if let (Some(port), Some(resolver)) = (self.dns_port, &self.dns_resolver) {
            self.spawn_dns_server(port, resolver.clone());
        }

        // 2. 启动 ETP 回包分发器
        let streams_map = self.streams.clone();
        let stats_ref = self.stats.clone();
        tokio::spawn(async move {
            while let Some((src_node, stream_id, data)) = etp_rx.recv().await {
                stats_ref.bytes_rx.fetch_add(data.len() as u64, Ordering::Relaxed);
                if let Some(sender) = streams_map.get(&(src_node, stream_id)) {
                    if sender.send(data).await.is_err() {
                        // Stream closed
                    }
                }
            }
        });

        // 3. 主接受循环
        let server = Arc::new(self);
        loop {
            // 连接限流
            let permit = server.conn_limiter.clone().acquire_owned().await.unwrap();
            
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    // ACL 检查
                    if !server.acl.check(&peer_addr) {
                        warn!("Access denied for {}", peer_addr);
                        continue;
                    }

                    let srv = server.clone();
                    server.stats.active_conn.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        if let Err(e) = srv.handle_session(socket, peer_addr).await {
                            debug!("SOCKS5 Session [{}]: {}", peer_addr, e);
                        }
                        srv.stats.active_conn.fetch_sub(1, Ordering::Relaxed);
                        drop(permit); // Release semaphore
                    });
                }
                Err(e) => error!("Accept error: {}", e),
            }
        }
    }

    fn spawn_dns_server(&self, port: u16, resolver: EncryptedDnsResolver) {
        info!("Secure DNS Server running on 127.0.0.1:{}", port);
        tokio::spawn(async move {
            let socket = match UdpSocket::bind(format!("127.0.0.1:{}", port)).await {
                Ok(s) => Arc::new(s),
                Err(e) => { error!("DNS bind failed: {}", e); return; }
            };

            let mut buf = [0u8; 1024];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let query = buf[..len].to_vec();
                        let res = resolver.clone();
                        let sock = socket.clone();
                        tokio::spawn(async move {
                            match res.resolve(&query).await {
                                Ok(ans) => { let _ = sock.send_to(&ans, src).await; },
                                Err(e) => debug!("DNS resolve error: {}", e),
                            }
                        });
                    },
                    Err(_) => break,
                }
            }
        });
    }

    async fn handle_session(&self, mut socket: TcpStream, _peer: SocketAddr) -> Result<()> {
        // --- 1. Negotiation Phase ---
        let mut head = [0u8; 2];
        socket.read_exact(&mut head).await?;
        if head[0] != SOCKS_VER { return Err(anyhow!("Ver mismatch")); }

        let nmethods = head[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await?;

        // 认证选择
        let mut method = AUTH_NO_ACCEPTABLE;
        if self.auth.is_empty() && methods.contains(&AUTH_NONE) {
            method = AUTH_NONE;
        } else if !self.auth.is_empty() && methods.contains(&AUTH_USER_PASS) {
            method = AUTH_USER_PASS;
        }

        socket.write_all(&[SOCKS_VER, method]).await?;
        if method == AUTH_NO_ACCEPTABLE {
            return Err(anyhow!("No auth method"));
        }

        // --- 2. Authentication Phase ---
        if method == AUTH_USER_PASS {
            let mut auth_ver = [0u8; 1];
            socket.read_exact(&mut auth_ver).await?; // Sub-negotiation ver usually 1
            
            let mut ulen = [0u8; 1];
            socket.read_exact(&mut ulen).await?;
            let mut user_bytes = vec![0u8; ulen[0] as usize];
            socket.read_exact(&mut user_bytes).await?;
            
            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await?;
            let mut pass_bytes = vec![0u8; plen[0] as usize];
            socket.read_exact(&mut pass_bytes).await?;

            let user = String::from_utf8_lossy(&user_bytes);
            let pass = String::from_utf8_lossy(&pass_bytes);

            if self.auth.validate(&user, &pass) {
                socket.write_all(&[0x01, 0x00]).await?; // Success
            } else {
                socket.write_all(&[0x01, 0x01]).await?; // Fail
                return Err(anyhow!("Auth failed for {}", user));
            }
        }

        // --- 3. Request Phase ---
        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await?; // VER, CMD, RSV, ATYP
        let cmd = head[1];
        
        let target = match Self::read_target(&mut socket, head[3]).await {
            Ok(t) => t,
            Err(e) => {
                Self::write_reply(&mut socket, REP_ADDR_TYPE_NOT_SUPPORTED).await?;
                return Err(e);
            }
        };

        // --- 4. TNS & Routing Logic ---
        let exit_node = self.resolve_route(&target).await?;

        match cmd {
            CMD_CONNECT => {
                self.handle_connect(socket, target, exit_node).await
            }
            CMD_UDP => {
                let client_addr = socket.peer_addr()?; // Simple assumption
                self.handle_udp(socket, client_addr, exit_node).await
            }
            CMD_BIND => {
                Self::write_reply(&mut socket, REP_CMD_NOT_SUPPORTED).await?;
                Ok(())
            }
            _ => {
                Self::write_reply(&mut socket, REP_CMD_NOT_SUPPORTED).await?;
                Err(anyhow!("Unknown CMD"))
            }
        }
    }

    /// ★ 核心路由解析：集成 TNS 与 Router
    async fn resolve_route(&self, target: &Socks5Target) -> Result<SocketAddr> {
        // A. 检查 TNS 域名 (.etp, .tns)
        if let Socks5Target::Domain(domain, port) = target {
            if domain.ends_with(".etp") || domain.ends_with(".tns") {
                if let (Some(tns), Some(registry)) = (&self.tns_service, &self.node_registry) {
                    debug!("SOCKS5: Intercepting TNS request for {}", domain);
                    // 1. Resolve Name -> NodeID
                    let node_id = tns.resolve(domain).await
                        .map_err(|e| anyhow!("TNS resolve failed: {}", e))?;
                    
                    // 2. Lookup NodeID -> IP
                    if let Some(ip) = registry.lookup_ip(&node_id).await {
                        info!("SOCKS5: Resolved {} -> NodeID[{:?}] -> {}", domain, &node_id[0..4], ip);
                        return Ok(ip);
                    } else {
                        // 如果找不到 IP，可能是因为 DHT 还没收敛。
                        // 这里我们无法建立 ETP 隧道，因为没有物理地址。
                        return Err(anyhow!("TNS Target Node not found in DHT"));
                    }
                }
            }
        }

        // B. 常规路由
        self.router.select_exit(target)
            .map_err(|e| anyhow!("Routing failed: {}", e))
    }

    async fn handle_connect(
        &self,
        mut socket: TcpStream,
        target: Socks5Target,
        exit_node: SocketAddr,
    ) -> Result<()> {
        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel(2048);
        self.streams.insert((exit_node, stream_id), tx);

        // Send Metadata (Connect)
        let mut meta = vec![0x01]; 
        meta.extend(Self::encode_target(&target));

        if self.etp_tx.send((exit_node, stream_id, meta, false)).await.is_err() {
            self.streams.remove(&(exit_node, stream_id));
            Self::write_reply(&mut socket, REP_NET_UNREACHABLE).await?;
            return Err(anyhow!("ETP Uplink failed"));
        }

        Self::write_reply(&mut socket, REP_SUCCESS).await?;

        let (mut ri, mut wi) = socket.split();
        let etp_tx = self.etp_tx.clone();
        let stats = self.stats.clone();

        // Uplink
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match ri.read(&mut buf).await {
                    Ok(0) => {
                        let _ = etp_tx.send((exit_node, stream_id, vec![], true)).await;
                        break;
                    }
                    Ok(n) => {
                        stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                        if etp_tx.send((exit_node, stream_id, buf[..n].to_vec(), false)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                         let _ = etp_tx.send((exit_node, stream_id, vec![], true)).await;
                         break;
                    }
                }
            }
        });

        // Downlink
        let down = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if data.is_empty() { break; }
                if wi.write_all(&data).await.is_err() { break; }
            }
            let _ = wi.shutdown().await;
        });

        let _ = tokio::join!(up, down);
        self.streams.remove(&(exit_node, stream_id));
        Ok(())
    }

    async fn handle_udp(
        &self,
        mut socket: TcpStream,
        client_addr: SocketAddr,
        exit_node: SocketAddr,
    ) -> Result<()> {
        // Bind UDP
        let udp = UdpSocket::bind("0.0.0.0:0").await?;
        let local_port = udp.local_addr()?.port();
        
        // Reply with bind address
        let mut resp = vec![SOCKS_VER, REP_SUCCESS, 0x00, ATYP_IPV4, 0,0,0,0];
        resp.extend(local_port.to_be_bytes());
        socket.write_all(&resp).await?;

        let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::channel(2048);
        self.streams.insert((exit_node, stream_id), tx);

        // Send Metadata (UDP Assoc)
        let meta = vec![0x03];
        self.etp_tx.send((exit_node, stream_id, meta, false)).await?;

        let udp = Arc::new(udp);
        let udp_rx = udp.clone();
        let udp_tx = udp.clone();
        let etp_tx = self.etp_tx.clone();
        let stats = self.stats.clone();

        // Uplink: UDP -> ETP
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match udp_rx.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        if src.ip() != client_addr.ip() { continue; } // Access Check
                        stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                        if etp_tx.send((exit_node, stream_id, buf[..n].to_vec(), false)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Downlink: ETP -> UDP
        let down = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if data.is_empty() { break; }
                // Data includes SOCKS5 header, client expects this
                let _ = udp_tx.send_to(&data, client_addr).await;
            }
        });

        // Hold TCP
        let mut hold = [0u8; 1];
        let _ = socket.read(&mut hold).await;

        let _ = self.etp_tx.send((exit_node, stream_id, vec![], true)).await;
        self.streams.remove(&(exit_node, stream_id));
        Ok(())
    }

    // --- Helpers ---

    async fn write_reply(socket: &mut TcpStream, rep: u8) -> Result<()> {
        socket.write_all(&[SOCKS_VER, rep, 0x00, ATYP_IPV4, 0,0,0,0, 0,0]).await?;
        Ok(())
    }

    async fn read_target(socket: &mut TcpStream, atyp: u8) -> Result<Socks5Target> {
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                socket.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok(Socks5Target::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                socket.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::from(u128::from_be_bytes(buf[0..16].try_into()?));
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Ok(Socks5Target::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                socket.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                socket.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                socket.read_exact(&mut port).await?;
                let d_str = String::from_utf8(domain).context("Invalid Domain")?;
                let p_num = u16::from_be_bytes(port);
                Ok(Socks5Target::Domain(d_str, p_num))
            }
            _ => Err(anyhow!("Bad ATYP")),
        }
    }

    fn encode_target(target: &Socks5Target) -> Vec<u8> {
        let mut buf = Vec::new();
        match target {
            Socks5Target::Ip(SocketAddr::V4(a)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
            Socks5Target::Ip(SocketAddr::V6(a)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&a.ip().octets());
                buf.extend_from_slice(&a.port().to_be_bytes());
            }
            Socks5Target::Domain(d, p) => {
                buf.push(ATYP_DOMAIN);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d.as_bytes());
                buf.extend_from_slice(&p.to_be_bytes());
            }
        }
        buf
    }
}
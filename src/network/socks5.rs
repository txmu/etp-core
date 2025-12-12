// etp-core/src/network/socks5.rs

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use dashmap::DashMap;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error, trace};
use rand::seq::SliceRandom;

// --- SOCKS5 协议常量 ---
const SOCKS_VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDR_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// ETP 应用层信令
pub type AppSignal = (SocketAddr, u32, Vec<u8>, bool);

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
// 模块：智能路由系统 (Smart Router)
// ----------------------------------------------------------------------------

/// 出口路由器接口
/// 决定一个请求应该由哪个 ETP 节点代理
pub trait ExitRouter: Send + Sync {
    /// 根据目标地址选择最佳出口节点
    fn select_exit(&self, target: &Socks5Target) -> Result<SocketAddr>;
    /// 添加可用的出口节点
    fn add_exit_node(&self, addr: SocketAddr);
}

/// 基于规则和负载均衡的路由器
pub struct RuleBasedRouter {
    /// 可用出口节点池
    exit_pool: DashMap<SocketAddr, u64>, // Addr -> Load/Score
    /// 域名后缀规则: ".eth" -> NodeA
    domain_rules: DashMap<String, SocketAddr>,
}

impl RuleBasedRouter {
    pub fn new(default_exits: Vec<SocketAddr>) -> Self {
        let pool = DashMap::new();
        for exit in default_exits {
            pool.insert(exit, 0);
        }
        Self {
            exit_pool: pool,
            domain_rules: DashMap::new(),
        }
    }

    pub fn add_rule(&self, suffix: &str, node: SocketAddr) {
        self.domain_rules.insert(suffix.to_string(), node);
    }
}

impl ExitRouter for RuleBasedRouter {
    fn add_exit_node(&self, addr: SocketAddr) {
        self.exit_pool.insert(addr, 0);
    }

    fn select_exit(&self, target: &Socks5Target) -> Result<SocketAddr> {
        // 1. 规则匹配 (Rule Matching)
        if let Socks5Target::Domain(domain, _) = target {
            for entry in self.domain_rules.iter() {
                if domain.ends_with(entry.key()) {
                    return Ok(*entry.value());
                }
            }
        }

        // 2. 哈希一致性/会话保持 (Session Affinity)
        // 保证同一个目标域名的请求走同一个出口，利用出口端的 DNS 缓存
        if !self.exit_pool.is_empty() {
            // 简单实现：将 target hash 后取模
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::Hash;
            use std::hash::Hasher;
            target.hash(&mut hasher);
            let hash = hasher.finish();
            
            // DashMap 不支持随机索引，我们需要快照 keys
            // 生产环境应维护一个 Vec 缓存以提高性能
            let keys: Vec<SocketAddr> = self.exit_pool.iter().map(|kv| *kv.key()).collect();
            if !keys.is_empty() {
                let idx = (hash as usize) % keys.len();
                return Ok(keys[idx]);
            }
        }

        Err(anyhow!("No exit nodes available"))
    }
}

// ----------------------------------------------------------------------------
// 模块：SOCKS5 服务器核心
// ----------------------------------------------------------------------------

pub struct Socks5Server {
    listen_addr: String,
    etp_tx: mpsc::Sender<AppSignal>,
    router: Arc<dyn ExitRouter>,
    streams: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
    next_stream_id: AtomicU32,
}

impl Socks5Server {
    pub fn new(listen_addr: String, etp_tx: mpsc::Sender<AppSignal>, router: Arc<dyn ExitRouter>) -> Self {
        Self {
            listen_addr,
            etp_tx,
            router,
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU32::new(1),
        }
    }

    pub async fn run(self, mut etp_rx: mpsc::Receiver<(SocketAddr, u32, Vec<u8>)>) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await
            .context(format!("Failed to bind SOCKS5 on {}", self.listen_addr))?;
        
        info!("SOCKS5 Server running on {}", self.listen_addr);

        // 1. ETP 回包分发器
        let streams_map = self.streams.clone();
        tokio::spawn(async move {
            while let Some((src_node, stream_id, data)) = etp_rx.recv().await {
                if let Some(sender) = streams_map.get(&(src_node, stream_id)) {
                    if data.is_empty() {
                        debug!("Stream {} FIN from {}", stream_id, src_node);
                        // 空包视为 FIN，不再发送
                    } else {
                        let _ = sender.send(data).await;
                    }
                }
            }
        });

        // 2. 接受连接
        let router = self.router.clone();
        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    let etp_tx = self.etp_tx.clone();
                    let router = router.clone();
                    let streams = self.streams.clone();
                    let stream_id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_session(socket, peer_addr, etp_tx, router, streams, stream_id).await {
                            debug!("SOCKS5 Session Error [{}]: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => error!("Accept error: {}", e),
            }
        }
    }

    async fn handle_session(
        mut socket: TcpStream,
        peer_addr: SocketAddr,
        etp_tx: mpsc::Sender<AppSignal>,
        router: Arc<dyn ExitRouter>,
        streams: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
        stream_id: u32
    ) -> Result<()> {
        // --- Handshake ---
        let mut ver_nmethods = [0u8; 2];
        socket.read_exact(&mut ver_nmethods).await?;
        if ver_nmethods[0] != SOCKS_VER { return Err(anyhow!("Unsupported Version")); }
        
        let mut methods = vec![0u8; ver_nmethods[1] as usize];
        socket.read_exact(&mut methods).await?;
        if !methods.contains(&0x00) {
            socket.write_all(&[SOCKS_VER, 0xFF]).await?;
            return Err(anyhow!("No acceptable auth"));
        }
        socket.write_all(&[SOCKS_VER, 0x00]).await?;

        // --- Request ---
        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await?; // VER, CMD, RSV, ATYP
        let cmd = head[1];
        
        // 读取目标地址
        let target = match Self::read_target_addr(&mut socket, head[3]).await {
            Ok(t) => t,
            Err(e) => {
                Self::write_reply(&mut socket, REP_ADDR_TYPE_NOT_SUPPORTED).await?;
                return Err(e);
            }
        };

        // 路由决策
        let exit_node = match router.select_exit(&target) {
            Ok(n) => n,
            Err(e) => {
                error!("Routing failed for {}: {}", target, e);
                Self::write_reply(&mut socket, REP_FAILURE).await?;
                return Err(e);
            }
        };

        match cmd {
            CMD_CONNECT => {
                Self::handle_connect(socket, target, exit_node, etp_tx, streams, stream_id).await
            }
            CMD_UDP => {
                Self::handle_udp_associate(socket, peer_addr, etp_tx, exit_node, streams, stream_id).await
            }
            CMD_BIND => {
                // BIND 仅用于 FTP 被动模式，现代环境很少使用，但我们实现协议流程
                Self::handle_bind(socket).await
            }
            _ => {
                Self::write_reply(&mut socket, REP_CMD_NOT_SUPPORTED).await?;
                Err(anyhow!("Unsupported command"))
            }
        }
    }

    /// 处理 TCP CONNECT
    async fn handle_connect(
        mut socket: TcpStream,
        target: Socks5Target,
        exit_node: SocketAddr,
        etp_tx: mpsc::Sender<AppSignal>,
        streams: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
        stream_id: u32
    ) -> Result<()> {
        // 注册回包通道
        let (tcp_in_tx, mut tcp_in_rx) = mpsc::channel::<Vec<u8>>(2048);
        streams.insert((exit_node, stream_id), tcp_in_tx);

        // 发送 Metadata (微协议: [JSON/Bin Target])
        // 这里使用简单的 [0x01 (CONNECT)] + EncodedTarget
        let mut meta = vec![0x01]; 
        meta.extend(Self::encode_target_metadata(&target));
        
        if etp_tx.send((exit_node, stream_id, meta, false)).await.is_err() {
            streams.remove(&(exit_node, stream_id));
            Self::write_reply(&mut socket, REP_FAILURE).await?;
            return Err(anyhow!("ETP Down"));
        }

        // 回复 Success (BND.ADDR=0.0.0.0, PORT=0)
        Self::write_reply(&mut socket, REP_SUCCESS).await?;
        
        // 双向转发
        let (mut ri, mut wi) = socket.split();
        let etp_tx_out = etp_tx.clone();

        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match ri.read(&mut buf).await {
                    Ok(0) => {
                        let _ = etp_tx_out.send((exit_node, stream_id, Vec::new(), true)).await;
                        break; 
                    }
                    Ok(n) => {
                        if etp_tx_out.send((exit_node, stream_id, buf[..n].to_vec(), false)).await.is_err() { break; }
                    }
                    Err(_) => {
                        let _ = etp_tx_out.send((exit_node, stream_id, Vec::new(), true)).await;
                        break; 
                    }
                }
            }
        });

        let downstream = tokio::spawn(async move {
            while let Some(data) = tcp_in_rx.recv().await {
                if data.is_empty() { break; } 
                if wi.write_all(&data).await.is_err() { break; }
            }
            let _ = wi.shutdown().await;
        });

        let _ = tokio::join!(upstream, downstream);
        streams.remove(&(exit_node, stream_id));
        Ok(())
    }

    /// 处理 UDP ASSOCIATE
    /// 实现原理：开启一个 UDP Socket 转发，封装为 ETP Stream (Reliable) 或 ETP Datagram
    /// 注意：ETP 目前是 Stream 接口，所以我们实际上是在做 UDP-over-TCP 隧道
    async fn handle_udp_associate(
        mut socket: TcpStream,
        client_addr: SocketAddr, // Client's IP expecting to send UDP
        etp_tx: mpsc::Sender<AppSignal>,
        exit_node: SocketAddr,
        streams: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
        stream_id: u32
    ) -> Result<()> {
        // 1. Bind UDP Socket
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = udp_socket.local_addr()?;
        
        // 2. Tell Client where to send UDP
        let ip = match local_addr.ip() {
            IpAddr::V4(i) => i.octets().to_vec(),
            IpAddr::V6(i) => i.octets().to_vec(),
        };
        let port = local_addr.port();
        
        let mut resp = vec![SOCKS_VER, REP_SUCCESS, 0x00, if ip.len()==4 {ATYP_IPV4} else {ATYP_IPV6}];
        resp.extend(ip);
        resp.extend(port.to_be_bytes());
        socket.write_all(&resp).await?;

        // 3. Register ETP Stream
        let (udp_in_tx, mut udp_in_rx) = mpsc::channel::<Vec<u8>>(2048);
        streams.insert((exit_node, stream_id), udp_in_tx);

        // 发送 Metadata: [0x03 (UDP_ASSOC)] (No target needed yet, socks5 udp header has target)
        // 但我们需要告诉 Exit Node 开启 UDP 转发模式
        let meta = vec![0x03]; 
        etp_tx.send((exit_node, stream_id, meta, false)).await?;

        let udp_socket = Arc::new(udp_socket);
        let udp_send = udp_socket.clone();
        let udp_recv = udp_socket.clone();

        // Task A: UDP Recv -> ETP
        // Client sends UDP with SOCKS5 Header: [RSV][RSV][FRAG][ATYP][ADDR][PORT][DATA]
        // We strip nothing? Actually Exit Node needs to know target.
        // We just tunnel the WHOLE packet payload as stream data.
        let etp_tx_out = etp_tx.clone();
        let upstream = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match udp_recv.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        // Security: Only accept from the client that requested association
                        if src.ip() != client_addr.ip() { continue; }
                        
                        // Tunnel the raw SOCKS5 UDP packet
                        if etp_tx_out.send((exit_node, stream_id, buf[..n].to_vec(), false)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Task B: ETP -> UDP Send
        let downstream = tokio::spawn(async move {
            while let Some(data) = udp_in_rx.recv().await {
                if data.is_empty() { break; }
                // Data contains SOCKS5 UDP Header + Payload
                // We send it back to client
                let _ = udp_send.send_to(&data, client_addr).await;
            }
        });

        // Keep TCP alive (SOCKS5 requires TCP connection to be kept alive)
        let mut buf = [0u8; 1];
        let _ = socket.read(&mut buf).await; // Wait for close
        
        // Cleanup
        let _ = etp_tx.send((exit_node, stream_id, Vec::new(), true)).await;
        streams.remove(&(exit_node, stream_id));
        
        Ok(())
    }

    /// 处理 BIND (简化版)
    async fn handle_bind(mut socket: TcpStream) -> Result<()> {
        // BIND 需要两次 Reply。
        // 1. Bind port success.
        // 2. Incoming connection accepted.
        // 由于这需要 Exit Node 反向连接，极为复杂，生产环境通常只返回 Failure 或不支持。
        // 这里我们为了完备性，返回 "Command Not Supported" 是最安全的生产实践，
        // 避免给用户虚假的 BIND 成功预期。
        Self::write_reply(&mut socket, REP_CMD_NOT_SUPPORTED).await?;
        Ok(())
    }

    // --- Helpers ---

    async fn write_reply(socket: &mut TcpStream, rep: u8) -> Result<()> {
        socket.write_all(&[SOCKS_VER, rep, 0x00, ATYP_IPV4, 0,0,0,0, 0,0]).await?;
        Ok(())
    }

    async fn read_target_addr(socket: &mut TcpStream, atyp: u8) -> Result<Socks5Target> {
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
                let mut len_buf = [0u8; 1];
                socket.read_exact(&mut len_buf).await?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                socket.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf).context("Invalid Domain")?;
                let mut port_buf = [0u8; 2];
                socket.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);
                Ok(Socks5Target::Domain(domain, port))
            }
            _ => Err(anyhow!("Unknown ATYP {}", atyp)),
        }
    }

    fn encode_target_metadata(target: &Socks5Target) -> Vec<u8> {
        let mut buf = Vec::new();
        match target {
            Socks5Target::Ip(SocketAddr::V4(addr)) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Socks5Target::Ip(SocketAddr::V6(addr)) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Socks5Target::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    struct MockRouter;
    impl ExitRouter for MockRouter {
        fn select_exit(&self, _t: &Socks5Target) -> Result<SocketAddr> {
            Ok("10.0.0.1:9999".parse().unwrap())
        }
        fn add_exit_node(&self, _a: SocketAddr) {}
    }

    #[tokio::test]
    async fn test_socks5_udp_associate_negotiation() {
        let (etp_tx, mut etp_rx) = mpsc::channel(100);
        let server = Socks5Server::new("127.0.0.1:12080".to_string(), etp_tx, Arc::new(MockRouter));
        
        tokio::spawn(async move {
            // Mock receiving the UDP Associate metadata signal
            if let Some((_, _, data, _)) = etp_rx.recv().await {
                assert_eq!(data[0], 0x03); // Check meta type
            }
        });
        
        let (_null_tx, null_rx) = mpsc::channel(10);
        tokio::spawn(async move {
            server.run(null_rx).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = TcpStream::connect("127.0.0.1:12080").await.unwrap();
        // Handshake
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        
        // Request UDP ASSOCIATE
        // 0.0.0.0:0 as dummy DST
        let req = vec![0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0];
        client.write_all(&req).await.unwrap();
        
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00); // Success
        assert_eq!(rep[3], 0x01); // Bind IP type IPv4
    }
}
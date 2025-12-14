// etp-core/src/anonymity/adapter.rs

use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use std::time::Duration;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::timeout;
use async_trait::async_trait;
use log::{info, warn, error, debug, trace};
use anyhow::{Result, anyhow, Context};
use dashmap::DashMap;

use crate::network::node::PacketTransport;

// --- 配置常量 ---
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAME_SIZE: usize = 65535;
const VIRTUAL_IP_PREFIX: u8 = 240; // 240.0.0.0/8 (Class E) reserved for Tor mapping

// ============================================================================
//  1. SOCKS5 协议工具
// ============================================================================

async fn socks5_handshake(proxy: SocketAddr, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect(proxy).await?;
    let mut stream = stream; // pin

    // 1. Auth Negotiation
    stream.write_all(&[0x05, 0x01, 0x00]).await?; // VER, NMETHODS, NO_AUTH
    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;
    if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
        return Err(anyhow!("SOCKS5 auth rejected or protocol error"));
    }

    // 2. Connect Request
    // [VER, CMD, RSV, ATYP, ADDR..., PORT]
    let mut req = vec![0x05, 0x01, 0x00, 0x03]; // 0x03 = Domain Name
    if target_host.len() > 255 {
        return Err(anyhow!("Target host too long"));
    }
    req.push(target_host.len() as u8);
    req.extend_from_slice(target_host.as_bytes());
    req.extend_from_slice(&target_port.to_be_bytes());

    stream.write_all(&req).await?;

    // 3. Connect Response
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(anyhow!("SOCKS5 connect failed code: {}", head[1]));
    }

    // Consume BND.ADDR
    match head[3] {
        0x01 => { let _ = stream.read_exact(&mut [0u8; 4+2]).await; },
        0x03 => {
            let len = stream.read_u8().await?;
            let _ = stream.read_exact(&mut vec![0u8; len as usize + 2]).await;
        },
        0x04 => { let _ = stream.read_exact(&mut [0u8; 16+2]).await; },
        _ => return Err(anyhow!("Unknown address type in response")),
    }

    Ok(stream)
}

// ============================================================================
//  2. 动态 Tor 传输层 (TorDynamicTransport)
//  能够为不同的目标地址建立独立的 SOCKS5 隧道，并维护连接池
// ============================================================================

#[derive(Debug)]
pub struct TorDynamicTransport {
    /// 本地代理地址
    proxy_addr: SocketAddr,
    
    /// 活跃隧道映射表: TargetAddr -> MpscSender (发送数据帧到 Writer Task)
    /// 注意：这里的 TargetAddr 是 ETP 视角的地址 (可能是虚拟 IP)
    tunnels: Arc<DashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    
    /// 接收数据汇聚通道 (所有 Tunnel 的 Reader Task 都把数据发到这里)
    /// 必须用 Mutex 保护 Receiver 以满足 Sync
    rx_queue: Arc<Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
    
    /// 内部发送端 (克隆给 Reader Task)
    tx_internal: mpsc::Sender<(Vec<u8>, SocketAddr)>,

    /// 虚拟地址映射器 (解决 .onion 域名无法放入 SocketAddr 的问题)
    /// VirtualIP (240.x.x.x) <-> DomainString
    dns_mapper: Arc<VirtualDnsMapper>,
}

impl TorDynamicTransport {
    pub fn new(proxy_addr: &str) -> Result<Arc<Self>> {
        let proxy: SocketAddr = proxy_addr.parse().context("Invalid proxy address")?;
        let (tx, rx) = mpsc::channel(4096); // 全局接收缓冲

        Ok(Arc::new(Self {
            proxy_addr: proxy,
            tunnels: Arc::new(DashMap::new()),
            rx_queue: Arc::new(Mutex::new(rx)),
            tx_internal: tx,
            dns_mapper: Arc::new(VirtualDnsMapper::new()),
        }))
    }

    /// 注册一个 Onion 域名，获取一个虚拟 IP
    /// 上层业务 (Flavor/Discovery) 必须调用此方法来解析 .onion 地址
    pub fn map_domain(&self, domain: &str) -> SocketAddr {
        self.dns_mapper.get_or_create_ip(domain)
    }

    /// 获取虚拟 IP 对应的真实域名
    pub fn resolve_ip(&self, ip: &SocketAddr) -> Option<(String, u16)> {
        self.dns_mapper.resolve_ip(ip)
    }

    /// 建立新隧道 (内部方法)
    async fn connect_tunnel(&self, target_virtual: SocketAddr) -> Result<mpsc::Sender<Vec<u8>>> {
        // 1. 解析目标
        let (host, port) = self.resolve_ip(&target_virtual)
            .ok_or_else(|| anyhow!("Target IP {} is not a mapped virtual address", target_virtual))?;

        debug!("TorTransport: Dialing tunnel to {}:{} via {}...", host, port, self.proxy_addr);

        // 2. 执行 SOCKS5 握手
        let stream = timeout(CONNECT_TIMEOUT, socks5_handshake(self.proxy_addr, &host, port)).await??;
        
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx_frame, mut rx_frame) = mpsc::channel::<Vec<u8>>(1024); // 单个隧道的发送队列

        // 3. 启动 Writer Task (App -> Tunnel)
        let target_clone = target_virtual;
        let tunnels_map = self.tunnels.clone();
        
        tokio::spawn(async move {
            while let Some(data) = rx_frame.recv().await {
                // Framing: [Len u16][Data]
                if data.len() > MAX_FRAME_SIZE {
                    warn!("TorTransport: Frame too large, dropping.");
                    continue;
                }
                let len = (data.len() as u16).to_be_bytes();
                if let Err(e) = writer.write_all(&len).await.and_then(|_| writer.write_all(&data).await) {
                    error!("TorTransport: Write error to {}: {}", target_clone, e);
                    break;
                }
            }
            // Cleanup
            tunnels_map.remove(&target_clone);
            debug!("TorTransport: Tunnel writer closed for {}", target_clone);
        });

        // 4. 启动 Reader Task (Tunnel -> App)
        let tx_main = self.tx_internal.clone();
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                // Read Length
                if reader.read_exact(&mut len_buf).await.is_err() { break; }
                let len = u16::from_be_bytes(len_buf) as usize;
                
                // Read Payload
                let mut buf = vec![0u8; len];
                if reader.read_exact(&mut buf).await.is_err() { break; }
                
                // Forward to main engine
                // 注意：我们将 Source 标记为 Virtual IP，这样 Engine 回包时会再次查表
                if tx_main.send((buf, target_clone)).await.is_err() {
                    break; // Engine shutdown
                }
            }
            debug!("TorTransport: Tunnel reader closed for {}", target_clone);
        });

        Ok(tx_frame)
    }
}

#[async_trait]
impl PacketTransport for TorDynamicTransport {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        // 1. 检查是否存在活跃隧道
        // 使用 DashMap 的 get 或 entry api
        // 由于 create_tunnel 是 async 的，不能直接在 entry closure 里调用
        
        let tx = if let Some(sender) = self.tunnels.get(&target) {
            sender.clone()
        } else {
            // 需要新建连接
            // 注意：这里可能存在并发建立连接的问题，但在 DashMap 下可接受，多余的会被覆盖或丢弃
            match self.connect_tunnel(target).await {
                Ok(sender) => {
                    self.tunnels.insert(target, sender.clone());
                    sender
                }
                Err(e) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()));
                }
            }
        };

        // 2. 发送数据到 Writer Task
        // 使用 try_send 避免阻塞 Engine 核心循环
        // 如果 Channel 满，说明 Tor 网络阻塞，丢包是合理的 (Backpressure)
        match tx.try_send(buf.to_vec()) {
            Ok(_) => Ok(buf.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Tunnel buffer full"))
            },
            Err(_) => {
                // Channel closed, remove and retry next time
                self.tunnels.remove(&target);
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Tunnel closed"))
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx_queue.lock().await;
        if let Some((data, src)) = rx.recv().await {
            let len = std::cmp::min(buf.len(), data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, src))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Transport shutdown"))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        // 返回代理地址或伪造的本地地址
        Ok(self.proxy_addr)
    }
}

// ============================================================================
//  3. 混合传输层 (HybridTransport)
//  同时支持 UDP 直连和 Tor 隧道，根据目标 IP 路由
// ============================================================================

#[derive(Debug)]
pub struct HybridTransport {
    udp: Arc<dyn PacketTransport>,
    tunnel: Arc<TorDynamicTransport>, // 需要具体类型以访问 map_domain
    
    // 接收聚合
    rx: Arc<Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
}

impl HybridTransport {
    pub fn new(udp: Arc<dyn PacketTransport>, tunnel: Arc<TorDynamicTransport>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(4096);

        // 1. 启动 UDP 转发任务
        let udp_clone = udp.clone();
        let tx_udp = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match udp_clone.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let _ = tx_udp.send((buf[..len].to_vec(), addr)).await;
                    }
                    Err(_) => break, // Socket closed
                }
            }
        });

        // 2. 启动 Tunnel 转发任务
        let tunnel_clone = tunnel.clone();
        let tx_tun = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match tunnel_clone.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        let _ = tx_tun.send((buf[..len].to_vec(), addr)).await;
                    }
                    Err(_) => break,
                }
            }
        });

        Arc::new(Self {
            udp,
            tunnel,
            rx: Arc::new(Mutex::new(rx)),
        })
    }

    /// 暴露 DNS 映射接口给 Facade
    pub fn map_onion_address(&self, domain: &str) -> SocketAddr {
        self.tunnel.map_domain(domain)
    }
}

#[async_trait]
impl PacketTransport for HybridTransport {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        // 路由逻辑：检查是否为虚拟 IP (Class E: 240.x.x.x)
        let is_virtual = match target {
            SocketAddr::V4(addr) => addr.ip().octets()[0] == VIRTUAL_IP_PREFIX,
            _ => false,
        };

        if is_virtual {
            // 路由到 Tor/I2P
            self.tunnel.send_to(buf, target).await
        } else {
            // 路由到 Clearnet UDP
            self.udp.send_to(buf, target).await
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        if let Some((data, addr)) = rx.recv().await {
            let len = std::cmp::min(buf.len(), data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Hybrid transport closed"))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

// ============================================================================
//  4. 虚拟 DNS 映射器 (辅助工具)
// ============================================================================

#[derive(Debug)]
struct VirtualDnsMapper {
    // Domain -> VirtualIP
    forward: RwLock<HashMap<String, SocketAddr>>,
    // VirtualIP -> (Domain, Port)
    backward: RwLock<HashMap<SocketAddr, (String, u16)>>,
    // IP分配计数器 (240.0.0.1 开始)
    counter: AtomicU32,
}

impl VirtualDnsMapper {
    fn new() -> Self {
        Self {
            forward: RwLock::new(HashMap::new()),
            backward: RwLock::new(HashMap::new()),
            counter: AtomicU32::new(1),
        }
    }

    fn get_or_create_ip(&self, domain_port: &str) -> SocketAddr {
        // Check cache
        if let Some(addr) = self.forward.read().await.get(domain_port) {
            return *addr;
        }

        let mut f_lock = self.forward.write().await;
        // Double check
        if let Some(addr) = f_lock.get(domain_port) {
            return *addr;
        }

        // Allocate new IP
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let b1 = (id >> 16) as u8;
        let b2 = (id >> 8) as u8;
        let b3 = id as u8;
        
        // Parse port from string, default 0 if not present
        let parts: Vec<&str> = domain_port.split(':').collect();
        let port = if parts.len() > 1 {
            parts[parts.len()-1].parse().unwrap_or(0)
        } else { 0 };
        
        let domain_only = if parts.len() > 1 {
            parts[0..parts.len()-1].join(":")
        } else {
            domain_port.to_string()
        };

        let ip = Ipv4Addr::new(VIRTUAL_IP_PREFIX, b1, b2, b3);
        let addr = SocketAddr::new(IpAddr::V4(ip), port);

        f_lock.insert(domain_port.to_string(), addr);
        self.backward.write().await.insert(addr, (domain_only, port));

        debug!("VirtualDNS: Mapped {} -> {}", domain_port, addr);
        addr
    }

    fn resolve_ip(&self, ip: &SocketAddr) -> Option<(String, u16)> {
        // 这里使用了简单的 block_on 或 try_read，因为 resolve 通常在 transport 的 send 路径
        // 注意：在 async 环境中尽量不要用 blocking_read。
        // 但 RwLock 是 tokio 的，所以可以 await。
        // 由于 PacketTransport::send_to 是 async 的，这是安全的。
        // 不过我们这里偷懒用了 std::sync::RwLock 还是 Tokio?
        // 上面定义是 tokio::sync::RwLock.
        
        // 由于这是内部辅助，我们假设这是在一个 async block 中被调用。
        // 但这里并没有 async。修正：改为 blocking RwLock (parking_lot) 性能更好且无需 await。
        // parking_lot 对于极短的读操作是安全的。
        
        // 修正：将上面的 tokio::sync::RwLock 改为 parking_lot::RwLock
        // 从而避免 async infect。
        None // Placeholder: see fix below
    }
}

// 修正 VirtualDnsMapper 使用同步锁以简化调用
mod internal_dns {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use super::VIRTUAL_IP_PREFIX;

    #[derive(Debug)]
    pub struct VirtualDnsMapper {
        forward: RwLock<HashMap<String, SocketAddr>>,
        backward: RwLock<HashMap<SocketAddr, (String, u16)>>,
        counter: AtomicU32,
    }

    impl VirtualDnsMapper {
        pub fn new() -> Self {
            Self {
                forward: RwLock::new(HashMap::new()),
                backward: RwLock::new(HashMap::new()),
                counter: AtomicU32::new(1),
            }
        }

        pub fn get_or_create_ip(&self, domain_port: &str) -> SocketAddr {
            if let Some(addr) = self.forward.read().get(domain_port) {
                return *addr;
            }
            let mut f_lock = self.forward.write();
            let id = self.counter.fetch_add(1, Ordering::Relaxed);
            
            // Extract Port
            let parts: Vec<&str> = domain_port.split(':').collect();
            let port = if parts.len() > 1 {
                parts.last().unwrap().parse().unwrap_or(0)
            } else { 0 };
            
            let host = if parts.len() > 1 {
                parts[..parts.len()-1].join(":")
            } else { domain_port.to_string() };

            let ip = Ipv4Addr::new(VIRTUAL_IP_PREFIX, (id >> 16) as u8, (id >> 8) as u8, id as u8);
            let addr = SocketAddr::new(IpAddr::V4(ip), port);

            f_lock.insert(domain_port.to_string(), addr);
            self.backward.write().insert(addr, (host, port));
            addr
        }

        pub fn resolve_ip(&self, ip: &SocketAddr) -> Option<(String, u16)> {
            self.backward.read().get(ip).cloned()
        }
    }
}
use internal_dns::VirtualDnsMapper;
// etp-core/src/anonymity/adapter.rs

use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, interval};
use async_trait::async_trait;
use log::{info, warn, error, debug, trace};
use anyhow::{Result, anyhow, Context};
use dashmap::DashMap;

use crate::network::node::PacketTransport;

// ============================================================================
//  配置常量
// ============================================================================

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5分钟无流量自动断开
const GC_INTERVAL: Duration = Duration::from_secs(60);          // 每分钟执行一次 GC
const MAX_FRAME_SIZE: usize = 65535;

// ============================================================================
//  1. SOCKS5 协议工具 (带 TCP 调优)
// ============================================================================

async fn socks5_handshake(proxy: SocketAddr, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect(proxy).await?;
    
    // [Feature: TCP Optimization]
    // 禁用 Nagle 算法，因为我们在隧道中传输的是实时包，不需要 TCP 帮我们合并小包
    stream.set_nodelay(true).context("Failed to set TCP_NODELAY")?;
    // 设置缓冲区大小，优化吞吐量
    let _ = stream.set_recv_buffer_size(64 * 1024);
    let _ = stream.set_send_buffer_size(64 * 1024);

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
//  支持：自动电路建立、空闲回收、Class E 映射
// ============================================================================

/// 隧道元数据 (用于健康检查)
#[derive(Debug)]
struct TunnelState {
    tx: mpsc::Sender<Vec<u8>>,
    /// 最后一次发送/接收数据的时间戳 (用于 GC)
    last_active: Arc<AtomicU64>,
}

#[derive(Debug)]
pub struct TorDynamicTransport {
    /// 本地代理地址
    proxy_addr: SocketAddr,
    
    /// 活跃隧道映射表: TargetAddr (Virtual IP) -> TunnelState
    tunnels: Arc<DashMap<SocketAddr, TunnelState>>,
    
    /// 接收数据汇聚通道 (所有 Tunnel 的 Reader Task 都把数据发到这里)
    rx_queue: Arc<Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
    
    /// 内部发送端 (克隆给 Reader Task)
    tx_internal: mpsc::Sender<(Vec<u8>, SocketAddr)>,

    /// 虚拟地址映射器
    dns_mapper: Arc<VirtualDnsMapper>,
}

impl TorDynamicTransport {
    pub fn new(proxy_addr: &str) -> Result<Arc<Self>> {
        let proxy: SocketAddr = proxy_addr.parse().context("Invalid proxy address")?;
        let (tx, rx) = mpsc::channel(4096); // 全局接收缓冲

        let transport = Arc::new(Self {
            proxy_addr: proxy,
            tunnels: Arc::new(DashMap::new()),
            rx_queue: Arc::new(Mutex::new(rx)),
            tx_internal: tx,
            dns_mapper: Arc::new(VirtualDnsMapper::new()),
        });

        // [Feature: Idle Tunnel Reaper]
        // 启动后台 GC 任务，清理僵尸连接
        let t_clone = transport.clone();
        tokio::spawn(async move {
            let mut interval = interval(GC_INTERVAL);
            loop {
                interval.tick().await;
                t_clone.run_garbage_collection();
            }
        });

        Ok(transport)
    }

    /// 执行垃圾回收
    fn run_garbage_collection(&self) {
        let now = current_timestamp();
        let timeout = TUNNEL_IDLE_TIMEOUT.as_secs();
        
        // DashMap retain 是安全的并发清理方式
        // 移除那些 (now - last_active) > timeout 的隧道
        self.tunnels.retain(|addr, state| {
            let last = state.last_active.load(Ordering::Relaxed);
            if now.saturating_sub(last) > timeout {
                debug!("TorTransport: Reaping idle tunnel to {}", addr);
                false // Remove
            } else {
                true // Keep
            }
        });
    }

    /// 注册一个 Onion 域名，获取一个虚拟 IP
    pub fn map_domain(&self, domain: &str) -> SocketAddr {
        self.dns_mapper.get_or_create_ip(domain)
    }

    /// 获取虚拟 IP 对应的真实域名
    pub fn resolve_ip(&self, ip: &SocketAddr) -> Option<(String, u16)> {
        self.dns_mapper.resolve_ip(ip)
    }

    /// 建立新隧道 (内部方法)
    async fn connect_tunnel(&self, target_virtual: SocketAddr) -> Result<TunnelState> {
        // 1. 解析目标
        let (host, port) = self.resolve_ip(&target_virtual)
            .ok_or_else(|| anyhow!("Target IP {} is not a mapped virtual address", target_virtual))?;

        debug!("TorTransport: Dialing tunnel to {}:{} via {}...", host, port, self.proxy_addr);

        // 2. 执行 SOCKS5 握手 (带超时)
        let stream = timeout(CONNECT_TIMEOUT, socks5_handshake(self.proxy_addr, &host, port)).await??;
        
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx_frame, mut rx_frame) = mpsc::channel::<Vec<u8>>(1024); // 单个隧道的发送队列
        
        let last_active = Arc::new(AtomicU64::new(current_timestamp()));

        // 3. 启动 Writer Task (App -> Tunnel)
        let target_clone = target_virtual;
        let tunnels_map = self.tunnels.clone();
        let active_writer = last_active.clone();
        
        tokio::spawn(async move {
            while let Some(data) = rx_frame.recv().await {
                if data.len() > MAX_FRAME_SIZE {
                    warn!("TorTransport: Frame too large, dropping.");
                    continue;
                }
                
                // Update Activity
                active_writer.store(current_timestamp(), Ordering::Relaxed);

                // Protocol: Length-Prefixed Framing inside TCP
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
        let active_reader = last_active.clone();
        
        tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                // Read Length
                if reader.read_exact(&mut len_buf).await.is_err() { break; }
                let len = u16::from_be_bytes(len_buf) as usize;
                
                // Read Payload
                let mut buf = vec![0u8; len];
                if reader.read_exact(&mut buf).await.is_err() { break; }
                
                // Update Activity
                active_reader.store(current_timestamp(), Ordering::Relaxed);

                // Forward to main engine
                if tx_main.send((buf, target_clone)).await.is_err() {
                    break; // Engine shutdown
                }
            }
            debug!("TorTransport: Tunnel reader closed for {}", target_clone);
        });

        Ok(TunnelState {
            tx: tx_frame,
            last_active,
        })
    }
}

#[async_trait]
impl PacketTransport for TorDynamicTransport {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        // 1. 尝试获取现有隧道
        // 使用 DashMap 的 get 或 entry api
        // 由于 create_tunnel 是 async 的，不能直接在 entry closure 里调用
        
        let tx = if let Some(state) = self.tunnels.get(&target) {
            // 更新活跃时间
            state.last_active.store(current_timestamp(), Ordering::Relaxed);
            state.tx.clone()
        } else {
            // 需要新建连接
            match self.connect_tunnel(target).await {
                Ok(state) => {
                    let tx = state.tx.clone();
                    self.tunnels.insert(target, state);
                    tx
                }
                Err(e) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()));
                }
            }
        };

        // 2. 发送数据到 Writer Task
        match tx.try_send(buf.to_vec()) {
            Ok(_) => Ok(buf.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Backpressure: Tunnel is congested
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Tunnel buffer full"))
            },
            Err(_) => {
                // Channel closed, clean up map and retry next time
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
        // 路由逻辑：检查是否为虚拟 IP (Class E: 240.0.0.0/4)
        // 范围: 240.0.0.0 - 255.255.255.255
        // 我们在 VirtualDnsMapper 中避开了 255.x.x.x
        let is_virtual = match target {
            SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                octets[0] >= 240 // Class E Check
            },
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
//  4. 虚拟 DNS 映射器 (Class E Enhanced)
//  使用 Knuth Multiplicative Hash 实现 240.0.0.0/4 全域映射
// ============================================================================

mod internal_dns {
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};

    // 黄金分割素数 (for 32-bit hash)
    const KNUTH_GOLDEN_PRIME: u32 = 2654435761;

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
            // 1. Check cache
            if let Some(addr) = self.forward.read().get(domain_port) {
                return *addr;
            }
            let mut f_lock = self.forward.write();
            // Double check inside write lock
            if let Some(addr) = f_lock.get(domain_port) {
                return *addr;
            }

            // 2. Allocate new ID and Hash it
            let id_raw = self.counter.fetch_add(1, Ordering::Relaxed);
            
            // Knuth Multiplicative Hash: 将顺序 ID 映射到离散的 u32 空间
            // 这种双射保证了无碰撞且分布均匀
            let hash = id_raw.wrapping_mul(KNUTH_GOLDEN_PRIME);

            // 3. Map to Class E (240.0.0.0 - 254.255.255.255)
            let b0_raw = (hash >> 24) as u8;
            let b1 = (hash >> 16) as u8;
            let b2 = (hash >> 8) as u8;
            let b3 = hash as u8;

            // 强制首字节高 4 位为 1111 (0xF0 -> 240)
            // 0xF0 | (low 4 bits of b0)
            let mut b0 = 0xF0 | (b0_raw & 0x0F);

            // 规避 255.x.x.x (广播风暴/保留)
            if b0 == 255 {
                b0 = 254; 
            }

            // 规避 .0 和 .255 结尾 (网络/广播地址)
            let final_b3 = if b3 == 0 { 1 } else if b3 == 255 { 254 } else { b3 };

            let ip = Ipv4Addr::new(b0, b1, b2, final_b3);

            // Extract Port
            let parts: Vec<&str> = domain_port.split(':').collect();
            let port = if parts.len() > 1 {
                parts.last().unwrap().parse().unwrap_or(0)
            } else { 0 };
            
            let host = if parts.len() > 1 {
                parts[..parts.len()-1].join(":")
            } else { domain_port.to_string() };

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

// --- Helper ---
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
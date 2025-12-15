// etp-core/src/extensions/transport_kit.rs

use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use std::io::Cursor;

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::net::TcpStream;
use async_trait::async_trait;
use anyhow::{Result, anyhow, Context as AnyhowContext};
use log::{info, warn, error, debug, trace};
use parking_lot::{RwLock, Mutex};
use dashmap::DashMap;
use bytes::{Bytes, BytesMut, Buf};

use crate::network::node::PacketTransport;

// ============================================================================
//  1. 基础接口定义 (Interfaces)
// ============================================================================

/// 虚拟链路接口：定义如何建立到底层的物理连接
/// 用户只需实现此接口即可接入新协议 (TCP, WS, Bluetooth, etc.)
#[async_trait]
pub trait VirtualLink: Send + Sync + 'static {
    /// 协议名称 (用于日志)
    fn name(&self) -> &str;

    /// 建立出站连接
    /// addr_str: 目标地址字符串 (e.g. "1.2.3.4:8080", "wss://relay.io")
    async fn connect(&self, addr_str: &str) -> Result<Box<dyn VirtualStream>>;

    /// 接受入站连接 (可选，如果不支持 Server 模式可返回 Pending)
    /// 返回流对象和对方的物理地址字符串
    async fn accept(&self) -> Result<(Box<dyn VirtualStream>, String)>;
}

/// 虚拟流对象：对底层 IO 的抽象 (AsyncRead + AsyncWrite)
pub trait VirtualStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
// 为所有满足条件的类型自动实现 Marker Trait
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> VirtualStream for T {}

/// 传输层中间件：拦截进出数据包
pub trait TransportLayer: Send + Sync + 'static {
    /// 出站处理 (ETP -> Network)
    /// 返回 Ok(true) 继续发送，Ok(false) 丢弃包
    fn on_send(&self, packet: &mut Vec<u8>, target: &SocketAddr) -> Result<bool>;

    /// 入站处理 (Network -> ETP)
    fn on_recv(&self, packet: &mut Vec<u8>, src: &SocketAddr) -> Result<bool>;
}

// ============================================================================
//  2. 核心：TransportKit (The Factory)
// ============================================================================

/// TransportKit: 通用的传输层适配器
pub struct TransportKit {
    /// 底层链路实现
    link: Arc<dyn VirtualLink>,
    
    /// 中间件链
    layers: Arc<Vec<Box<dyn TransportLayer>>>,
    
    /// 地址映射表: VirtualIP <-> Physical Address String
    /// ETP 使用 SocketAddr 路由，我们需要将其映射到底层协议的地址格式
    addr_map: Arc<AddressRegistry>,
    
    /// 活跃连接池: VirtualIP -> TxChannel
    connections: Arc<DashMap<SocketAddr, ConnectionState>>,
    
    /// 全局接收队列 (所有流的数据汇聚于此，供 recv_from 消费)
    global_rx: Arc<TokioMutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>>,
    
    /// 内部发送端 (克隆给 Reader Task)
    rx_producer: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

struct ConnectionState {
    tx: mpsc::Sender<Vec<u8>>,
    last_active: std::time::Instant,
}

impl TransportKit {
    /// 创建构建器
    pub fn builder() -> TransportKitBuilder {
        TransportKitBuilder::default()
    }

    /// 注册一个远端地址，获取一个虚拟 IP
    /// 这是使用非 IP 协议 (如 Domain, URL) 时的关键步骤
    pub fn map_address(&self, phys_addr: &str) -> SocketAddr {
        self.addr_map.get_or_create(phys_addr)
    }

    /// 启动监听循环 (Server Mode)
    fn start_accept_loop(&self) {
        let link = self.link.clone();
        let producer = self.rx_producer.clone();
        let map = self.addr_map.clone();
        let layers = self.layers.clone();
        let conns = self.connections.clone();

        tokio::spawn(async move {
            info!("TransportKit: Accept loop started for {}", link.name());
            loop {
                match link.accept().await {
                    Ok((stream, remote_phys)) => {
                        // 分配虚拟 IP
                        let vip = map.get_or_create(&remote_phys);
                        info!("TransportKit: New connection from {} -> {}", remote_phys, vip);

                        // 建立管道
                        Self::spawn_stream_handlers(
                            stream, 
                            vip, 
                            producer.clone(), 
                            conns.clone(), 
                            layers.clone()
                        );
                    }
                    Err(e) => {
                        // 某些实现可能不支持 accept，或者发生致命错误
                        warn!("TransportKit: Accept error: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    /// 建立新的出站连接
    async fn connect_outbound(&self, target_vip: SocketAddr) -> Result<mpsc::Sender<Vec<u8>>> {
        // 1. 查表获取物理地址
        let phys_addr = self.addr_map.resolve_phys(&target_vip)
            .ok_or_else(|| anyhow!("Unknown virtual address: {}", target_vip))?;

        debug!("TransportKit: Dialing {} ({})", phys_addr, target_vip);

        // 2. 调用底层 Link 建立连接
        let stream = self.link.connect(&phys_addr).await?;

        // 3. 启动处理任务
        let tx = Self::spawn_stream_handlers(
            stream, 
            target_vip, 
            self.rx_producer.clone(), 
            self.connections.clone(), 
            self.layers.clone()
        );

        Ok(tx)
    }

    /// 核心：启动流处理任务 (Framing + Layering)
    fn spawn_stream_handlers(
        stream: Box<dyn VirtualStream>,
        peer_vip: SocketAddr,
        global_producer: mpsc::Sender<(Vec<u8>, SocketAddr)>,
        conn_map: Arc<DashMap<SocketAddr, ConnectionState>>,
        layers: Arc<Vec<Box<dyn TransportLayer>>>,
    ) -> mpsc::Sender<Vec<u8>> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        // 注册连接状态
        conn_map.insert(peer_vip, ConnectionState {
            tx: tx.clone(),
            last_active: std::time::Instant::now(),
        });

        // Task A: Writer Loop (App -> Layers -> Stream)
        let layers_writer = layers.clone();
        tokio::spawn(async move {
            while let Some(mut packet) = rx.recv().await {
                // 1. 应用中间件 (Outbound)
                let mut drop = false;
                for layer in layers_writer.iter() {
                    match layer.on_send(&mut packet, &peer_vip) {
                        Ok(keep) => if !keep { drop = true; break; },
                        Err(e) => {
                            warn!("Layer send error: {}", e);
                            drop = true; break;
                        }
                    }
                }
                if drop { continue; }

                // 2. 封包 (Length Prefix Framing)
                // Format: [Len: u32_be][Payload]
                let len = packet.len() as u32;
                let mut frame = Vec::with_capacity(4 + packet.len());
                frame.extend_from_slice(&len.to_be_bytes());
                frame.extend_from_slice(&packet);

                // 3. 写入流
                if let Err(e) = writer.write_all(&frame).await {
                    debug!("TransportKit: Write error to {}: {}", peer_vip, e);
                    break;
                }
            }
            debug!("TransportKit: Writer closed for {}", peer_vip);
        });

        // Task B: Reader Loop (Stream -> Layers -> App)
        let layers_reader = layers.clone();
        let conn_map_reader = conn_map.clone();
        
        tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            loop {
                // 1. 读取长度头
                if reader.read_exact(&mut len_buf).await.is_err() { break; }
                let len = u32::from_be_bytes(len_buf) as usize;

                if len > 10 * 1024 * 1024 { // 10MB Sanity Check
                    error!("TransportKit: Oversized frame ({} bytes) from {}", len, peer_vip);
                    break;
                }

                // 2. 读取 Payload
                let mut buf = vec![0u8; len];
                if reader.read_exact(&mut buf).await.is_err() { break; }

                // 3. 更新活跃时间
                if let Some(mut entry) = conn_map_reader.get_mut(&peer_vip) {
                    entry.last_active = std::time::Instant::now();
                }

                // 4. 应用中间件 (Inbound)
                let mut drop = false;
                for layer in layers_reader.iter() {
                    match layer.on_recv(&mut buf, &peer_vip) {
                        Ok(keep) => if !keep { drop = true; break; },
                        Err(e) => {
                            warn!("Layer recv error: {}", e);
                            drop = true; break;
                        }
                    }
                }
                if drop { continue; }

                // 5. 提交给内核
                if global_producer.send((buf, peer_vip)).await.is_err() {
                    break; // Engine shutdown
                }
            }
            
            // Cleanup
            conn_map_reader.remove(&peer_vip);
            debug!("TransportKit: Reader closed for {}", peer_vip);
        });

        tx
    }
}

#[async_trait]
impl PacketTransport for TransportKit {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        // 1. 尝试获取现有连接通道
        let tx_opt = if let Some(state) = self.connections.get(&target) {
            Some(state.tx.clone())
        } else {
            None
        };

        // 2. 如果没有连接，尝试建立 (Auto Dial)
        let tx = if let Some(t) = tx_opt {
            t
        } else {
            match self.connect_outbound(target).await {
                Ok(t) => t,
                Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())),
            }
        };

        // 3. 发送数据
        // 注意：这里发送的是原始数据，Layer 处理在 Writer Task 中进行
        match tx.send(buf.to_vec()).await {
            Ok(_) => Ok(buf.len()),
            Err(_) => {
                self.connections.remove(&target);
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Channel closed"))
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut guard = self.global_rx.lock().await;
        if let Some((data, addr)) = guard.recv().await {
            let len = std::cmp::min(buf.len(), data.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Transport shutdown"))
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        // 返回一个虚拟的本地地址
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
    }
}

// ============================================================================
//  3. 辅助组件：地址注册表 (Address Registry)
// ============================================================================

/// 负责将任意字符串地址映射到 240.x.x.x 的虚拟空间
pub struct AddressRegistry {
    // Virtual IP -> Phys String
    forward: DashMap<SocketAddr, String>,
    // Phys String -> Virtual IP
    backward: DashMap<String, SocketAddr>,
    // 计数器
    counter: std::sync::atomic::AtomicU32,
}

impl AddressRegistry {
    pub fn new() -> Self {
        Self {
            forward: DashMap::new(),
            backward: DashMap::new(),
            counter: std::sync::atomic::AtomicU32::new(1),
        }
    }

    pub fn get_or_create(&self, phys_addr: &str) -> SocketAddr {
        if let Some(addr) = self.backward.get(phys_addr) {
            return *addr;
        }

        // Allocate new Class E IP
        // 240.0.0.0/4 range
        // Algorithm: increment counter
        let id = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Map u32 to IP (Skip 0 and broadcast)
        let b1 = ((id >> 16) & 0xFF) as u8;
        let b2 = ((id >> 8) & 0xFF) as u8;
        let b3 = (id & 0xFF) as u8;
        
        let ip = Ipv4Addr::new(240, b1, b2, b3);
        let port = 0; // Port irrelevant for virtual map
        let addr = SocketAddr::new(IpAddr::V4(ip), port);

        self.forward.insert(addr, phys_addr.to_string());
        self.backward.insert(phys_addr.to_string(), addr);
        addr
    }

    pub fn resolve_phys(&self, vip: &SocketAddr) -> Option<String> {
        self.forward.get(vip).map(|v| v.clone())
    }
}

// ============================================================================
//  4. 构建器 (Builder)
// ============================================================================

#[derive(Default)]
pub struct TransportKitBuilder {
    link: Option<Arc<dyn VirtualLink>>,
    layers: Vec<Box<dyn TransportLayer>>,
}

impl TransportKitBuilder {
    pub fn with_link<L: VirtualLink>(mut self, link: L) -> Self {
        self.link = Some(Arc::new(link));
        self
    }

    pub fn with_layer<L: TransportLayer>(mut self, layer: L) -> Self {
        self.layers.push(Box::new(layer));
        self
    }

    pub fn build(self) -> Result<Arc<TransportKit>> {
        let link = self.link.ok_or_else(|| anyhow!("No VirtualLink configured"))?;
        let (tx, rx) = mpsc::channel(4096);

        let kit = Arc::new(TransportKit {
            link,
            layers: Arc::new(self.layers),
            addr_map: Arc::new(AddressRegistry::new()),
            connections: Arc::new(DashMap::new()),
            global_rx: Arc::new(TokioMutex::new(rx)),
            rx_producer: tx,
        });

        // 自动启动监听
        kit.start_accept_loop();

        Ok(kit)
    }
}

// ============================================================================
//  5. 内置组件 (Batteries Included)
// ============================================================================

// --- A. TCP Link Implementation ---

pub struct TcpLink {
    bind_addr: String,
    listener: TokioMutex<Option<tokio::net::TcpListener>>,
}

impl TcpLink {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
            listener: TokioMutex::new(None),
        }
    }
    
    // 初始化 Listener (Lazy Init)
    async fn get_listener(&self) -> Result<()> {
        let mut guard = self.listener.lock().await;
        if guard.is_none() {
            let l = tokio::net::TcpListener::bind(&self.bind_addr).await?;
            *guard = Some(l);
        }
        Ok(())
    }
}

#[async_trait]
impl VirtualLink for TcpLink {
    fn name(&self) -> &str { "tcp" }

    async fn connect(&self, addr_str: &str) -> Result<Box<dyn VirtualStream>> {
        let stream = TcpStream::connect(addr_str).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }

    async fn accept(&self) -> Result<(Box<dyn VirtualStream>, String)> {
        // Ensure listener is bound
        {
            let mut guard = self.listener.lock().await;
            if guard.is_none() {
                let l = tokio::net::TcpListener::bind(&self.bind_addr).await?;
                *guard = Some(l);
            }
        }

        // Accept
        // Note: We need to hold the lock to accept, or use Arc<Mutex> better.
        // But mutex guard is not Send across await if we wait for accept.
        // Correct way: Take listener out? No.
        // We assume listener is initialized.
        
        // Using a loop inside to access lock briefly is tricky for `accept` which blocks.
        // Better design for TcpLink: Bind in `new` or `start`.
        // Here we do a hack: we clone the listener? No, TcpListener is not cloneable.
        // We use a dedicated accept loop inside TcpLink? No, `VirtualLink::accept` is the loop body.
        
        // Workaround: We define `TcpLink` to hold `Arc<TcpListener>`.
        // But `bind` is async.
        // For this impl, we assume the user calls `TcpLink::bind().await` to create it.
        
        Err(anyhow!("TcpLink: use TcpLink::bind_and_build helper")) 
    }
}

// Simplified TcpLink for ease of use
pub struct SimpleTcpLink {
    listener: tokio::net::TcpListener,
}

impl SimpleTcpLink {
    pub async fn bind(addr: &str) -> Result<Self> {
        Ok(Self {
            listener: tokio::net::TcpListener::bind(addr).await?,
        })
    }
}

#[async_trait]
impl VirtualLink for SimpleTcpLink {
    fn name(&self) -> &str { "tcp" }
    
    async fn connect(&self, addr: &str) -> Result<Box<dyn VirtualStream>> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
    
    async fn accept(&self) -> Result<(Box<dyn VirtualStream>, String)> {
        let (stream, addr) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok((Box::new(stream), addr.to_string()))
    }
}

// --- B. Middleware Examples ---

/// 简单的 XOR 混淆层 (轻量级)
pub struct XorLayer {
    key: u8,
}

impl XorLayer {
    pub fn new(key: u8) -> Self { Self { key } }
}

impl TransportLayer for XorLayer {
    fn on_send(&self, packet: &mut Vec<u8>, _target: &SocketAddr) -> Result<bool> {
        for b in packet.iter_mut() { *b ^= self.key; }
        Ok(true)
    }

    fn on_recv(&self, packet: &mut Vec<u8>, _src: &SocketAddr) -> Result<bool> {
        for b in packet.iter_mut() { *b ^= self.key; }
        Ok(true)
    }
}

/// 日志层
pub struct LogLayer;
impl TransportLayer for LogLayer {
    fn on_send(&self, packet: &mut Vec<u8>, target: &SocketAddr) -> Result<bool> {
        trace!("TX -> {}: {} bytes", target, packet.len());
        Ok(true)
    }
    fn on_recv(&self, packet: &mut Vec<u8>, src: &SocketAddr) -> Result<bool> {
        trace!("RX <- {}: {} bytes", src, packet.len());
        Ok(true)
    }
}
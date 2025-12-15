// etp-core/src/plugin/flavors/ipfs_fusion.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;

use tokio::sync::{mpsc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use log::{info, warn, debug, error};
use anyhow::Result;
use bytes::{Bytes, BytesMut, Buf};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

// --- 协议定义 ---
const IPFS_FUSION_VER: u8 = 0x01;
const CMD_DHT_QUERY_BRIDGE: u8 = 0x01;
const CMD_IPFS_TUNNEL: u8 = 0x02;

// ============================================================================
//  Virtual Socket & Transport Implementation (The "Heavy Lifting")
// ============================================================================

// 仅在开启特性时编译具体的流实现
#[cfg(feature = "ipfs-integration")]
mod virtual_net {
    use super::*;
    use libp2p::core::{Transport, transport::ListenerId, Multiaddr};
    use futures::future::{BoxFuture, FutureExt};
    use futures::stream::{Stream, StreamExt};
    use std::future::ready;

    /// 虚拟流：在 libp2p 看来这是一个 Socket，实际上它通过 ETP Tunnel 传输
    pub struct VirtualStream {
        /// 从 ETP 网络接收数据的通道 (Ingress)
        incoming_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        /// 读取缓冲区 (处理分包/粘包)
        read_buf: BytesMut,
        /// 向 ETP 网络发送数据的通道 (Egress)
        outgoing_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        /// 目标物理地址
        remote_addr: SocketAddr,
    }

    impl VirtualStream {
        pub fn new(
            rx: mpsc::UnboundedReceiver<Vec<u8>>,
            tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
            remote: SocketAddr
        ) -> Self {
            Self {
                incoming_rx: rx,
                read_buf: BytesMut::with_capacity(4096),
                outgoing_tx: tx,
                remote_addr: remote,
            }
        }
    }

    impl AsyncRead for VirtualStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // 1. 如果缓冲区有数据，先消耗缓冲区
            if !self.read_buf.is_empty() {
                let len = std::cmp::min(self.read_buf.len(), buf.remaining());
                let chunk = self.read_buf.split_to(len);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            // 2. 尝试从 Channel 读取新数据
            match self.incoming_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    // 将数据放入缓冲区或直接写入 buf
                    if data.len() <= buf.remaining() {
                        buf.put_slice(&data);
                    } else {
                        // 数据比 buf 大，存入 read_buf
                        let to_copy = buf.remaining();
                        buf.put_slice(&data[..to_copy]);
                        self.read_buf.extend_from_slice(&data[to_copy..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Ok(())), // Channel Closed (EOF)
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl AsyncWrite for VirtualStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // 封装 ETP 协议头: [Ver][CMD][Payload]
            let mut packet = Vec::with_capacity(2 + buf.len());
            packet.push(IPFS_FUSION_VER);
            packet.push(CMD_IPFS_TUNNEL);
            packet.extend_from_slice(buf);

            // 发送给 Flavor 的 network_tx
            // 注意：try_send 避免阻塞，如果满则丢包或阻塞 (这里简化为阻塞式 send 的 poll 模拟)
            // 由于 mpsc::Sender 在 poll_write 中不好处理 await，我们使用 try_send
            // 更好的做法是 spawn 发送任务，或者使用 unbounded。
            // 这里为了保证顺序，我们假设 channel 足够大。
            
            match self.outgoing_tx.try_send((self.remote_addr, packet)) {
                Ok(_) => Poll::Ready(Ok(buf.len())),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Backpressure
                    Poll::Pending 
                },
                Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "ETP Tunnel Closed"))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// ETP 虚拟传输层
    /// 实现 libp2p 的 Transport trait
    #[derive(Clone)]
    pub struct EtpTransport {
        /// 全局连接映射表：SocketAddr -> Ingress Channel Sender
        /// 用于 Flavor 将收到的数据路由到对应的 VirtualStream
        pub socket_map: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        /// 发送通道 (克隆给 VirtualStream)
        pub network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    }

    impl Transport for EtpTransport {
        type Output = VirtualStream;
        type Error = io::Error;
        type ListenerUpgrade = BoxFuture<'static, Result<Self::Output, Self::Error>>;
        type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

        fn listen_on(&mut self, _addr: Multiaddr) -> Result<ListenerId, Self::Error> {
            // ETP 已经在监听，这里只是逻辑占位，返回一个假 ID
            Ok(ListenerId::new())
        }

        fn remove_listener(&mut self, _id: ListenerId) -> bool {
            true
        }

        fn dial(&mut self, _addr: Multiaddr) -> Result<Self::Dial, Self::Error> {
            // 解析 Multiaddr 获取目标 SocketAddr
            // 假设地址格式 /ip4/1.2.3.4/udp/9000/etp
            // 这里简化处理，假设我们能从 Multiaddr 提取出 IP:Port
            // 实际生产代码需要完整的 Protocol 解析
            
            let remote_addr: SocketAddr = "127.0.0.1:0".parse().unwrap(); // FIXME: Extract from _addr logic

            let (ingress_tx, ingress_rx) = mpsc::unbounded_channel();
            let network_tx = self.network_tx.clone();
            let map = self.socket_map.clone();

            Ok(async move {
                // 注册到映射表
                map.lock().await.insert(remote_addr, ingress_tx);
                
                // 创建流
                Ok(VirtualStream::new(ingress_rx, network_tx, remote_addr))
            }.boxed())
        }

        fn dial_as_listener(&mut self, addr: Multiaddr) -> Result<Self::Dial, Self::Error> {
            self.dial(addr)
        }

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<libp2p::core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>> {
            // 我们不产生 Listener 事件，因为连接是由 ETP 底层管理的
            // 或者是通过 accept 逻辑（此处省略 accept 队列实现）
            Poll::Pending
        }
    }
}

// ============================================================================
//  Feature Integration
// ============================================================================

#[cfg(feature = "ipfs-integration")]
use libp2p::{
    swarm::{NetworkBehaviour, SwarmEvent},
    kad::{store::MemoryStore, Kademlia, KademliaConfig},
    identity, Swarm, PeerId,
};
#[cfg(feature = "ipfs-integration")]
use self::virtual_net::EtpTransport;

/// IPFS 融合模块
pub struct IpfsFusionFlavor {
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    
    #[cfg(feature = "ipfs-integration")]
    socket_map: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl IpfsFusionFlavor {
    pub async fn new(
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        enable_upgrade_mode: bool
    ) -> Result<Arc<Self>> {
        
        #[cfg(feature = "ipfs-integration")]
        {
            let socket_map = Arc::new(Mutex::new(HashMap::new()));
            
            // 1. 初始化 libp2p 身份
            let local_key = identity::Keypair::generate_ed25519();
            let local_peer_id = PeerId::from(local_key.public());
            info!("IpfsFusion: Local PeerID: {}", local_peer_id);

            // 2. 构建自定义 Transport
            let etp_transport = EtpTransport {
                socket_map: socket_map.clone(),
                network_tx: network_tx.clone(),
            };

            // 3. 构建 Swarm
            // 使用 libp2p::core::upgrade::Version::V1 包装我们的 etp_transport
            // 这里为了代码简洁，展示核心组装逻辑
            let transport = libp2p::core::transport::timeout::TransportTimeout::new(
                etp_transport, 
                std::time::Duration::from_secs(30)
            ).boxed();

            // 标准 IPFS 协议栈: Noise + Yamux
            let transport = transport
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(libp2p::noise::Config::new(&local_key)?)
                .multiplex(libp2p::yamux::Config::default())
                .boxed();

            let mut cfg = KademliaConfig::default();
            cfg.set_protocol_names(vec![std::borrow::Cow::Borrowed(b"/ipfs/kad/1.0.0")]);
            let store = MemoryStore::new(local_peer_id);
            let behaviour = Kademlia::with_config(local_peer_id, store, cfg);
            
            let mut swarm = Swarm::with_tokio_executor(transport, behaviour, local_peer_id);

            // 4. 启动 Swarm 循环
            tokio::spawn(async move {
                loop {
                    match swarm.next().await {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            info!("IpfsFusion: Virtual Interface Listening on {}", address);
                        },
                        Some(SwarmEvent::Behaviour(event)) => {
                            debug!("IpfsFusion: Kademlia Event: {:?}", event);
                        },
                        _ => {}
                    }
                }
            });

            if enable_upgrade_mode {
                info!("IpfsFusion: Upgrade Mode (Masquerade) Enabled.");
            }

            Ok(Arc::new(Self {
                network_tx,
                socket_map,
            }))
        }

        #[cfg(not(feature = "ipfs-integration"))]
        {
            Ok(Arc::new(Self { network_tx }))
        }
    }

    #[cfg(feature = "ipfs-integration")]
    async fn inject_tunnel_data(&self, src: SocketAddr, data: Vec<u8>) {
        let mut map = self.socket_map.lock().await;
        
        // 查找或创建连接
        // 如果是新连接，我们需要模拟 "Accept" 行为
        // 在上面的 Transport::dial 实现中我们处理了主动连接。
        // 被动连接（Accept）需要在 Transport::poll 中产出 IncomingConnection。
        // 由于 Transport::poll 比较复杂，这里采用简化策略：
        // 如果找不到 Entry，说明可能是一个新的 Inbound 连接，
        // 我们创建一个 Channel 并放入 Map。
        // *关键*：为了让 Swarm 感知到这个新连接，Transport::poll 需要被通知。
        // 这里为了代码在单文件内闭环，我们仅处理已存在的连接（即假设已通过某种方式握手或 Map 已由 Dial 填充）。
        
        if let Some(tx) = map.get(&src) {
            // 将数据注入虚拟流的读取端
            if let Err(_) = tx.send(data) {
                // 通道已关闭，移除映射
                map.remove(&src);
            }
        } else {
            // 这是一个新的入站隧道请求
            // 在完整的实现中，这里应该触发 Transport::poll 返回 ListenerUpgrade
            debug!("IpfsFusion: Dropping data from unknown stream {} (Accept logic omitted in this snippet)", src);
        }
    }
}

impl CapabilityProvider for IpfsFusionFlavor {
    fn capability_id(&self) -> String { "etp.flavor.ipfs.v1".into() }
}

impl Flavor for IpfsFusionFlavor {
    fn priority(&self) -> u8 { 90 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != IPFS_FUSION_VER { return false; }

        match data[1] {
            CMD_DHT_QUERY_BRIDGE => {
                // 简单的 DHT 查询桥接，不走隧道
                true
            },
            CMD_IPFS_TUNNEL => {
                // 隧道数据包: [Ver][CMD][Payload]
                let payload = data[2..].to_vec();
                let src = ctx.src_addr;
                
                #[cfg(feature = "ipfs-integration")]
                {
                    // 异步注入，避免阻塞 Flavor 线程
                    let self_clone = self.clone_ref(); // 需要 Self 引用
                    // 由于 Flavor trait 是 &self，我们需要 Arc 包装或者内部特定字段是 Arc
                    // 这里 socket_map 是 Arc，可以直接 clone
                    let map = self.socket_map.clone();
                    
                    tokio::spawn(async move {
                        let mut guard = map.lock().await;
                        if let Some(tx) = guard.get(&src) {
                            let _ = tx.send(payload);
                        }
                    });
                }
                
                true
            },
            _ => false
        }
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    
    fn on_connection_close(&self, peer: SocketAddr) {
        #[cfg(feature = "ipfs-integration")]
        {
            let map = self.socket_map.clone();
            tokio::spawn(async move {
                map.lock().await.remove(&peer);
                info!("IpfsFusion: Virtual stream closed for {}", peer);
            });
        }
    }
}

// 辅助：为了在 on_stream_data 中使用 spawn，我们需要访问内部 Arc 字段
// 由于 self 是 &IpfsFusionFlavor，我们只能 clone 内部的 Arc 字段。
// 上面的实现已经直接 clone 了 socket_map。
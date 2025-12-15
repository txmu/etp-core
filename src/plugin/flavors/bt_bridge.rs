// etp-core/src/plugin/flavors/bt_bridge.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use parking_lot::RwLock;
use log::{info, debug, warn, error};
use anyhow::{Result, anyhow};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

// --- 协议定义 ---
const BT_BRIDGE_PROTO_VER: u8 = 0x01;
const CMD_KRPC_FRAME: u8 = 0x01; // 封装的 KRPC 数据包

/// BitTorrent 桥接器
/// 允许将 BT DHT 流量 (KRPC) 通过 ETP 隧道传输，从而绕过针对 BT 协议的 DPI 封锁
pub struct BtBridgeFlavor {
    /// 绑定本地 UDP 端口，用于与真实 BT 网络交互
    raw_socket: Arc<UdpSocket>,
    /// 网络发送通道 (ETP Tunnel)
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    /// NAT 映射表: TransactionID (or remote IP) -> ETP Peer
    /// 这里的简化逻辑是：我们作为网关，将收到的 BT 包转发给特定的 ETP 节点
    /// 实际场景中，通常是一个 ETP 客户端连接一个 ETP 出口节点
    tunnel_peer: RwLock<Option<SocketAddr>>,
}

impl BtBridgeFlavor {
    pub async fn new(
        bind_port: u16, 
        network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Result<Arc<Self>> {
        // 绑定本地端口 (例如 6881)
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", bind_port)).await?;
        info!("BtBridge: Listening for raw BT traffic on 0.0.0.0:{}", bind_port);

        let flavor = Arc::new(Self {
            raw_socket: Arc::new(socket),
            network_tx,
            tunnel_peer: RwLock::new(None),
        });

        // 启动 Raw Socket 监听循环 (BT Network -> ETP Tunnel)
        flavor.start_listener();

        Ok(flavor)
    }

    /// 设置隧道对端 (即我们要把 BT 流量发给哪个 ETP 节点)
    pub fn set_tunnel_peer(&self, peer: SocketAddr) {
        *self.tunnel_peer.write() = Some(peer);
    }

    fn start_listener(&self) {
        let socket = self.raw_socket.clone();
        let tx = self.network_tx.clone();
        // 这是一个 Weak 引用或者需要在结构体中处理生命周期，这里简化为 clone 传递
        // 注意：实际代码中要注意 async 任务的生命周期管理
        let peer_lock = self.tunnel_peer.read().clone(); // Copy logic needed or use Arc

        // Hack: 为了在 static future 中访问 self 的成员，通常需要 Arc<Self>
        // 这里我们假设 spawn 的逻辑是独立的
        // 简化实现：我们只转发收到的任何 UDP 包到 ETP 隧道
        
        // 我们需要一个 channel 来把 peer 信息传进去，或者用 Arc<RwLock>
        // 由于 self 已经是 Arc，我们可以传 self.clone()
        // 但 start_listener 是 &self。
    }
    
    // 修正后的启动逻辑，需在外部调用或使用 Arc<Self>
    pub fn start_background_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match self.raw_socket.recv_from(&mut buf).await {
                    Ok((len, src_addr)) => {
                        // 1. 简单的协议识别 (Heuristic)
                        // BT KRPC 也是 Bencoded 字典，通常以 'd' 开头，以 'e' 结尾
                        // 且包含 "y", "t", "q" 或 "r" 键
                        let data = &buf[..len];
                        if !Self::looks_like_bt(data) {
                            debug!("BtBridge: Ignored non-BT packet from {}", src_addr);
                            continue;
                        }

                        // 2. 获取隧道目标
                        let target = *self.tunnel_peer.read();
                        
                        if let Some(etp_peer) = target {
                            // 3. 封装并发送进隧道
                            // Format: [Ver][CMD][RawIP(4/16)][RawPort(2)][Payload]
                            // 我们需要保留原始 BT 节点的 IP，以便回包时知道发给谁
                            // 这里简化：假设是点对点隧道，直接把 payload 发过去
                            
                            let mut packet = Vec::with_capacity(2 + data.len());
                            packet.push(BT_BRIDGE_PROTO_VER);
                            packet.push(CMD_KRPC_FRAME);
                            packet.extend_from_slice(data);

                            if let Err(e) = self.network_tx.send((etp_peer, packet)).await {
                                warn!("BtBridge: Tunnel closed: {}", e);
                                break;
                            }
                            
                            debug!("BtBridge: Tunneled {} bytes from BT({}) to ETP({})", len, src_addr, etp_peer);
                        }
                    }
                    Err(e) => {
                        error!("BtBridge: UDP recv error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    /// 简单的启发式检查 (Bencode Dictionary)
    fn looks_like_bt(data: &[u8]) -> bool {
        if data.len() < 2 { return false; }
        // Starts with 'd' (dict) and ends with 'e' (end)
        data[0] == b'd' && data[data.len()-1] == b'e'
    }
}

impl CapabilityProvider for BtBridgeFlavor {
    fn capability_id(&self) -> String { "etp.flavor.bt_bridge.v1".into() }
}

impl Flavor for BtBridgeFlavor {
    fn priority(&self) -> u8 { 60 }

    // ETP Tunnel -> BT Network
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != BT_BRIDGE_PROTO_VER { return false; }

        match data[1] {
            CMD_KRPC_FRAME => {
                let payload = &data[2..];
                // 收到来自 ETP 隧道的 BT 数据包
                // 我们需要把它发送给真实的 BT 网络
                // 问题：发给谁？
                // 方案 A: 隧道协议里包含了 Target IP (更复杂，类似 SOCKS5 UDP Associate)
                // 方案 B: 这是一个出口节点，它将数据发给本地 BT 客户端 (127.0.0.1:xxx)
                
                // 这里演示方案 B：默认转发给本地 BT 客户端 (假设运行在 6881)
                // 或者我们可以实现一个简单的 NAT 表。
                
                let target_bt_node: SocketAddr = "127.0.0.1:6881".parse().unwrap();
                let socket = self.raw_socket.clone();
                let payload_vec = payload.to_vec();
                
                tokio::spawn(async move {
                    let _ = socket.send_to(&payload_vec, target_bt_node).await;
                });
                
                true
            },
            _ => false
        }
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 自动绑定：第一个连接的 ETP 节点成为隧道出口
        let mut lock = self.tunnel_peer.write();
        if lock.is_none() {
            *lock = Some(peer);
            info!("BtBridge: Tunnel established with {}", peer);
        }
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        let mut lock = self.tunnel_peer.write();
        if *lock == Some(peer) {
            *lock = None;
            info!("BtBridge: Tunnel disconnected");
        }
    }
}
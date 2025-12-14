// etp-core/src/plugin/flavors/vpn.rs

use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use parking_lot::RwLock; // 使用高性能读写锁
use anyhow::{Result, anyhow};
use log::{info, warn, error, debug, trace};
use rand::Rng;
use serde::{Serialize, Deserialize};

// 引入依赖
#[cfg(feature = "vpn")]
use tun::platform::Device as TunDevice;
#[cfg(feature = "vpn")]
use tun::Configuration;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::platform::PlatformCapabilities;

/// VPN 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub virtual_ip: Ipv4Addr,
    pub virtual_mask: Ipv4Addr,
    pub mtu: i32,
    pub morphing_enabled: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            virtual_ip: Ipv4Addr::new(10, 8, 0, 2),
            virtual_mask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1420, // 留出头部空间
            morphing_enabled: true,
        }
    }
}

/// 流量形变器 (Traffic Morpher)
/// 将 VPN 数据包伪装成视频流特征 (Variable Bitrate Video Stream)
struct TrafficMorpher;

impl TrafficMorpher {
    /// 对数据包进行填充，使其符合特定统计分布
    fn morph(payload: &mut Vec<u8>, mtu: usize) {
        let current_len = payload.len();
        let mut rng = rand::thread_rng();

        // 策略：模拟 I-Frame (大包) 和 P-Frame (小包) 的混合
        // 如果包接近 MTU，填满它 (像 I-Frame 分片)
        // 如果包很小 (如 TCP ACK)，随机填充一点，掩盖它是 ACK 的事实
        
        let target_len = if current_len > 1000 {
            // 可能是大数据传输，填充至 MTU 附近
            mtu - rng.gen_range(0..20) 
        } else if current_len < 100 {
            // 小包，填充到 300-500 字节范围，模拟音频或控制帧
            rng.gen_range(300..500)
        } else {
            // 中等包，保持原样或微量填充
            current_len + rng.gen_range(0..50)
        };

        if target_len > current_len {
            let padding_size = target_len - current_len;
            let mut padding = vec![0u8; padding_size];
            rng.fill(&mut padding[..]);
            payload.extend(padding);
        }
    }

    /// 去除填充 (根据 IP 头长度)
    /// 返回去除填充后的有效数据切片
    fn unmorph(data: &[u8]) -> &[u8] {
        if data.len() < 20 {
            return data;
        }

        // 解析 IP 头获取真实长度
        // IPv4: Version (4 bits)
        let version = data[0] >> 4;
        
        let actual_len = match version {
            4 => {
                // IPv4 Total Length is at bytes 2-3
                let len = u16::from_be_bytes([data[2], data[3]]) as usize;
                if len <= data.len() && len > 0 { len } else { data.len() }
            },
            6 => {
                // IPv6 Payload Length is at bytes 4-5
                // Total length = 40 (Header) + Payload Length
                let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
                let total = payload_len + 40;
                if total <= data.len() { total } else { data.len() }
            },
            _ => data.len() // 非 IP 包，无法判断，假设全部有效
        };

        &data[..actual_len]
    }
}

/// VPN 状态机
enum VpnState {
    Disabled, // 权限不足或配置关闭
    #[cfg(feature = "vpn")]
    Active {
        tun_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TunDevice>>>,
    },
    #[cfg(not(feature = "vpn"))]
    ActiveStub, // 非 VPN 特性构建时的占位符
}

pub struct VpnFlavor {
    state: VpnState,
    config: VpnConfig,
    // 用于将从 TUN 读到的数据发回给 ETP Node (Outbound)
    net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    // 默认路由目标 (VPN 流量的出口节点)
    // 使用 RwLock 保证线程安全，允许在运行时动态切换网关
    gateway_peer: Arc<RwLock<Option<SocketAddr>>>,
}

impl VpnFlavor {
    pub fn new(
        net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        config: Option<VpnConfig>,
    ) -> Arc<Self> {
        let conf = config.unwrap_or_default();
        let caps = PlatformCapabilities::probe();

        // 初始化网关容器
        let gateway_store = Arc::new(RwLock::new(None));

        let state = if !caps.supports_tun {
            warn!("VPN Flavor: Disabled due to lack of OS support or permissions.");
            VpnState::Disabled
        } else {
            Self::init_tun_device(&conf, net_tx.clone(), gateway_store.clone())
        };

        Arc::new(Self {
            state,
            config: conf,
            net_tx,
            gateway_peer: gateway_store,
        })
    }

    /// 设置默认网关 (VPN流量的去向)
    /// 可以在连接建立后调用，或者根据路由策略动态调整
    pub fn set_gateway(&self, peer: SocketAddr) {
        let mut gw = self.gateway_peer.write();
        *gw = Some(peer);
        info!("VPN Flavor: Default gateway set to {}", peer);
    }

    /// 清除网关 (暂停 VPN 转发)
    pub fn clear_gateway(&self) {
        let mut gw = self.gateway_peer.write();
        *gw = None;
        info!("VPN Flavor: Default gateway cleared");
    }

    #[cfg(feature = "vpn")]
    fn init_tun_device(
        config: &VpnConfig, 
        net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        gateway_store: Arc<RwLock<Option<SocketAddr>>>
    ) -> VpnState {
        let mut tun_conf = Configuration::default();
        tun_conf
            .queues(4) // 开启多队列，对应 CPU 核心数，默认为4
            .address(config.virtual_ip)
            .netmask(config.virtual_mask)
            .mtu(config.mtu)
            .up();

        #[cfg(target_os = "linux")]
        tun_conf.platform(|cfg| { cfg.packet_information(false); });

        match tun::create_as_async(&tun_conf) {
            Ok(dev) => {
                info!("VPN Flavor: TUN device created (IP: {})", config.virtual_ip);
                let (mut reader, writer) = tokio::io::split(dev);
                let mtu = config.mtu as usize;
                
                // 启动 TUN 读取循环 (TUN -> ETP)
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096]; // 足够大以容纳 MTU + Padding
                    
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(n) => {
                                if n == 0 { break; }
                                
                                // 1. 检查是否有有效的网关
                                let target_peer = {
                                    let gw = gateway_store.read();
                                    *gw
                                };

                                if let Some(peer) = target_peer {
                                    let mut packet = buf[..n].to_vec();
                                    
                                    // 2. 应用 Traffic Morphing (混淆流量特征)
                                    TrafficMorpher::morph(&mut packet, mtu);
                                    
                                    // 3. 发送给 ETP 引擎
                                    // VPN 流量封装为 Stream 数据。接收端 Flavor 会解析。
                                    // 这里的 data 就是原始 IP 包 (经过 Morph)。
                                    if let Err(_) = net_tx.send((peer, packet)).await {
                                        warn!("VPN Flavor: Engine channel closed, stopping TUN reader");
                                        break; 
                                    }
                                } else {
                                    // 如果没有网关，丢弃包（或暂存，但UDP丢弃更安全）
                                    // 仅在 trace 级别打印，防止日志爆炸
                                    trace!("VPN Flavor: No gateway set, dropping packet len {}", n);
                                }
                            }
                            Err(e) => {
                                error!("TUN read error: {}", e);
                                break;
                            }
                        }
                    }
                });

                VpnState::Active {
                    tun_writer: Arc::new(tokio::sync::Mutex::new(writer)),
                }
            }
            Err(e) => {
                error!("Failed to create TUN device: {}", e);
                VpnState::Disabled
            }
        }
    }

    #[cfg(not(feature = "vpn"))]
    fn init_tun_device(
        _config: &VpnConfig, 
        _net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        _gw: Arc<RwLock<Option<SocketAddr>>>
    ) -> VpnState {
        warn!("VPN feature not compiled in.");
        VpnState::Disabled
    }
}

impl CapabilityProvider for VpnFlavor {
    fn capability_id(&self) -> String { "etp.flavor.vpn.v1".into() }
}

impl Flavor for VpnFlavor {
    fn priority(&self) -> u8 { 200 } // 高优先级，处理实时 IP 包

    fn on_stream_data(&self, _ctx: FlavorContext, data: &[u8]) -> bool {
        match &self.state {
            VpnState::Disabled => false, 
            #[cfg(not(feature = "vpn"))]
            VpnState::ActiveStub => false,
            #[cfg(feature = "vpn")]
            VpnState::Active { tun_writer } => {
                // 将接收到的 ETP 数据包写入 TUN 设备
                
                // 1. 去除混淆填充
                let valid_data = TrafficMorpher::unmorph(data);
                
                if valid_data.is_empty() { return true; }

                let writer = tun_writer.clone();
                let packet = valid_data.to_vec();
                
                // 异步写入，避免阻塞协议栈
                tokio::spawn(async move {
                    let mut lock = writer.lock().await;
                    if let Err(e) = lock.write_all(&packet).await {
                        error!("TUN write failed: {}", e);
                    }
                });
                
                true // 已处理，拦截
            }
        }
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        info!("VPN Flavor: Peer connected {}", peer);
        // 策略：如果当前没有网关，将第一个连接的 VPN 节点设为默认网关
        // 生产级：应该有更复杂的路由表或 metric 检查
        let mut gw = self.gateway_peer.write();
        if gw.is_none() {
            *gw = Some(peer);
            info!("VPN Flavor: Auto-configured {} as default gateway", peer);
        }
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        info!("VPN Flavor: Peer disconnected {}", peer);
        let mut gw = self.gateway_peer.write();
        if *gw == Some(peer) {
            *gw = None;
            warn!("VPN Flavor: Default gateway lost!");
        }
    }
}
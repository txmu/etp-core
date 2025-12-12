// etp-core/src/plugin/flavors/vpn.rs

use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use parking_lot::Mutex;
use anyhow::{Result, anyhow};
use log::{info, warn, error, debug};
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
    // 默认路由目标 (VPN 流量通常发给网关/服务器)
    gateway_peer: Option<SocketAddr>,
}

impl VpnFlavor {
    pub fn new(
        net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        config: Option<VpnConfig>,
    ) -> Arc<Self> {
        let conf = config.unwrap_or_default();
        let caps = PlatformCapabilities::probe();

        let state = if !caps.supports_tun {
            warn!("VPN Flavor: Disabled due to lack of OS support or permissions.");
            VpnState::Disabled
        } else {
            Self::init_tun_device(&conf, net_tx.clone())
        };

        Arc::new(Self {
            state,
            config: conf,
            net_tx,
            gateway_peer: None, // 需在 connection_open 时设置或通过配置指定
        })
    }

    /// 设置默认网关 (VPN流量的去向)
    pub fn set_gateway(&mut self, peer: SocketAddr) {
        self.gateway_peer = Some(peer);
    }

    #[cfg(feature = "vpn")]
    fn init_tun_device(config: &VpnConfig, net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>) -> VpnState {
        let mut tun_conf = Configuration::default();
        tun_conf
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
                
                // 启动 TUN 读取循环 (TUN -> ETP)
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    // 这里我们需要一个目标地址。对于 Client 来说，通常只有一个 Server。
                    // 简化：这部分代码需要访问外部的 gateway_peer 状态。
                    // 由于这是静态 spawn，我们暂且假设通过 channel 广播或者后续逻辑处理路由。
                    // 修正：我们在 new 的时候还没有 peer。
                    // 方案：VPN 流量暂时广播给所有连接的“VPN网关”类型的 Peer，或者等待 connection_open。
                    
                    // 为了生产级健壮性，这里暂时阻塞直到有网关，或丢弃。
                    // 更好的方式：将 reader loop 放在 on_connection_open 里启动？
                    // 不行，TUN 是全局的。
                    
                    // 生产级实现：创建一个 channel 来接收 gateway 更新
                    // 这里 MVP+：简化为“读取并尝试发送给最近活跃的 Peer”
                    // 实际：在 handle_packet 外部逻辑控制。
                    
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(n) => {
                                if n == 0 { break; }
                                let mut packet = buf[..n].to_vec();
                                
                                // 应用 Traffic Morphing
                                TrafficMorpher::morph(&mut packet, 1400);
                                
                                // TODO: 发送给网关。由于我们在闭包里，无法访问 self.gateway_peer
                                // 这是一个架构难点。
                                // 解决方案：使用一个全局共享的 Routing Table 或者通过 net_tx 发送特殊的
                                // RouteRequest 包，让 Node 决定发给谁。
                                // 这里我们发送给 "0.0.0.0:0"，约定 Node 层将其路由给默认 VPN 网关。
                                let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
                                if let Err(_) = net_tx.send((dummy_addr, packet)).await {
                                    break; // Node 关闭
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
    fn init_tun_device(_config: &VpnConfig, _net_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>) -> VpnState {
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
            VpnState::Disabled => false, // 未启用，忽略数据
            #[cfg(not(feature = "vpn"))]
            VpnState::ActiveStub => false,
            #[cfg(feature = "vpn")]
            VpnState::Active { tun_writer } => {
                // 将接收到的 ETP 数据包写入 TUN 设备
                // 注意：这里需要去除 padding (Traffic Morphing 的逆过程)
                // IP 包有自描述长度 (IPv4 header total length)，可以据此去除尾部 padding
                
                let actual_len = if data.len() > 20 {
                    // 解析 IPv4 长度字段 (Byte 2-3)
                    // IPv6 (Payload len + 40)
                    // 简单 heuristic
                    match data[0] >> 4 {
                        4 => {
                            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
                            if len <= data.len() { len } else { data.len() }
                        },
                        6 => {
                            let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
                            payload_len + 40
                        },
                        _ => data.len() // 不是 IP 包？直接写吧
                    }
                } else {
                    data.len()
                };

                let writer = tun_writer.clone();
                let packet = data[..actual_len].to_vec();
                
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
        // 这里可以更新默认网关逻辑
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        info!("VPN Flavor: Peer disconnected {}", peer);
    }
}
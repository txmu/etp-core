// etp-core/src/network/nat.rs

use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use log::{info, warn, debug, error};
use igd_next::{search_gateway, SearchOptions};
use governor::{Quota, RateLimiter};
use governor::state::{InMemoryState, NotKeyed};
use governor::clock::DefaultClock;
use std::num::NonZeroU32;

/// NAT 穿透管理器
pub struct NatManager {
    /// 速率限制器 (全局 NAT 操作限制，防止 API 滥用)
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// 外部地址缓存
    public_addr: Option<SocketAddr>,
}

impl NatManager {
    pub fn new() -> Self {
        // 配置限流：每秒最多 2 次 NAT 操作 (UPnP 请求或重映射)
        let quota = Quota::per_second(NonZeroU32::new(2).unwrap());
        Self {
            rate_limiter: Arc::new(RateLimiter::direct(quota)),
            public_addr: None,
        }
    }

    /// 尝试通过 UPnP 映射端口
    /// local_port: 本地监听的 UDP 端口
    /// lease_duration: 映射有效期 (秒)
    pub fn map_port_upnp(&mut self, local_port: u16, lease_duration: u64) -> Result<SocketAddr> {
        // Anti-Spam Check
        if self.rate_limiter.check().is_err() {
            return Err(anyhow!("NAT rate limit exceeded"));
        }

        info!("Attempting UPnP port mapping for port {}...", local_port);

        let opts = SearchOptions {
            timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        };

        match search_gateway(opts) {
            Ok(gateway) => {
                let local_ip = std::net::Ipv4Addr::new(0, 0, 0, 0); // 绑定所有
                // 外部端口建议与内部一致，如果不一致网关会分配
                let external_port = gateway.add_port(
                    igd_next::PortMappingProtocol::UDP,
                    local_port,
                    local_ip.into(), // 这里的 local_ip 实际上应该是本机在局域网的 IP，igd 库通常能自动推断
                    lease_duration as u32,
                    "ETP Node",
                )?;

                let external_ip = gateway.get_external_ip()?;
                let public_socket = SocketAddr::new(IpAddr::V4(external_ip), external_port);
                
                info!("UPnP Success: External address is {}", public_socket);
                self.public_addr = Some(public_socket);
                Ok(public_socket)
            }
            Err(e) => {
                warn!("UPnP failed: {}", e);
                Err(anyhow!("UPnP failed: {}", e))
            }
        }
    }

    /// 生成 STUN 探测包 (Hole Punching Payload)
    /// 生产级应包含 Cookie 和 Transaction ID
    pub fn generate_stun_probe(&self) -> Vec<u8> {
        // 简单实现：[Magic(4)][TxID(12)]
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // Magic Cookie
        let tx_id: [u8; 12] = rand::random();
        buf.extend_from_slice(&tx_id);
        buf
    }

    /// 验证接收到的探测包是否合法 (Anti-Spam: Drop garbage)
    pub fn validate_stun_probe(data: &[u8]) -> bool {
        if data.len() < 16 { return false; }
        if &data[0..4] != &[0xDE, 0xAD, 0xBE, 0xEF] { return false; }
        true
    }
}
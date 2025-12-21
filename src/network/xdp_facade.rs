// etp-core/src/network/xdp_facade.rs

//! # XDP Facade - 硬件加速开发套件
//! 提供了对网卡特性的深度嗅探与 ETP 引擎的无缝绑定。

#![cfg(feature = "xdp")]

use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};
use log::{info, warn, error, debug};
use anyhow::{Result, anyhow, Context};
use crate::network::node::{EtpEngine, EtpHandle, NodeConfig};
use crate::network::xda_transport::XdpTransport;
use crate::plugin::{PluginRegistry, Dialect};

pub struct XdpEngineFactory;

impl XdpEngineFactory {
    /// 创设并启动 XDP 节点
    pub async fn spawn(
        iface: &str,
        config: NodeConfig,
        dialects: Vec<Arc<dyn Dialect>>,
    ) -> Result<(EtpHandle, tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)>)> {
        
        info!("XDP-Facade: Deploying hardware-protected node on '{}'", iface);

        // 1. 系统优化：取消内存锁定限制 (AF_XDP 必需)
        Self::lift_rlimit()?;

        // 2. 深度硬件探测
        let caps = Self::probe_interface_capabilities(iface)?;
        if !caps.has_xdp {
            return Err(anyhow!("Interface {} does not support XDP", iface));
        }
        info!("XDP-Facade: Interface caps: Native={}, MultiQueue={}", caps.has_native, caps.multi_queue);

        // 3. 初始化插件系统
        let registry = Arc::new(PluginRegistry::new());
        for d in dialects { registry.register_dialect(d); }
        registry.register_flavor(Arc::new(crate::plugin::StandardFlavor));

        // 4. 构建传输层
        let port = config.bind_addr.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(4433);
        let transport = Arc::new(XdpTransport::new(iface, 0, port)?);

        // 5. 链接 TokenManager 同步逻辑 (关键：建立用户态到内核态的桥梁)
        let token_mgr = registry.token_manager.clone();
        token_mgr.link_xdp_transport(transport.clone());

        // 6. 配置内核态 ACL 与 端口
        transport.set_config_map(0, port as u32)?; // Port
        transport.set_config_map(1, 1)?;           // Enable ACL by default

        // 7. 启动引擎
        let (engine, handle, app_rx) = EtpEngine::new_with_transport(config, registry, transport).await?;
        tokio::spawn(async move { if let Err(e) = engine.run().await { error!("XDP Engine Crash: {}", e); } });

        Ok((handle, app_rx))
    }

    /// 使用 Netlink 和系统文件执行深层硬件探测
    fn probe_interface_capabilities(iface: &str) -> Result<InterfaceCaps> {
        use std::fs;
        let mut caps = InterfaceCaps { has_xdp: false, has_native: false, multi_queue: false };
        
        // A. 检查内核 XDP 暴露位
        let path = format!("/sys/class/net/{}/xdp_features", iface);
        if let Ok(feat) = fs::read_to_string(path) {
            let val = u64::from_str_radix(feat.trim().trim_start_matches("0x"), 16).unwrap_or(0);
            caps.has_xdp = val > 0;
            caps.has_native = (val & (1 << 0)) != 0; // XDP_F_NATIVE
        }

        // B. 检查队列数 (判断多核并行潜力)
        let queue_path = format!("/sys/class/net/{}/queues", iface);
        if let Ok(entries) = fs::read_dir(queue_path) {
            caps.multi_queue = entries.count() > 1;
        }

        Ok(caps)
    }

    fn lift_rlimit() -> Result<()> {
        unsafe {
            let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
                return Err(anyhow!("RLIMIT_MEMLOCK failed. Run with sudo."));
            }
        }
        Ok(())
    }
}

struct InterfaceCaps { has_xdp: bool, has_native: bool, multi_queue: bool }
// etp-core/src/anonymity/facade.rs

use std::sync::Arc;
use std::path::PathBuf;
use std::net::SocketAddr;
use tokio::sync::{RwLock, mpsc};
use log::{info, warn, error};
use anyhow::{Result, anyhow, Context};

// Core
use crate::network::node::{EtpEngine, EtpHandle, NodeConfig};
use crate::network::node::UdpTransport; // 需要手动构建 UDP Transport
use crate::plugin::PluginRegistry;
use crate::transport::injection::AclManager;

// Anonymity Module
use super::{
    adapter::{TorDynamicTransport, HybridTransport},
    isolation::{IsolationManager, SecurityLevel},
    canary::CanaryInterceptor,
    DeepProfile
};

/// 门面当前状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacadeState {
    Initializing,
    Running,
    EmergencyLockdown,
}

/// 深度匿名门面 (The Facade)
pub struct DeepAnonymityFacade {
    /// 动态配置
    profile: RwLock<DeepProfile>,
    
    /// 状态标志
    state: RwLock<FacadeState>,
    
    /// 隔离管理器 (Dom0)
    isolation_mgr: Arc<IsolationManager>,
    
    /// 全局 ACL (防火墙联动)
    global_acl: Arc<AclManager>,

    /// 持有 Transport 引用以便运行时更新路由表 (Hybrid Mode only)
    /// 因为 Transport 被 move 给了 Engine，我们需要保留一份 Weak 或者 Arc 克隆
    hybrid_transport: RwLock<Option<Arc<HybridTransport>>>,
}

impl DeepAnonymityFacade {
    pub fn new(profile: DeepProfile, storage_base: PathBuf) -> Self {
        Self {
            profile: RwLock::new(profile),
            state: RwLock::new(FacadeState::Initializing),
            isolation_mgr: Arc::new(IsolationManager::new(storage_base)),
            global_acl: Arc::new(AclManager::new(true)),
            hybrid_transport: RwLock::new(None),
        }
    }

    // ========================================================================
    //  主节点启动逻辑
    // ========================================================================

    pub async fn spawn_main_node(
        &self, 
        mut config: NodeConfig, 
        mut registry: PluginRegistry
    ) -> Result<(EtpHandle, mpsc::Receiver<(SocketAddr, Vec<u8>)>)> {
        
        let mut state = self.state.write().await;
        if *state == FacadeState::EmergencyLockdown {
            return Err(anyhow!("Cannot spawn node: System in LOCKDOWN mode"));
        }

        let profile = self.profile.read().await.clone();

        // 1. 注入主动防御 (Canary)
        if profile.enable_canary_traps {
            let canary = Arc::new(CanaryInterceptor::new(self.global_acl.clone()));
            registry.register_default_interceptor(canary);
            info!("Facade: Canary defense activated.");
        }

        // 2. 配置传输层
        let (engine, handle, rx) = if profile.enable_external_anonymity {
            
            // --- Darknet / Hybrid Mode ---
            let proxy = profile.proxy_addr
                .ok_or_else(|| anyhow!("Anonymity enabled but no proxy address configured"))?;
            
            // 创建 Tor 传输层
            let tor_trans = TorDynamicTransport::new(&proxy)
                .context("Failed to initialize Tor Transport")?;

            if true { 
                // 暂时假设开启 "Hybrid" 模式作为高级特性的默认行为
                // 因为 Hybrid 包含 Pure Tor 的能力，且更灵活
                
                // 初始化 UDP
                let udp_sock = tokio::net::UdpSocket::bind(&config.bind_addr).await?;
                // 优化 UDP buffer
                let _ = udp_sock.set_recv_buffer_size(config.recv_buffer_size);
                let _ = udp_sock.set_send_buffer_size(config.send_buffer_size);
                let udp_trans = Arc::new(UdpTransport(Arc::new(udp_sock)));

                // 组合
                let hybrid = HybridTransport::new(udp_trans, tor_trans.clone());
                
                // 保存引用以便后续 map_domain
                *self.hybrid_transport.write().await = Some(hybrid.clone());

                // 注入 Engine
                EtpEngine::new_with_transport(config, Arc::new(registry), hybrid).await?
            
            } else {
                // Pure Darknet Mode (No UDP) - Logic placeholder
                // 如果需要纯 Darknet，不绑定 UDP，直接用 TorDynamicTransport
                EtpEngine::new_with_transport(config, Arc::new(registry), tor_trans).await?
            }

        } else {
            // --- Clearnet Mode ---
            EtpEngine::new(config, Arc::new(registry)).await?
        };

        *state = FacadeState::Running;
        
        // 3. 后台运行
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                error!("Main Node Engine stopped: {}", e);
            }
        });

        Ok((handle, rx))
    }

    // ========================================================================
    //  动态功能 API
    // ========================================================================

    /// 注册一个 Onion 地址，并获取可用于 send_data 的虚拟 SocketAddr
    /// 仅在 Hybrid 或 Darknet 模式下有效
    pub async fn register_onion_peer(&self, onion_domain: &str) -> Result<SocketAddr> {
        let guard = self.hybrid_transport.read().await;
        if let Some(trans) = guard.as_ref() {
            let addr = trans.map_onion_address(onion_domain);
            info!("Facade: Mapped {} -> {}", onion_domain, addr);
            Ok(addr)
        } else {
            Err(anyhow!("Transport does not support onion mapping (Check if Anonymity is enabled)"))
        }
    }

    /// 紧急关停 (Panic Button)
    /// level 0: 停止网络
    /// level 1: 停止 + 内存清理
    /// level 2: 停止 + 内存清理 + 磁盘销毁
    pub async fn emergency_shutdown(&self, level: u8) {
        warn!("!!! EMERGENCY SHUTDOWN TRIGGERED (Level {}) !!!", level);
        
        let mut state = self.state.write().await;
        *state = FacadeState::EmergencyLockdown;

        // 1. 封锁网络：通过 ACL 禁止所有新握手
        // 实际上 ACL 需要一个 clear_all_whitelist 方法
        // 这里演示逻辑：
        // self.global_acl.clear_whitelist(); 
        // self.global_acl.enable_strict_mode();

        // 2. 销毁隔离域
        if level >= 2 {
            self.isolation_mgr.panic_nuke(SecurityLevel::Vault).await;
            self.isolation_mgr.panic_nuke(SecurityLevel::Standard).await;
            self.isolation_mgr.panic_nuke(SecurityLevel::Untrusted).await;
        }

        // 3. 进程退出 (Optional)
        std::process::exit(1);
    }
}
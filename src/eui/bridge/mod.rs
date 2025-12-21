// src/eui/bridge/mod.rs

use std::net::SocketAddr;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, error, debug};
use crate::network::node::{EtpHandle, Command};
use super::EuiCommand;

/// UI 指令桥接器
/// 负责将 UI 层面的非结构化请求（如字符串地址）转换为内核需要的结构化指令
pub struct UiCommandBridge {
    /// 持有内核控制句柄
    handle: EtpHandle,
}

impl UiCommandBridge {
    /// 创建新的桥接器实例
    pub fn new(handle: EtpHandle) -> Self {
        Self { handle }
    }

    /// 执行 UI 指令分发
    /// 
    /// 此方法是异步的，Backend（如 Slint 事件回调）应通过 `tokio::spawn` 
    /// 或 GUI 框架提供的异步机制调用它。
    pub async fn dispatch(&self, eui_cmd: EuiCommand) -> Result<()> {
        match eui_cmd {
            // 1. 会话生命周期管理：断开连接
            EuiCommand::DisconnectPeer(addr_raw) => {
                let addr = self.parse_addr(&addr_raw)?;
                info!("UIBridge: Dispatching CloseSession for {}", addr);
                
                self.handle.cmd_tx.send(Command::CloseSession {
                    target: addr,
                    reason: "Terminated by user via EUI".to_string(),
                }).await.map_err(|_| anyhow!("Kernel command channel dropped"))?;
                Ok(())
            }

            // 2. 安全强化：强制重协商
            EuiCommand::TriggerRekey(addr_raw) => {
                let addr = self.parse_addr(&addr_raw)?;
                info!("UIBridge: Dispatching RekeySession for {}", addr);

                self.handle.cmd_tx.send(Command::RekeySession { 
                    target: addr 
                }).await.map_err(|_| anyhow!("Kernel command channel dropped"))?;
                Ok(())
            }

            // 3. 实时策略调整：掩护流量开关
            EuiCommand::ToggleCoverTraffic(enabled) => {
                debug!("UIBridge: Updating Anonymity Policy -> CoverTraffic={}", enabled);
                
                self.handle.cmd_tx.send(Command::UpdateAnonymityConfig { 
                    enable_cover: enabled 
                }).await.map_err(|_| anyhow!("Kernel command channel dropped"))?;
                Ok(())
            }

            // 4. 系统管理：停机指令
            EuiCommand::ShutdownNode => {
                warn!("UIBridge: !!! EMERGENCY SHUTDOWN REQUEST RECEIVED FROM UI !!!");
                
                self.handle.cmd_tx.send(Command::Shutdown)
                    .await.map_err(|_| anyhow!("Kernel command channel dropped"))?;
                Ok(())
            }

            // 5. RSS 逻辑：通常在 EuiManager 层面拦截，此处作为冗余处理
            EuiCommand::AddRssSource(label, url) => {
                info!("UIBridge: New RSS Source requested - {}: {}", label, url);
                // RSS 属于 UI 侧逻辑，此处可返回 Err 通知 Facade 拦截处理
                Err(anyhow!("RSS command should be handled by EuiManager internal state"))
            }
        }
    }

    /// 内部辅助：将 UI 字符串地址安全地解析为 SocketAddr
    /// 支持错误上下文包装，以便在 UI 上展示错误原因
    fn parse_addr(&self, raw: &str) -> Result<SocketAddr> {
        raw.parse::<SocketAddr>()
            .map_err(|e| anyhow!("Invalid socket address '{}': {}", raw, e))
            .context("UIBridge: Peer address parsing failed")
    }
}

// ============================================================================
//  辅助 Trait 实现 (针对 Backend 的便捷调用)
// ============================================================================

/// 允许 Backend 通过简单的 Handle 扩展直接调用桥接逻辑
pub trait BackendBridgeExt {
    fn bridge(&self) -> UiCommandBridge;
}

impl BackendBridgeExt for EtpHandle {
    fn bridge(&self) -> UiCommandBridge {
        UiCommandBridge::new(self.clone())
    }
}
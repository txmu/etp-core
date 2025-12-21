// src/eui/backend/web/mod.rs

#![cfg(any(feature = "eui-gui-tauri", feature = "eui-gui-electron"))]

pub mod jsonrpc;
pub mod tauri_bridge;

use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::{Result, Context};
use tokio::net::TcpListener;
use tokio::sync::watch;
use log::{info, error, warn};

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use self::tauri_bridge::WebBridgeManager;

pub struct WebBackend {
    manager: Arc<WebBridgeManager>,
    listen_addr: SocketAddr,
    /// 停机广播发送端
    shutdown_tx: watch::Sender<bool>,
}

impl WebBackend {
    pub fn new(addr: &str, token: &str) -> Self {
        let (tx, _) = watch::channel(false);
        Self {
            manager: Arc::new(WebBridgeManager::new(token)),
            listen_addr: addr.parse().unwrap_or(([127, 0, 0, 1], 10101).into()),
            shutdown_tx: tx,
        }
    }
}

impl EuiBackend for WebBackend {
    fn name(&self) -> &'static str { "EUI-Web-Tauri-HyperBridge" }

    fn init(&self) -> Result<()> {
        info!("WebBackend: Visual bridge stack pre-flight check passed.");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        let addr = self.listen_addr;
        let manager = Arc::clone(&self.manager);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        
        // 启动异步驱动
        tokio::spawn(async move {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("WebBackend: Port {} bind fatal error: {}", addr, e);
                    return;
                }
            };

            info!("WebBackend: Ready for upstream UI connection at ws://{}", addr);

            loop {
                tokio::select! {
                    // 处理新连接
                    accept_res = listener.accept() => {
                        if let Ok((stream, peer)) = accept_res {
                            let m = Arc::clone(&manager);
                            let h = handle.clone();
                            tokio::spawn(async move {
                                debug!("WebBackend: Incoming UI session from {}", peer);
                                if let Err(e) = m.handle_session(stream, h).await {
                                    debug!("WebBackend: Session {} ended: {}", peer, e);
                                }
                            });
                        }
                    }
                    // 监听停机信号
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            warn!("WebBackend: Breaking accept loop for shutdown.");
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        let m = Arc::clone(&self.manager);
        tokio::spawn(async move {
            m.broadcast_snapshot(snapshot).await;
        });
    }

    fn shutdown(&self) {
        warn!("WebBackend: Initializing graceful shutdown sequence...");
        // 1. 发送逻辑停机信号给 accept loop
        let _ = self.shutdown_tx.send(true);
        
        // 2. 通知所有已连接的客户端
        let m = Arc::clone(&self.manager);
        tokio::spawn(async move {
            m.notify_halt("Node shutting down via EUI").await;
        });
    }
}
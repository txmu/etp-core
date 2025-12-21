// src/eui/backend/gui/slint/mod.rs

#![cfg(feature = "eui-gui-slint")]

use std::sync::Arc;
use parking_lot::RwLock;
use slint::{ComponentHandle, ModelHandle, VecModel, SharedString, Color};
use anyhow::{Result, anyhow};
use log::{info, error, debug};

use crate::network::node::EtpHandle;
use crate::eui::state::{NodeSummary, SessionBrief};
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;

// 生成的模块包含
slint::include_modules!();

/// 生产级 Slint 后端
pub struct SlintBackend {
    /// 核心 UI 句柄，使用弱引用防止与 Tokio 任务产生循环计数
    window_handle: Arc<RwLock<Option<slint::Weak<MainWindow>>>>,
}

impl SlintBackend {
    pub fn new() -> Self {
        Self {
            window_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// 辅助：将字节单位转换为人类可读格式
    fn format_bytes(b: u64) -> String {
        if b > 1024 * 1024 * 1024 { format!("{:.2} GB", b as f64 / 1.074e+9) }
        else if b > 1024 * 1024 { format!("{:.1} MB", b as f64 / 1.049e+6) }
        else { format!("{:.1} KB", b as f64 / 1024.0) }
    }

    /// 辅助：计算直方图的归一化高度
    fn normalize_history(data: &[u64]) -> Vec<f32> {
        let max = data.iter().max().cloned().unwrap_or(1).max(1);
        data.iter().map(|&v| (v as f32 / max as f32).clamp(0.01, 1.0)).collect()
    }
}

impl EuiBackend for SlintBackend {
    fn name(&self) -> &'static str { "Slint-Cyber-Core" }

    fn init(&self) -> Result<()> {
        info!("SlintBackend: Optimizing GPU layers for ETP Monitor...");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        let ui = MainWindow::new().map_err(|e| anyhow!("Slint Init Fail: {}", e))?;
        
        // 存储弱引用，供 update 方法跨线程调度
        *self.window_handle.write() = Some(ui.as_weak());

        // --- A. 指令映射 (UI -> Bridge -> Kernel) ---
        let bridge = Arc::new(handle.bridge());

        let b1 = bridge.clone();
        ui.on_shutdown_node(move || {
            let b = b1.clone();
            tokio::spawn(async move { let _ = b.dispatch(EuiCommand::ShutdownNode).await; });
        });

        let b2 = bridge.clone();
        ui.on_disconnect_peer(move |addr| {
            let b = b2.clone();
            let a = addr.to_string();
            tokio::spawn(async move { let _ = b.dispatch(EuiCommand::DisconnectPeer(a)).await; });
        });

        let b3 = bridge.clone();
        ui.on_rekey_peer(move |addr| {
            let b = b3.clone();
            let a = addr.to_string();
            tokio::spawn(async move { let _ = b.dispatch(EuiCommand::TriggerRekey(a)).await; });
        });

        ui.on_open_external_link(|url| {
            let _ = webbrowser::open(url.as_str());
        });

        // --- B. 运行主循环 (接管当前线程) ---
        ui.run().map_err(|e| anyhow!("Slint Runtime Error: {}", e))
    }

    fn update(&self, snapshot: NodeSummary) {
        let weak_opt = self.window_handle.read().clone();
        if let Some(weak) = weak_opt {
            let _ = weak.upgrade_in_event_loop(move |ui| {
                // 1. 更新基础标签
                ui.set_node_id_short(SharedString::from(&snapshot.node_id_hex[..8]));
                ui.set_node_uptime(SharedString::from(format!("{}s", snapshot.uptime_secs)));
                
                // 2. 更新速率与总量
                ui.set_bps_in(SharedString::from(format!("{}/s", Self::format_bytes(snapshot.bps_in))));
                ui.set_bps_out(SharedString::from(format!("{}/s", Self::format_bytes(snapshot.bps_out))));
                ui.set_total_in(SharedString::from(Self::format_bytes(snapshot.total_bytes_in)));
                ui.set_total_out(SharedString::from(Self::format_bytes(snapshot.total_bytes_out)));

                // 3. 更新流量图表数据
                let hist_in: Vec<f32> = Self::normalize_history(&snapshot.traffic_history.iter().map(|p| p.bytes_in).collect::<Vec<_>>());
                let hist_out: Vec<f32> = Self::normalize_history(&snapshot.traffic_history.iter().map(|p| p.bytes_out).collect::<Vec<_>>());
                ui.set_history_in(ModelHandle::new(Arc::new(VecModel::from(hist_in))));
                ui.set_history_out(ModelHandle::new(Arc::new(VecModel::from(hist_out))));

                // 4. 会话列表更新 (高效 VecModel 映射)
                let session_models = VecModel::default();
                for s in snapshot.sessions {
                    session_models.push(SessionEntry {
                        identity: s.peer_identity.into(),
                        addr: s.socket_addr.into(),
                        rtt: s.rtt_ms.to_string().into(),
                        flavor: s.flavor.into(),
                        bytes_tx: Self::format_bytes(s.bytes_sent).into(),
                        bytes_rx: "0 B".into(),
                        status_color: Color::from_rgb_u8(0, 242, 255),
                    });
                }
                ui.set_sessions(ModelHandle::new(Arc::new(session_models)));

                // 5. RSS 情报流更新
                #[cfg(feature = "eui-rss")]
                {
                    let rss_models = VecModel::default();
                    for item in snapshot.rss_feeds {
                        rss_models.push(RssEntry {
                            title: item.title.into(),
                            source: item.source_name.into(),
                            date: item.pub_date.into(),
                            link: item.link.into(),
                            is_hot: item.title.contains("URGENT") || item.title.contains("CRITICAL"),
                        });
                    }
                    ui.set_rss_news(ModelHandle::new(Arc::new(rss_models)));
                }

                // 6. 更新 Flavor 标签
                let flavors: Vec<SharedString> = snapshot.enabled_flavors.into_iter().map(SharedString::from).collect();
                ui.set_active_flavors(ModelHandle::new(Arc::new(VecModel::from(flavors))));
            });
        }
    }

    fn shutdown(&self) {
        let weak_opt = self.window_handle.read().clone();
        if let Some(weak) = weak_opt {
            let _ = weak.upgrade_in_event_loop(|ui| ui.hide());
        }
    }
}
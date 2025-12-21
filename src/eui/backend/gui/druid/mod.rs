// src/eui/backend/gui/druid/mod.rs

#![cfg(feature = "eui-gui-druid")]

pub mod data;
pub mod ui;

use std::sync::Arc;
use anyhow::{Result, anyhow};
use druid::{
    AppLauncher, WindowDesc, Selector, ExtEventSink, Target, 
    AppDelegate, DelegateCtx, Command, Env, Handled, Application
};
use parking_lot::Mutex;
use log::{info, error, debug, trace};

use crate::network::node::EtpHandle;
use crate::eui::state::{NodeSummary, SessionBrief};
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::{BackendBridgeExt, UiCommandBridge};
use crate::eui::EuiCommand;
use self::data::{AppState, SessionData, RssData};

// ============================================================================
//  1. Druid 指令选择子 (Selectors)
// ============================================================================

/// 内部通知：接收到新的内核快照，请求刷新 UI
pub const DRUID_UPDATE_SNAPSHOT: Selector<NodeSummary> = Selector::new("etp.eui.druid.update_snapshot");

/// 界面动作：UI 触发了特定的内核指令
pub const DRUID_EXECUTE_ACTION: Selector<EuiCommand> = Selector::new("etp.eui.druid.execute_action");

// ============================================================================
//  2. 核心委托处理器 (AppDelegate)
// ============================================================================

/// EuiDelegate 负责在 UI 线程处理所有异步到达的指令
struct EuiDelegate {
    /// 指令桥接器，用于将 UI 事件转译为内核命令
    bridge: Arc<UiCommandBridge>,
}

impl AppDelegate<AppState> for EuiDelegate {
    fn command(
        &mut self,
        _ctx: &mut DelegateCtx,
        _target: Target,
        cmd: &Command,
        data: &mut AppState,
        _env: &Env,
    ) -> Handled {
        // --- 处理数据刷新 ---
        if let Some(snap) = cmd.get(DRUID_UPDATE_SNAPSHOT) {
            trace!("Druid: Applying state snapshot to UI tree");
            
            // 同步基础标量
            data.node_id = snap.node_id_hex[..12].to_string();
            data.uptime = format!("{}s", snap.uptime_secs);
            data.bps_in = format!("{:.1} KB/s", snap.bps_in as f64 / 1024.0);
            data.bps_out = format!("{:.1} KB/s", snap.bps_out as f64 / 1024.0);
            data.handshake_stats = format!("OK: {} / ERR: {}", snap.handshake_success, snap.handshake_failed);

            // 增量更新会话列表 (利用 im::Vector 的 O(1) 克隆特性)
            let mut new_sessions = im::Vector::new();
            for s in &snap.sessions {
                new_sessions.push_back(SessionData {
                    identity: s.peer_identity.clone(),
                    addr: s.socket_addr.clone(),
                    rtt: s.rtt_ms.to_string(),
                    flavor: s.flavor.clone(),
                    tx_bytes: format!("{:.2} MB", s.bytes_sent as f64 / 1048576.0),
                });
            }
            data.sessions = new_sessions;

            // 处理 RSS 数据流
            #[cfg(feature = "eui-rss")]
            {
                let mut new_rss = im::Vector::new();
                for item in &snap.rss_feeds {
                    new_rss.push_back(RssData {
                        title: item.title.clone(),
                        source: item.source_name.clone(),
                        date: item.pub_date.clone(),
                    });
                }
                data.rss_feed = new_rss;
            }

            return Handled::Yes;
        }

        // --- 处理 UI 交互动作 ---
        if let Some(eui_cmd) = cmd.get(DRUID_EXECUTE_ACTION) {
            let b = Arc::clone(&self.bridge);
            let c = eui_cmd.clone();
            
            // 在非 UI 线程异步发射内核指令，避免阻塞渲染
            tokio::spawn(async move {
                if let Err(e) = b.dispatch(c).await {
                    error!("Druid: Failed to dispatch EUI command: {}", e);
                }
            });
            
            // 如果是停机指令，也同时通知 UI 进程退出
            if let EuiCommand::ShutdownNode = eui_cmd {
                Application::global().quit();
            }
            
            return Handled::Yes;
        }

        Handled::No
    }
}

// ============================================================================
//  3. Backend Trait 实现
// ============================================================================

pub struct DruidBackend {
    /// 外部事件发送句柄。
    /// 必须包装在 Arc<Mutex> 中，因为 EuiBackend::update 是在 Facade 的任务线程中调用的。
    sink: Arc<Mutex<Option<ExtEventSink>>>,
}

impl DruidBackend {
    pub fn new() -> Self {
        Self {
            sink: Arc::new(Mutex::new(None)),
        }
    }
}

impl EuiBackend for DruidBackend {
    fn name(&self) -> &'static str {
        "Druid-Native-Direct2D"
    }

    fn init(&self) -> Result<()> {
        info!("DruidBackend: Preparing data-driven UI context.");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        // 1. 创建主窗口描述符
        let main_window = WindowDesc::new(ui::build_root_widget())
            .title("ETP-CORE // Druid Intelligence Terminal")
            .window_size((1150.0, 850.0));

        // 2. 初始化桥接器与委托
        let bridge = Arc::new(handle.bridge());
        let delegate = EuiDelegate { bridge };

        // 3. 配置启动器
        let launcher = AppLauncher::with_window(main_window)
            .delegate(delegate);

        // 4. 关键：捕获并存储外部事件汇
        // 这一步建立了从 Rust 通用 Facade 到 Druid 窗口系统的唯一通道
        let event_handle = launcher.get_external_handle();
        *self.sink.lock() = Some(event_handle);

        // 5. 阻塞当前线程运行 Druid 事件循环
        info!("DruidBackend: Main thread taking control of the UI loop.");
        launcher.launch(AppState::initial())
            .map_err(|e| anyhow!("Druid launcher failed: {}", e))
    }

    /// 由 Facade 定时调用：将内核状态推送到 Druid 的命令队列中
    fn update(&self, snapshot: NodeSummary) {
        let guard = self.sink.lock();
        if let Some(sink) = guard.as_ref() {
            // submit_command 是线程安全的且立即返回
            if let Err(e) = sink.submit_command(DRUID_UPDATE_SNAPSHOT, snapshot, Target::Auto) {
                error!("DruidBackend: Failed to submit refresh command: {}", e);
            }
        }
    }

    /// 强制退出 UI
    fn shutdown(&self) {
        info!("DruidBackend: Manual shutdown requested.");
        // 在 Druid 中，最优雅的方式是通过 Application 实例发出退出指令
        // 但如果无法通过 handle 访问，通常通过 submit_command 给 Delegate
        let guard = self.sink.lock();
        if let Some(sink) = guard.as_ref() {
            let _ = sink.submit_command(DRUID_EXECUTE_ACTION, EuiCommand::ShutdownNode, Target::Auto);
        }
    }
}
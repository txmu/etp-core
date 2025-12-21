// src/eui/backend/gui/tk/mod.rs

#![cfg(feature = "eui-gui-tk")]

use std::sync::Arc;
use std::time::Duration;
use parking_lot::Mutex;
use anyhow::{Result, anyhow};
use tk::*;
use tokio::sync::mpsc;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;

/// Tk 内部异步信令
#[derive(Debug, Clone)]
enum TkSignal {
    /// 刷新 UI 状态
    Refresh(NodeSummary),
    /// 强制销毁窗口并退出
    Terminate,
}

pub struct TkBackend {
    /// 供 Facade 使用的发射端
    tx: mpsc::UnboundedSender<TkSignal>,
    /// 供 Tk 线程使用的接收端（在 run 中取出）
    rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<TkSignal>>>>,
}

impl TkBackend {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx: Arc::new(Mutex::new(Some(rx))),
        }
    }

    /// 格式化数值辅助函数
    fn format_bps(bps: u64) -> String {
        if bps > 1024 * 1024 {
            format!("{:.2} MB/s", bps as f64 / 1048576.0)
        } else {
            format!("{:.1} KB/s", bps as f64 / 1024.0)
        }
    }
}

impl EuiBackend for TkBackend {
    fn name(&self) -> &'static str { "Tk-Interpreted-Legacy-Core" }

    fn init(&self) -> Result<()> {
        log::info!("TkBackend: Initializing Tcl/Tk binary bridge...");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        // 1. 创建 Tk 解释器根实例
        let root = make_tk().map_err(|e| anyhow!("Failed to initialize Tcl interpreter: {}", e))?;
        root.title("ETP-CORE // Universal Fallback Dashboard");
        root.geometry(1000, 700, -1, -1);

        // 2. 初始化 Tcl 全局变量 (用于原生 Data Binding)
        root.set_var("v_id", "ID: 0x000000000000")?;
        root.set_var("v_uptime", "0s")?;
        root.set_var("v_bps_in", "0.0 KB/s")?;
        root.set_var("v_bps_out", "0.0 KB/s")?;
        root.set_var("v_sessions", "Sessions: 0")?;

        // 3. 构建布局
        // --- 头部 ---
        let header = root.add_label("lbl_header")?
            .textvariable("v_id")?
            .font("Helvetica 16 bold")?
            .foreground("#7aa2f7")?;
        header.grid().row(0).column(0).sticky("w").padx(20).pady(10).tight()?;

        // --- 实时速率区 ---
        let metrics_frame = root.add_frame("frm_metrics")?;
        let lbl_in = metrics_frame.add_label("in")?.textvariable("v_bps_in")?.foreground("#9ece6a")?;
        let lbl_out = metrics_frame.add_label("out")?.textvariable("v_bps_out")?.foreground("#7dcfff")?;
        lbl_in.grid().row(0).column(0).padx(10).tight()?;
        lbl_out.grid().row(0).column(1).padx(10).tight()?;
        metrics_frame.grid().row(1).column(0).sticky("we").padx(20).tight()?;

        // --- 会话列表 (使用 Tk 强大的 Treeview) ---
        let tree = root.add_treeview("tv_sessions")?;
        tree.columns(&["identity", "addr", "rtt", "flavor"])?;
        tree.heading("identity", "Peer Identity")?;
        tree.heading("addr", "Socket Address")?;
        tree.heading("rtt", "RTT")?;
        tree.heading("flavor", "Flavor")?;
        tree.grid().row(2).column(0).sticky("nswe").padx(20).pady(10).tight()?;

        // --- 底部控制 ---
        let footer = root.add_frame("frm_footer")?;
        let lbl_up = footer.add_label("lbl_up")?.textvariable("v_uptime")?;
        
        let bridge = Arc::new(handle.bridge());
        let b_clone = bridge.clone();
        let btn_shutdown = footer.add_button("btn_stop")?
            .text("ABORT NODE")?
            .command(move || {
                let b = b_clone.clone();
                tokio::spawn(async move {
                    let _ = b.dispatch(EuiCommand::ShutdownNode).await;
                });
            })?;
        
        lbl_up.grid().row(0).column(0).padx(10).tight()?;
        btn_shutdown.grid().row(0).column(1).padx(10).tight()?;
        footer.grid().row(3).column(0).sticky("we").padx(20).pady(10).tight()?;

        // 权重配置使 Treeview 可拉伸
        root.grid_row_configure(2, 1.0)?;
        root.grid_column_configure(0, 1.0)?;

        // 4. 核心：实现基于 Tcl 事件循环的轮询逻辑
        // 因为 Tk 主循环是阻塞的，我们需要通过 `after` 递归调度
        let mut rx = self.rx.lock().take().ok_or_else(|| anyhow!("Tk receiver consumed"))?;
        let root_handle = root.clone();
        
        // 我们利用 Tcl 的自定义指令能力包装一个“心跳”
        let poll_interval_ms = 200;

        // 定义递归轮询闭包
        let mut poll_proc = move || -> Result<()> {
            let mut updated = false;
            // 批量清空队列，减少重绘压力
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    TkSignal::Refresh(snap) => {
                        root_handle.set_var("v_id", format!("NODE // {}", &snap.node_id_hex[..12]))?;
                        root_handle.set_var("v_uptime", format!("Uptime: {}s", snap.uptime_secs))?;
                        root_handle.set_var("v_bps_in", format!("IN: {}", Self::format_bps(snap.bps_in)))?;
                        root_handle.set_var("v_bps_out", format!("OUT: {}", Self::format_bps(snap.bps_out)))?;
                        root_handle.set_var("v_sessions", format!("Active: {}", snap.active_sessions_count))?;

                        // 更新 Treeview 列表
                        // 为简单起见采用全量重刷策略，Tk Treeview 处理 100 节点量级极快
                        root_handle.eval("tv_sessions delete [tv_sessions children {}]")?;
                        for s in snap.sessions {
                            let values = format!("{{ {} }} {{ {} }} {{ {}ms }} {{ {} }}", 
                                s.peer_identity, s.socket_addr, s.rtt_ms, s.flavor);
                            root_handle.eval(format!("tv_sessions insert {{}} end -values {{ {} }}", values))?;
                        }
                        updated = true;
                    }
                    TkSignal::Terminate => {
                        log::warn!("TkBackend: Termination signal received.");
                        root_handle.eval("destroy .")?;
                        return Ok(());
                    }
                }
            }

            if updated {
                // 执行 Tcl 更新
                root_handle.eval("update idletasks")?;
            }

            // 递归调度下一次 poll
            // 此处利用 Tcl 原生的 after 机制
            root_handle.eval(format!("after {} {{ poll_rust_queue }}", poll_interval_ms))?;
            Ok(())
        };

        // 在 Tcl 中注册 Rust 闭包为指令
        root.add_command("poll_rust_queue", poll_proc)?;
        
        // 启动首次调度
        root.eval("poll_rust_queue")?;

        // 5. 启动循环
        log::info!("TkBackend: Entering Tcl main loop.");
        root.main_loop();
        
        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        // 无锁发送，Facade 调用此方法是 0 阻塞的
        let _ = self.tx.send(TkSignal::Refresh(snapshot));
    }

    fn shutdown(&self) {
        // 发送 Terminate 信号，由 poll_proc 在 Tcl 线程捕获并执行 destroy
        let _ = self.tx.send(TkSignal::Terminate);
    }
}
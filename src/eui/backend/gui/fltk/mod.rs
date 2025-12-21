// src/eui/backend/gui/fltk/mod.rs

#![cfg(feature = "eui-gui-fltk")]

pub mod theme;

use std::sync::Arc;
use fltk::{
    app, button::Button, frame::Frame, group::{Flex, FlexType, Scroll}, 
    misc::{Chart, ChartType}, prelude::*, window::Window, browser::MultiBrowser,
    enums::{Color, Font, FrameType, Align},
};
use anyhow::{Result, anyhow};

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;
use self::theme::EuiTheme;

/// FLTK 后端内部指令集
#[derive(Clone)]
enum InternalMsg {
    Refresh(NodeSummary),
    Quit,
}

pub struct FltkBackend {
    // 线程安全的消息发射端
    tx: app::Sender<InternalMsg>,
    // 消息接收端（在 run 方法中消费）
    rx: app::Receiver<InternalMsg>,
}

impl FltkBackend {
    pub fn new() -> Self {
        let (s, r) = app::channel::<InternalMsg>();
        Self { tx: s, rx: r }
    }

    fn human_readable_bps(bps: u64) -> String {
        if bps > 1024 * 1024 {
            format!("{:.2} MB/s", bps as f64 / 1048576.0)
        } else {
            format!("{:.1} KB/s", bps as f64 / 1024.0)
        }
    }
}

impl EuiBackend for FltkBackend {
    fn name(&self) -> &'static str { "FLTK-Native-HighSpeed" }

    fn init(&self) -> Result<()> {
        log::info!("FLTK: Registering optimized draw calls...");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        let _app = app::App::default().with_scheme(app::Scheme::Gtk);
        EuiTheme::apply();

        let mut win = Window::default()
            .with_size(1100, 800)
            .with_label("ETP-CORE // FLTK Terminal");
        win.make_resizable(true);

        // --- 1. 顶层容器 (Flex 纵向布局) ---
        let mut root_flex = Flex::default_fill().column();
        root_flex.set_margins(20, 20, 20, 20);
        root_flex.set_pad(15);

        // 标题与 Uptime
        let mut header = Frame::default();
        header.set_label_color(EuiTheme::ACCENT);
        header.set_label_size(22);
        header.set_label_font(Font::HelveticaBold);
        root_flex.set_size(&header, 45);

        // --- 2. 指标图表区 (横向布局) ---
        let mut chart_flex = Flex::default().row();
        
        let mut chart_in = Chart::default();
        chart_in.set_type(ChartType::Line);
        chart_in.set_color(EuiTheme::BG_CARD);
        chart_in.set_label("INGRESS HISTORY");
        chart_in.set_label_color(EuiTheme::GREEN);

        let mut chart_out = Chart::default();
        chart_out.set_type(ChartType::Line);
        chart_out.set_color(EuiTheme::BG_CARD);
        chart_out.set_label("EGRESS HISTORY");
        chart_out.set_label_color(EuiTheme::BLUE);
        
        chart_flex.end();
        root_flex.set_size(&chart_flex, 160);

        // --- 3. 核心数据表格 (Browser) ---
        let mut browser = MultiBrowser::default();
        browser.set_color(EuiTheme::BG_CARD);
        browser.set_text_color(EuiTheme::TEXT_MAIN);
        browser.set_column_widths(&[180, 220, 100, 150]);
        browser.set_column_char('\t');
        browser.add("@BIdentity\t@BAddress\t@BRTT\t@BProtocol");

        // --- 4. RSS 情报滚动区 ---
        let mut rss_browser = MultiBrowser::default();
        rss_browser.set_color(EuiTheme::BG_MAIN);
        rss_browser.set_text_color(Color::from_hex(0xe0af68));
        root_flex.set_size(&rss_browser, 140);

        // --- 5. 底部状态栏 ---
        let mut footer = Flex::default().row();
        let mut stat_label = Frame::default().with_align(Align::Left | Align::Inside);
        stat_label.set_label_color(EuiTheme::TEXT_DIM);

        let mut btn_shutdown = Button::default().with_label("PANIC SHUTDOWN");
        btn_shutdown.set_color(Color::from_hex(0xbb9af7).with_alpha(50));
        btn_shutdown.set_label_color(Color::White);
        footer.set_size(&btn_shutdown, 180);
        footer.end();
        root_flex.set_size(&footer, 40);

        root_flex.end();
        win.end();
        win.show();

        // --- 事件处理 ---
        let bridge = Arc::new(handle.bridge());
        let b_clone = bridge.clone();
        btn_shutdown.set_callback(move |_| {
            let b = b_clone.clone();
            tokio::spawn(async move {
                let _ = b.dispatch(EuiCommand::ShutdownNode).await;
            });
        });

        // 消息泵监听
        let receiver = self.rx.clone();
        app::add_idle3(move |_| {
            if let Some(msg) = receiver.recv() {
                match msg {
                    InternalMsg::Refresh(snap) => {
                        header.set_label(&format!("NODE // {} | Uptime: {}s", &snap.node_id_hex[..12], snap.uptime_secs));
                        stat_label.set_label(&format!("Sessions: {} | Rate: {}/s In, {}/s Out", 
                            snap.active_sessions_count,
                            Self::human_readable_bps(snap.bps_in),
                            Self::human_readable_bps(snap.bps_out)
                        ));

                        // 动态更新图表
                        chart_in.add(snap.bps_in as f64, "", EuiTheme::GREEN);
                        if chart_in.size() > 60 { chart_in.remove(1); }
                        
                        chart_out.add(snap.bps_out as f64, "", EuiTheme::BLUE);
                        if chart_out.size() > 60 { chart_out.remove(1); }

                        // 列表全量同步 (优化：仅在 Session 数变化时清空)
                        browser.clear();
                        browser.add("@BIdentity\t@BAddress\t@BRTT\t@BProtocol");
                        for s in snap.sessions {
                            browser.add(&format!("{}\t{}\t{}ms\t{}", s.peer_identity, s.socket_addr, s.rtt_ms, s.flavor));
                        }

                        #[cfg(feature = "eui-rss")]
                        {
                            rss_browser.clear();
                            for item in snap.rss_feeds {
                                rss_browser.add(&format!("• [{}] {}", item.source_name, item.title));
                            }
                        }
                        
                        app::redraw();
                    },
                    InternalMsg::Quit => app::quit(),
                }
            }
        });

        app::run().map_err(|e| anyhow!("FLTK MainLoop Fail: {}", e))
    }

    fn update(&self, snapshot: NodeSummary) {
        // app::channel 是极少数在 Rust GUI 生态中真正实现零开销跨线程通信的机制
        self.tx.send(InternalMsg::Refresh(snapshot));
        app::awake();
    }

    fn shutdown(&self) {
        self.tx.send(InternalMsg::Quit);
        app::awake();
    }
}
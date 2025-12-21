// src/eui/backend/gui/wx/mod.rs

#![cfg(feature = "eui-gui-wx")]

use std::sync::Arc;
use parking_lot::Mutex;
use anyhow::{Result, anyhow};
use wx::prelude::*;
use wx;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;

// 定义自定义事件 ID，用于跨线程更新
const EVT_UPDATE_SNAPSHOT: i32 = 10001;

pub struct WxBackend {
    // 线程安全的快照缓存
    snapshot_cache: Arc<Mutex<NodeSummary>>,
    // 存储 Frame 的原始指针（wxWidgets 内部管理内存）
    frame_ptr: Arc<Mutex<Option<wx::Frame>>>,
}

impl WxBackend {
    pub fn new() -> Self {
        Self {
            snapshot_cache: Arc::new(Mutex::new(NodeSummary::default())),
            frame_ptr: Arc::new(Mutex::new(None)),
        }
    }

    fn format_bps(bps: u64) -> String {
        if bps > 1024 * 1024 { format!("{:.2} MB/s", bps as f64 / 1048576.0) }
        else { format!("{:.1} KB/s", bps as f64 / 1024.0) }
    }
}

impl EuiBackend for WxBackend {
    fn name(&self) -> &'static str { "wxWidgets-Native-Core" }

    fn init(&self) -> Result<()> {
        log::info!("wxWidgets: Probing native windowing system...");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        wx::App::run(move || {
            let frame = wx::Frame::new(wx::Window::none(), wx::ID_ANY, "ETP-CORE // Native Terminal", 
                                     wx::Point::default(), wx::Size::new(1000, 700), 
                                     wx::DEFAULT_FRAME_STYLE);
            
            let panel = wx::Panel::new(Some(&frame), wx::ID_ANY, wx::Point::default(), wx::Size::default(), 0, "");
            let main_sizer = wx::BoxSizer::new(wx::VERTICAL);

            // 1. Header Area
            let lbl_id = wx::StaticText::new(Some(&panel), wx::ID_ANY, "NODE ID: 0x0000", 
                                          wx::Point::default(), wx::Size::default(), 0, "");
            let font = wx::Font::new(14, wx::FONTFAMILY_TELETYPE, wx::FONTSTYLE_NORMAL, wx::FONTWEIGHT_BOLD, false, "", wx::FONTENCODING_DEFAULT);
            lbl_id.set_font(&font);
            main_sizer.add_window(Some(&lbl_id), 0, wx::ALL | wx::EXPAND, 10, wx::Object::none());

            // 2. Metrics Row
            let metrics_sizer = wx::BoxSizer::new(wx::HORIZONTAL);
            let lbl_in = wx::StaticText::new(Some(&panel), wx::ID_ANY, "IN: 0 KB/s", wx::Point::default(), wx::Size::default(), 0, "");
            let lbl_out = wx::StaticText::new(Some(&panel), wx::ID_ANY, "OUT: 0 KB/s", wx::Point::default(), wx::Size::default(), 0, "");
            metrics_sizer.add_window(Some(&lbl_in), 1, wx::ALL, 5, wx::Object::none());
            metrics_sizer.add_window(Some(&lbl_out), 1, wx::ALL, 5, wx::Object::none());
            main_sizer.add_sizer(Some(&metrics_sizer), 0, wx::EXPAND, 0, wx::Object::none());

            // 3. Session List (ListCtrl)
            let list_sessions = wx::ListCtrl::new(Some(&panel), wx::ID_ANY, wx::Point::default(), wx::Size::default(), wx::LC_REPORT as i64, wx::Validator::none(), "");
            list_sessions.insert_column(0, "Identity", wx::LIST_FORMAT_LEFT, 200);
            list_sessions.insert_column(1, "Address", wx::LIST_FORMAT_LEFT, 250);
            list_sessions.insert_column(2, "RTT", wx::LIST_FORMAT_LEFT, 100);
            main_sizer.add_window(Some(&list_sessions), 1, wx::ALL | wx::EXPAND, 10, wx::Object::none());

            // 4. Footer
            let btn_shutdown = wx::Button::new(Some(&panel), wx::ID_ANY, "Emergency Shutdown", wx::Point::default(), wx::Size::default(), 0, wx::Validator::none(), "");
            main_sizer.add_window(Some(&btn_shutdown), 0, wx::ALIGN_RIGHT | wx::ALL, 10, wx::Object::none());

            panel.set_sizer(Some(&main_sizer), true);
            frame.show(true);

            // --- 事件绑定逻辑 ---
            let h_bridge = handle.bridge();
            btn_shutdown.bind(wx::RUST_EVT_BUTTON, move |_| {
                let b = h_bridge.clone();
                tokio::spawn(async move { let _ = b.dispatch(EuiCommand::ShutdownNode).await; });
            });

            // 注册异步更新处理器
            let snap_ref = self.snapshot_cache.clone();
            frame.bind(wx::RUST_EVT_MENU, move |_| { // 借用 MENU 事件通道作为刷新信号
                let snap = snap_ref.lock();
                lbl_id.set_label(&format!("NODE ID: {}", &snap.node_id_hex[..12]));
                lbl_in.set_label(&format!("IN: {}", Self::human_readable_bps(snap.bps_in)));
                lbl_out.set_label(&format!("OUT: {}", Self::human_readable_bps(snap.bps_out)));

                list_sessions.delete_all_items();
                for (i, s) in snap.sessions.iter().enumerate() {
                    list_sessions.insert_item_text(i as i64, &s.peer_identity);
                    list_sessions.set_item_text(i as i64, 1, &s.socket_addr);
                    list_sessions.set_item_text(i as i64, 2, &format!("{}ms", s.rtt_ms));
                }
            });
        });
        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        *self.snapshot_cache.lock() = snapshot;
        // 在 wxWidgets 中，我们通常发送一个 Dummy 菜单事件来唤醒 UI 线程重绘
        if let Some(frame) = &*self.frame_ptr.lock() {
            let event = wx::CommandEvent::new(wx::RUST_EVT_MENU, wx::ID_ANY);
            frame.queue_event(&event);
        }
    }

    fn shutdown(&self) {
        if let Some(frame) = &*self.frame_ptr.lock() {
            frame.close(true);
        }
    }
}
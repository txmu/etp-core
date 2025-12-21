// src/eui/backend/gui/gtk/mod.rs

#![cfg(feature = "eui-gui-gtk")]

use std::sync::Arc;
use gtk::prelude::*;
use gtk::{Builder, Window, Label, TreeView, ListStore, ListBox, Button};
use anyhow::{Result, anyhow};
use log::{info, error, debug};
use glib::Receiver;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;

/// 内部 UI 更新消息枚举
enum GtkUpdateMsg {
    NewSnapshot(NodeSummary),
}

pub struct GtkBackend {
    // 使用 glib 提供的 Thread-safe Sender
    update_tx: Arc<glib::Sender<GtkUpdateMsg>>,
    // 界面持有的全局状态引用 (只用于初始化)
    ui_rx: Arc<Mutex<Option<glib::Receiver<GtkUpdateMsg>>>>,
}

impl GtkBackend {
    pub fn new() -> Self {
        let (tx, rx) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
        Self {
            update_tx: Arc::new(tx),
            ui_rx: Arc::new(Mutex::new(Some(rx))),
        }
    }

    fn format_bps(bps: u64) -> String {
        if bps > 1024 * 1024 {
            format!("{:.2} MB/s", bps as f64 / 1048576.0)
        } else {
            format!("{:.1} KB/s", bps as f64 / 1024.0)
        }
    }
}

impl EuiBackend for GtkBackend {
    fn name(&self) -> &'static str {
        if cfg!(feature = "gtk2") { "GTK+ 2.0 (Legacy)" } else { "GTK+ 3.0 (Modern)" }
    }

    fn init(&self) -> Result<()> {
        info!("GtkBackend: Initializing GTK environment...");
        gtk::init().map_err(|_| anyhow!("Failed to initialize GTK"))?;
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        // 1. 加载布局
        let builder = Builder::from_string(include_str!("builder.ui"));
        let window: Window = builder.object("main_window").ok_or(anyhow!("UI Object not found"))?;
        
        // 2. 获取控件引用
        let lbl_id: Label = builder.object("lbl_node_id").unwrap();
        let lbl_uptime: Label = builder.object("lbl_uptime").unwrap();
        let lbl_bps_in: Label = builder.object("lbl_bps_in").unwrap();
        let lbl_bps_out: Label = builder.object("lbl_bps_out").unwrap();
        let tree_sessions: TreeView = builder.object("tree_sessions").unwrap();
        let list_rss: ListBox = builder.object("list_rss").unwrap();
        let btn_shutdown: Button = builder.object("btn_shutdown").unwrap();

        // 3. 配置 Session 树形列表 (Identity, Address, RTT, Flavor)
        let model = ListStore::new(&[
            glib::Type::STRING, // Identity
            glib::Type::STRING, // Address
            glib::Type::STRING, // RTT
            glib::Type::STRING, // Flavor
        ]);
        tree_sessions.set_model(Some(&model));
        Self::setup_tree_columns(&tree_sessions);

        // 4. 指令绑定
        let h_clone = handle.clone();
        btn_shutdown.connect_clicked(move |_| {
            let bridge = h_clone.bridge();
            tokio::spawn(async move {
                let _ = bridge.dispatch(EuiCommand::ShutdownNode).await;
            });
        });

        window.connect_delete_event(|_, _| {
            gtk::main_quit();
            Inhibit(false)
        });

        // 5. 核心：建立 UI 更新通道
        let rx = self.ui_rx.lock().take().ok_or(anyhow!("UI Receiver already consumed"))?;
        rx.attach(None, move |msg| {
            match msg {
                GtkUpdateMsg::NewSnapshot(snap) => {
                    lbl_id.set_text(&format!("Node ID: {}", &snap.node_id_hex[..12]));
                    lbl_uptime.set_text(&format!("Uptime: {}s", snap.uptime_secs));
                    lbl_bps_in.set_text(&Self::format_bps(snap.bps_in));
                    lbl_bps_out.set_text(&Self::format_bps(snap.bps_out));

                    // 更新列表
                    model.clear();
                    for s in snap.sessions {
                        model.insert_with_values(None, &[
                            (0, &s.peer_identity),
                            (1, &s.socket_addr),
                            (2, &format!("{}ms", s.rtt_ms)),
                            (3, &s.flavor),
                        ]);
                    }

                    // 更新 RSS (仅清理并重绘改变的部分)
                    list_rss.foreach(|child| list_rss.remove(child));
                    for item in snap.rss_feeds.iter().take(20) {
                        let row = gtk::ListBoxRow::new();
                        let lbl = Label::new(Some(&format!("[{}] {}", item.source_name, item.title)));
                        lbl.set_xalign(0.0);
                        row.add(&lbl);
                        list_rss.add(&row);
                    }
                    list_rss.show_all();
                }
            }
            glib::Continue(true)
        });

        // 6. 显示并进入循环
        window.show_all();
        info!("GtkBackend: Main loop entering...");
        gtk::main();
        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        // 向 GLib 事件循环发送更新请求 (这是线程安全的)
        if let Err(_) = self.update_tx.send(GtkUpdateMsg::NewSnapshot(snapshot)) {
            error!("GtkBackend: Failed to push update to UI thread.");
        }
    }

    fn shutdown(&self) {
        glib::idle_add_local(|| {
            gtk::main_quit();
            glib::Continue(false)
        });
    }
}

impl GtkBackend {
    fn setup_tree_columns(tree: &TreeView) {
        let titles = ["Peer Identity", "Address", "RTT", "Protocol"];
        for (i, &title) in titles.iter().enumerate() {
            let renderer = gtk::CellRendererText::new();
            let col = gtk::TreeViewColumn::new();
            col.set_title(title);
            col.pack_start(&renderer, true);
            col.add_attribute(&renderer, "text", i as i32);
            tree.append_column(&col);
        }
    }
}

use parking_lot::Mutex;
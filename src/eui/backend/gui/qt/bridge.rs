// src/eui/backend/gui/qt/bridge.rs

use qmetaobject::*;
use std::sync::Arc;
use crate::eui::state::{NodeSummary, SessionBrief};

// 定义 Session 条目的简易映射，以便 QML 使用
#[derive(Default, Clone, QGadget)]
pub struct QtSessionItem {
    pub identity: qt_property!(QString),
    pub addr: qt_property!(QString),
    pub rtt: qt_property!(QString),
    pub flavor: qt_property!(QString),
}

/// 核心 Qt 桥接对象
#[derive(QObject, Default)]
pub struct QtBackendBridge {
    base: qt_base!(DefaultObject),

    // --- 响应式属性 ---
    node_id: qt_property!(QString; notify: node_id_changed),
    uptime: qt_property!(QString; notify: uptime_changed),
    bps_in: qt_property!(QString; notify: bps_in_changed),
    bps_out: qt_property!(QString; notify: bps_out_changed),
    
    // 会话列表，使用 QVariantList 承载 QGadget 数组
    sessions: qt_property!(QVariantList; notify: sessions_changed),

    // --- 信号槽 ---
    node_id_changed: qt_signal!(),
    uptime_changed: qt_signal!(),
    bps_in_changed: qt_signal!(),
    bps_out_changed: qt_signal!(),
    sessions_changed: qt_signal!(),

    // --- 槽函数 (被 QML 调用) ---
    shutdown_node: qt_method!(fn(&self)),
    trigger_global_rekey: qt_method!(fn(&self)),

    // 内部句柄持有，用于执行回调逻辑
    pub on_shutdown: Option<Box<dyn Fn() + Send + Sync>>,
}

impl QtBackendBridge {
    /// 将 NodeSummary 转换为 Qt 属性
    pub fn apply_snapshot(&mut self, snap: NodeSummary) {
        self.node_id = snap.node_id_hex[..8].into();
        self.uptime = format!("{}s", snap.uptime_secs).into();
        self.bps_in = format!("{:.1} KB/s", snap.bps_in as f64 / 1024.0).into();
        self.bps_out = format!("{:.1} KB/s", snap.bps_out as f64 / 1024.0).into();

        let mut list = QVariantList::default();
        for s in snap.sessions {
            let item = QtSessionItem {
                identity: s.peer_identity.into(),
                addr: s.socket_addr.into(),
                rtt: s.rtt_ms.to_string().into(),
                flavor: s.flavor.into(),
            };
            list.push(item.to_qvariant());
        }
        self.sessions = list;

        // 触发 UI 刷新信号
        self.node_id_changed();
        self.uptime_changed();
        self.bps_in_changed();
        self.bps_out_changed();
        self.sessions_changed();
    }

    fn shutdown_node(&self) {
        if let Some(f) = &self.on_shutdown {
            f();
        }
    }

    fn trigger_global_rekey(&self) {
        // 逻辑由 Backend 处理
    }
}
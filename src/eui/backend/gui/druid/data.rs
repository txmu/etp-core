// src/eui/backend/gui/druid/data.rs

use druid::{Data, Lens};
use std::sync::Arc;
use crate::eui::state::NodeSummary;

/// 会话行数据模型
#[derive(Clone, Data, Lens)]
pub struct SessionData {
    pub identity: String,
    pub addr: String,
    pub rtt: String,
    pub flavor: String,
    pub tx_bytes: String,
}

/// RSS 条目模型
#[derive(Clone, Data, Lens)]
pub struct RssData {
    pub title: String,
    pub source: String,
    pub date: String,
}

/// Druid 全局应用状态
#[derive(Clone, Data, Lens)]
pub struct AppState {
    pub node_id: String,
    pub uptime: String,
    pub bps_in: String,
    pub bps_out: String,
    pub handshake_stats: String,
    pub sessions: im::Vector<SessionData>,
    pub rss_feed: im::Vector<RssData>,
    pub is_cyberpunk: bool,
}

impl AppState {
    pub fn initial() -> Self {
        Self {
            node_id: "0x0000".into(),
            uptime: "0s".into(),
            bps_in: "0 B/s".into(),
            bps_out: "0 B/s".into(),
            handshake_stats: "S: 0 / F: 0".into(),
            sessions: im::Vector::new(),
            rss_feed: im::Vector::new(),
            is_cyberpunk: true,
        }
    }
}
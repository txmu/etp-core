// src/eui/state.rs

use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// 流量数据点：用于 GUI 绘制历史折线图（如过去 60 秒的带宽波动）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficPoint {
    pub timestamp: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// 会话简报：用于在 TUI/GUI 的列表控件中展示活跃连接
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionBrief {
    /// 对端地址或 NodeID 缩写
    pub peer_identity: String,
    /// 物理 Socket 地址
    pub socket_addr: String,
    /// 该会话累积流量
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// 延迟 (ms)
    pub rtt_ms: u32,
    /// 会话持续时间
    pub uptime_secs: u64,
    /// 活跃的业务风味 (如 "VPN", "Chat")
    pub flavor: String,
}

/// 日志条目：用于 UI 底部的滚动日志窗口
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub module: String,
    pub message: String,
}

/// 节点全局状态快照 (EUI 核心数据模型)
/// 该结构体由 Facade 定时构建并推送给所有 Backend
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeSummary {
    // --- 基础信息 ---
    pub node_id_hex: String,
    pub version: String,
    pub uptime_secs: u64,
    
    // --- 核心指标 ---
    pub active_sessions_count: usize,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub total_cover_bytes: u64, // 掩护流量统计
    
    // --- 实时速率 (由 Facade 通过时间差分算法计算) ---
    pub bps_in: u64,
    pub bps_out: u64,

    // --- 安全与健康 ---
    pub handshake_success: u64,
    pub handshake_failed: u64,
    pub acl_drops: u64,
    pub packet_loss_rate: f32,

    // --- 动态组件状态 ---
    /// 当前加载的所有插件能力 ID
    pub enabled_flavors: Vec<String>,
    /// 正在运行的后台代理 (Agents)
    pub active_agents: Vec<String>,
    
    // --- 列表数据 (用于详情页) ---
    /// 实时会话列表快照
    pub sessions: Vec<SessionBrief>,
    /// 流量历史数据点 (通常保留最近 60-120 个点)
    pub traffic_history: Vec<TrafficPoint>,
    /// 最近的系统日志
    pub logs: Vec<LogEntry>,
    
    // --- [新增] RSS 数据流 ---
    /// 当前聚合的 RSS 新闻流
    pub rss_feeds: Vec<RssItem>,
    /// RSS 刷新状态
    pub rss_last_refresh: u64,
}

impl NodeSummary {
    /// 生产级工厂方法：创建一个带初始数据的快照
    pub fn new(id_hex: String) -> Self {
        Self {
            node_id_hex: id_hex,
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        }
    }

    /// 辅助方法：添加一个新的流量点并保持窗口大小
    pub fn push_traffic_record(&mut self, point: TrafficPoint, max_history: usize) {
        self.traffic_history.push(point);
        if self.traffic_history.len() > max_history {
            self.traffic_history.remove(0);
        }
    }

    /// 辅助方法：添加日志并保持窗口大小
    pub fn push_log(&mut self, entry: LogEntry, max_logs: usize) {
        self.logs.push(entry);
        if self.logs.len() > max_logs {
            self.logs.remove(0);
        }
    }
}
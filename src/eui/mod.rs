// src/eui/mod.rs

pub mod state;
pub mod facade;
pub mod bridge;
pub mod backend; // 统一存放所有 UI 实现

#[cfg(feature = "eui-rss")]
pub mod rss;

/// UI 后端指令：从界面发往内核的逻辑动作
/// 它是对内核底层 Command 的业务封装，增加了 UI 层的意图映射
#[derive(Debug, Clone)]
pub enum EuiCommand {
    /// 断开指定对等点 (参数为 SocketAddr 字符串)
    DisconnectPeer(String),
    /// 动态开关掩护流量
    ToggleCoverTraffic(bool),
    /// 强制对特定 Session 执行密钥轮换
    TriggerRekey(String),
    /// 触发节点物理停机
    ShutdownNode,
    /// [RSS专属] 添加新的订阅源 (label, url)
    AddRssSource(String, String),
}
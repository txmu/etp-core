// src/eui/mod.rs

//! # EUI (Evolutionary User Interface) - 核心门户
//! 
//! 本模块统合了 ETP-Core 的所有可视化表现层逻辑。
//! 支持从 1970 年代的文本终端到 2025 年的硬件加速 GUI。

use std::sync::Arc;
use anyhow::Result;
use serde::{Serialize, Deserialize};

// --- 核心子模块导出 ---
pub mod state;
pub mod facade;
pub mod bridge;
pub mod backend;

#[cfg(feature = "eui-rss")]
pub mod rss;

#[cfg(feature = "eui")]
pub mod auto_layout;

// --- 重新导出关键结构 ---
pub use self::state::{NodeSummary, SessionBrief, TrafficPoint, LogEntry, RssItem};
pub use self::facade::EuiManager;
pub use self::backend::EuiBackend;

// ============================================================================
//  1. 终极后端类型枚举 (The All-In-One Enum)
// ============================================================================

/// 支持的 UI 后端全矩阵类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiBackendType {
    /// 标准命令行解析器 (基于 getopts)
    #[cfg(feature = "eui-cli")]
    Cli,

    /// 终端仪表盘 (基于 ncurses)
    #[cfg(feature = "eui-tui-ncurses")]
    TuiNcurses,

    /// 交互式配置向导 (基于系统 dialog/newt)
    #[cfg(feature = "eui-tui-dialog")]
    TuiDialog,

    /// 现代硬件加速界面 (旗舰级支持)
    #[cfg(feature = "eui-gui-slint")]
    GuiSlint,

    /// 工业级标准桌面界面 (支持 v2/v3)
    #[cfg(feature = "eui-gui-gtk")]
    GuiGtk,

    /// 跨平台高性能界面 (支持 v4/v5)
    #[cfg(feature = "eui-gui-qt")]
    GuiQt,

    /// 数据驱动的 Rust 原生界面
    #[cfg(feature = "eui-gui-druid")]
    GuiDruid,

    /// 极小化静态链接界面
    #[cfg(feature = "eui-gui-fltk")]
    GuiFltk,

    /// 系统原生外观界面 (Win32/Cocoa/GTK)
    #[cfg(feature = "eui-gui-wx")]
    GuiWx,

    /// 终极兼容性回退界面 (基于 Tcl/Tk)
    #[cfg(feature = "eui-gui-tk")]
    GuiTk,

    /// 混合 Web 桥接器 (针对 Tauri / Electron)
    #[cfg(any(feature = "eui-gui-tauri", feature = "eui-gui-electron"))]
    WebBridge,
}

// ============================================================================
//  2. 终极 UI 指令集 (EuiCommand Expanded)
// ============================================================================

/// UI 反向控制指令：从任何 UI 后端发射至内核的操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EuiCommand {
    // --- [核心管理] ---
    /// 强制断开指定对等点 (SocketAddr String)
    DisconnectPeer(String),
    /// 强制重新协商对称密钥
    TriggerRekey(String),
    /// 触发节点优雅停机
    ShutdownNode,
    /// 切换系统安全配置档案 (Turbo / Balanced / Paranoid)
    SwitchSecurityProfile(String),

    // --- [动态防御 (手段 18, 19)] ---
    /// 开关掩护流量 (Cover Traffic)
    ToggleCoverTraffic(bool),
    /// 调整传输层随机抖动范围 (min_ms, max_ms)
    SetTrafficJitter(u64, u64),
    /// 修改 ZKP 频率种子 (动态改变逻辑波段)
    MutateLogicSeed(String),

    // --- [业务渗透：DarkNews & Usenet] ---
    /// 将本地匿名文章渗透到公网 Usenet
    DarkNewsPermeate {
        uuid: u128,
        host: String,
        port: u16,
        group: String,
        /// 用于在导出前解密 body 的策略密钥
        decryption_key: Vec<u8>,
    },

    // --- [逻辑演进：SMC & TC-15 (手段 22)] ---
    /// 远程注入逻辑补丁 (针对 VirtualDslProvider)
    ApplySmcPatch {
        dsl_id: String,
        offset: u16,
        data: Vec<u8>,
    },
    /// 原子置换逻辑提供者 (编译并热替换)
    SwapLogicProvider {
        dsl_id: String,
        c_source: String,
    },

    // --- [情报聚合：RSS / RSSHub] ---
    /// 添加新的 RSS 订阅源 (Label, URL)
    AddRssSource { label: String, url: String },
    /// 移除指定 URL 的订阅
    RemoveRssSource(String),
    /// 标记单条新闻已读
    MarkRssRead(String),
    /// 强制触发全球情报即时刷新
    RefreshAllRss,

    // --- [环境与系统] ---
    /// 更新 Web 访问授权令牌
    UpdateWebToken(String),
    /// 设置全局日志过滤等级 (Trace, Debug, Info, Warn, Error)
    SetLogLevel(String),
    /// 切换 UI 语言 (zh-CN, en-US, ja-JP)
    SetI18nLanguage(String),
}

// ============================================================================
//  3. 异常处理定义
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum EuiError {
    #[error("UI Backend '{0}' is not enabled in compilation features")]
    BackendNotCompiled(String),
    
    #[error("Graphical context initialization failed: {0}")]
    GraphicsInitError(String),
    
    #[error("Bridge communication failure: {0}")]
    BridgeError(String),
    
    #[error("Input validation failed for command: {0}")]
    InvalidCommandParam(String),

    #[error("Platform does not support the selected UI backend")]
    UnsupportedPlatform,
}

// ============================================================================
//  4. 模块初始化宏与版本锚定
// ============================================================================

/// 编译期版本锚定，用于 UI 界面显示
pub const EUI_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const EUI_BUILD_DATE: &str = env!("BUILD_DATE"); // 假设 build.rs 生成此变量

/// [手段 18] ZKP 协商 ID
pub const CAP_ID_EUI: &str = "etp.sys.eui.v2";

impl crate::plugin::CapabilityProvider for EuiManager {
    fn capability_id(&self) -> String { CAP_ID_EUI.into() }
}
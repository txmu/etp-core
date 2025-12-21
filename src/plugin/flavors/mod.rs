// etp-core/src/plugin/flavors/mod.rs

pub mod vpn;
pub mod router;
pub mod composite;
pub mod control;
pub mod fileshare;
pub mod bt_bridge;
pub mod ipfs_fusion;
pub mod mailbox;

// --- 存储强依赖模块 ---
#[cfg(feature = "persistence")]
pub mod tns;
#[cfg(feature = "persistence")]
pub mod chat;
#[cfg(feature = "persistence")]
pub mod forum;
#[cfg(feature = "persistence")]
pub mod universal;

// --- 虚拟机与动态演进模块 (更新点) ---

// 1. 导出 DSL 执行器 (基因运输通道)
#[cfg(feature = "dsl-runtime")]
pub mod dsl_executor;

// 2. 导出进化枢纽 (商业级控制台)
// 仅当开启了便捷界面特性和虚拟机支持时才导出
#[cfg(all(feature = "tc15-tcc", feature = "evolve-ui"))]
pub mod evolution_nexus;

// --- 其它扩展 ---
#[cfg(feature = "extensions")]
pub mod signal_drop;

/// [特性控制]：多网融合枢纽
#[cfg(feature = "fusion-nexus")]
pub mod fusion_nexus;

#[cfg(feature = "dark-news")]
pub mod dark_news;

#[cfg(feature = "dark-news")]
pub mod dark_news_reverse;

// ============================================================================
//  统一重新导出关键结构 (方便外部使用)
// ============================================================================

#[cfg(all(feature = "tc15-tcc", feature = "evolve-ui"))]
pub use evolution_nexus::EvolutionNexus;

#[cfg(feature = "dsl-runtime")]
pub use dsl_executor::DslExecutorFlavor;

#[cfg(feature = "persistence")]
pub use tns::TnsFlavor;

#[cfg(feature = "fusion-nexus")]
pub use fusion_nexus::{FusionNexusFlavor, NexusControlCmd};

#[cfg(feature = "dark-news")]
pub use dark_news::DarkNewsFlavor;

#[cfg(feature = "dark-news")]
pub use dark_news_reverse::{DarkNewsReverseGatewayFlavor, UsenetUpstreamConfig, ClearwebExportPolicy};
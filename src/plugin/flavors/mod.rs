// src/plugin/flavors/mod.rs

pub mod vpn; // 内部已做降级保护，不启用相关特性也不影响编译
pub mod router;
pub mod composite;
pub mod control;

// 不依赖 Sled 的 Flavor
pub mod fileshare;

pub mod bt_bridge;
pub mod ipfs_fusion; 

pub mod mailbox;

// 依赖sled的Flavors：

// 1. Chat Flavor (依赖 Sled)
#[cfg(feature = "sled")]
pub mod chat;

// 2. Forum Flavor (依赖 Sled)
#[cfg(feature = "sled")]
pub mod forum;

// 3. TNS Flavor (依赖 Sled)
#[cfg(feature = "sled")]
pub mod tns;

// 4. HTTP Gateway (依赖 TNS Flavor，间接依赖 Sled)
// 由于它内部引用了 TnsFlavor，如果 tns 模块被 cfg 禁用，这里也会报错。
// 所以必须一同加上保护，或者重构 Gateway 代码。
#[cfg(feature = "sled")]
pub mod http_gateway;

#[cfg(feature = "extensions")]
pub mod signal_drop;

// [新增] 通用信使 Flavor (依赖 Sled)
#[cfg(feature = "sled")]
pub mod universal;

// 新增的 DSL 执行器 Flavor
// 注意：它依赖 dsl-runtime 和 bincode (etp core default)
#[cfg(feature = "dsl-runtime")]
pub mod dsl_executor;

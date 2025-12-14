// etp-core/src/extensions/mod.rs

pub mod adapter;
pub mod bus;
pub mod state;
pub mod config;
pub mod ens;

// 统一导出
pub use adapter::{StreamAdapter, ProtocolStream};
pub use bus::{EventBus, Subscription};
pub use state::{SharedState, StateTransaction};
pub use config::{ConfigWatcher, DynamicConfig};
pub use ens::gateway::{EnsGatewayConfig, run_server as run_ens_gateway};
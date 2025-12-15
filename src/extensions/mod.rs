// etp-core/src/extensions/mod.rs

// 1. 基础扩展模块
pub mod adapter;
pub mod bus;
pub mod state;
pub mod config;

// 2. 条件编译模块 (ENS 网关)
#[cfg(feature = "ens-gateway")]
pub mod ens;

// 3. 核心身份与命名系统
pub mod identity;
pub mod kns;

// 4. 传输层构建套件
pub mod transport_kit;

// ============================================================================
//  统一导出 (Re-exports)
// ============================================================================

// --- Adapter (流适配器) ---
pub use adapter::{StreamAdapter, ProtocolStream};

// --- Bus (事件总线) ---
pub use bus::{EventBus, SystemEvent};

// --- State (共享状态) ---
pub use state::{SharedState, StateTransaction};

// --- Config (动态配置) ---
pub use config::{ConfigManager, DynamicConfig, ConfigWatcher};

// --- ENS (以太坊域名服务网关) ---
#[cfg(feature = "ens-gateway")]
pub use ens::gateway::{EnsGatewayConfig, run_server as run_ens_gateway};

// --- Identity (多态身份系统) ---
pub use identity::{
    // 核心接口与枚举
    IdentityManager,
    IdentityType,
    EtpIdentity,
    AnonymityLevel,
    
    // 十种具体身份实现
    AnchorIdentity,     // 基石
    AvatarIdentity,     // 化身
    GhostIdentity,      // 幽灵 (一次性)
    HiveIdentity,       // 蜂群 (多签/MPC)
    CitizenIdentity,    // 公民 (PoW)
    TokenIdentity,      // 盲视 (Blind Token)
    ProxyIdentity,      // 代理 (Delegated)
    ChameleonIdentity,  // 拟态 (隐写)
    WhisperIdentity,    // 否认 (HMAC)
    FortressIdentity,   // 堡垒 (Post-Quantum)
};

// --- KNS (内核命名系统) ---
pub use kns::{
    // 核心组件
    KnsKernel,
    KnsPath,
    KnsRecord,
    
    // 域与权限
    SecurityDomain,
    AccessControl,
    
    // 类型与接口
    RecordKind,
    ResolutionPriority,
    ExternalResolver,
};

// --- Transport Kit (自定义传输层构建器) ---
pub use transport_kit::{
    // 核心构建器
    TransportKit,
    TransportKitBuild
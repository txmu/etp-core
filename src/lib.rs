// etp-core/src/lib.rs

pub mod common;
pub mod wire;
pub mod crypto;
pub mod transport;
pub mod network;
pub mod plugin;
pub mod platform; // 新增

// 类型别名
pub type NodeID = [u8; 32];
pub type SessionID = u32;
pub type PacketNumber = u64;
pub type Signature = [u8; 64];

// 只有开启了 "ffi" 特性才编译此模块
#[cfg(feature = "ffi")]
pub mod ffi;
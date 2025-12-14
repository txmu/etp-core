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

// 只有开启了相应特性才编译的模块。警告：除了FFI，其它两个模块都只是初步完成。

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "extensions")]
pub mod extensions;

#[cfg(feature = "countermeasures")]
pub mod countermeasures;
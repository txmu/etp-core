// etp-core/src/lib.rs

pub mod common;
pub mod wire;
pub mod crypto;
pub mod transport; 
pub mod network;

// 类型别名保持不变
pub type NodeID = [u8; 32];
pub type SessionID = u32;
pub type PacketNumber = u64;
pub type Signature = [u8; 64];
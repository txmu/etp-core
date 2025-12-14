use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::NodeID;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeInfo {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub latency_ms: u16,
    // 信誉分不传输，仅本地存储，所以这里不包含 NRS
}

impl NodeInfo {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            latency_ms: 0,
        }
    }
}
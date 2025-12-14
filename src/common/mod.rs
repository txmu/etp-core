use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::NodeID;

/// 节点基本信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeInfo {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub latency_ms: u16,
    // 信誉分不传输，仅本地存储，所以这里不含NRS
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

/// DHT 离线存储请求 (通用结构体)
/// 用于 Flavor 通知 Engine 将数据推送到 DHT
#[derive(Debug, Clone)]
pub struct DhtStoreRequest {
    pub key: NodeID,
    pub value: Vec<u8>,
    pub ttl_seconds: u32,
}
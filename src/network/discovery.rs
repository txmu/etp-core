// etp-core/src/network/discovery.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use crate::NodeID;
use crate::common::NodeInfo;
use rand::seq::SliceRandom;

/// 路由表：存储已知节点
#[derive(Debug, Clone)]
pub struct RoutingTable {
    // NodeID -> NodeInfo
    peers: Arc<RwLock<HashMap<NodeID, NodeInfo>>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 添加或更新节点
    pub fn add_node(&self, info: NodeInfo) {
        let mut table = self.peers.write().unwrap();
        // 实际逻辑中可能需要检查是否更新 (比如 latency 更低)
        table.insert(info.id, info);
    }

    /// 查找节点地址 (Session 6 新增)
    pub fn lookup(&self, id: &NodeID) -> Option<SocketAddr> {
        let table = self.peers.read().unwrap();
        table.get(id).map(|info| info.addr)
    }

    /// 随机获取 N 个节点（用于 Gossip 分享）
    pub fn get_random_peers(&self, n: usize) -> Vec<NodeInfo> {
        let table = self.peers.read().unwrap();
        let mut nodes: Vec<NodeInfo> = table.values().cloned().collect();
        let mut rng = rand::thread_rng();
        nodes.shuffle(&mut rng);
        nodes.into_iter().take(n).collect()
    }
    
    /// 获取所有已知节点的地址
    pub fn get_all_addresses(&self) -> Vec<SocketAddr> {
        self.peers.read().unwrap().values().map(|n| n.addr).collect()
    }
}
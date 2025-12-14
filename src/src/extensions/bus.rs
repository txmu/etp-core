// etp-core/src/extensions/bus.rs

use std::sync::Arc;
use std::any::Any;
use tokio::sync::broadcast;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

/// 系统内部事件
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SystemEvent {
    ConsensusReached { height: u64, hash: String },
    NetworkPartitionDetected,
    PeerReputationUpdated { peer_id: [u8; 32], score: i32 },
    Custom(String, Vec<u8>),
}

/// 高性能事件总线
pub struct EventBus {
    channels: DashMap<String, broadcast::Sender<SystemEvent>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            channels: DashMap::new(),
        }
    }

    /// 订阅特定主题
    pub fn subscribe(&self, topic: &str) -> broadcast::Receiver<SystemEvent> {
        let tx = self.channels.entry(topic.to_string())
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(1024);
                tx
            })
            .value()
            .clone();
        tx.subscribe()
    }

    /// 发布事件
    pub fn publish(&self, topic: &str, event: SystemEvent) -> usize {
        if let Some(tx) = self.channels.get(topic) {
            // 忽略错误（如果没有订阅者）
            tx.send(event).unwrap_or(0)
        } else {
            0
        }
    }
}

// 全局单例模式可以通过 Arc 传递给所有 Flavor
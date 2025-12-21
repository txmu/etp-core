// etp-core/src/common/mod.rs

use serde::{Serialize, Deserialize};
use std::net::{SocketAddr, Ipv4Addr};
use crate::NodeID;

/// 全局统一节点信息模型
/// 
/// 该结构体在设计上分为两个部分：
/// 1. 传输字段：随网络包同步 (如 id, addr, virtual_ip, features)
/// 2. 本地字段：仅存在于节点内存/数据库中 (如 reputation, last_seen)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeInfo {
    // --- 传输面 (Transmitted) ---
    pub id: NodeID,
    pub addr: SocketAddr,
    
    /// 网络延迟 (RTT)
    pub latency_ms: u16,
    
    /// 虚拟 IP (240.x.x.x)，用于 Overlay 路由逻辑
    pub virtual_ip: Option<Ipv4Addr>,

    /// 客户端版本字符串 (用于版本兼容性协商)
    pub client_version: String,

    /// 能力位掩码 (用于发现服务类型，如是否支持 XDP, 是否是中继等)
    pub features: u32,

    // --- 本地状态面 (Local Only - 不参与网络序列化) ---
    
    /// 节点信誉分：基于本地交互结果动态增减
    #[serde(skip)]
    pub reputation: i32,

    /// 最后活跃时间 (Unix Timestamp)
    #[serde(skip)]
    pub last_seen: u64,
    
    /// 首次发现时间
    #[serde(skip)]
    pub first_seen: u64,
}

impl NodeInfo {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            id,
            addr,
            latency_ms: 0,
            virtual_ip: None,
            client_version: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            features: 0,
            
            // 本地初始化
            reputation: 100, // 初始分
            last_seen: now,
            first_seen: now,
        }
    }

    /// 更新本地活跃状态
    pub fn touch(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// 增减信誉分
    pub fn adjust_reputation(&mut self, delta: i32) {
        // 限制在有效范围内，防止溢出攻击
        self.reputation = self.reputation.saturating_add(delta).clamp(-1000, 1000);
    }
}

/// DHT 离线存储请求 (保持不变)
#[derive(Debug, Clone)]
pub struct DhtStoreRequest {
    pub key: NodeID,
    pub value: Vec<u8>,
    pub ttl_seconds: u32,
}
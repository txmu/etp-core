use serde::{Serialize, Deserialize};
use crate::{NodeID, Signature};
use crate::common::NodeInfo;

/// ETP 协议内部的功能帧
/// 使用 enum 包含不同类型，便于扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    /// 填充帧 (0x00)
    /// 用于对齐 MTU 或混淆流量特征，接收端应直接忽略
    Padding(Vec<u8>),

    /// 数据流帧 (0x01)
    /// 承载应用层数据，支持多路复用
    Stream {
        stream_id: u32,
        offset: u64,
        fin: bool, // 流结束标志
        data: Vec<u8>,
    },

    /// 确认帧 (0x02)
    /// 类似于 QUIC 的 ACK，携带 SACK ranges
    Ack {
        largest_acknowledged: u64,
        delay_time_micros: u64,
        // (Gap, AckRangeLength)
        // 用于高效表示非连续的确认块
        ranges: Vec<(u64, u64)>, 
    },

    /// 关闭连接 (0x03)
    Close {
        error_code: u16,
        reason: String,
    },

    /// 八卦/发现帧 (0x04)
    /// 交换已知节点信息，实现去中心化发现
    Gossip {
        nodes: Vec<NodeInfo>,
    },

    /// 介入/注入帧 (0x07)
    /// 允许第三方（或中继）在经过授权的情况下插入控制指令
    /// 必须携带签名以验证身份
    Injection {
        target_session: u32,  // 目标会话ID，防止重放给错误连接
        injector_id: NodeID,  // 插入者身份
        command: InjectionCommand,
        signature: Signature, // 对 (target_session + command + payload) 的签名
    },
    
    // 可以在此继续扩展 FEC 帧、Relay 帧等...
}

/// 注入指令类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionCommand {
    /// 路由建议：告诉发送方“我有更好的路径去往某地”
    RouteHint { 
        target_node: NodeID, 
        suggested_next_hop: NodeInfo 
    },
    /// 流量控制：强制要求发送方降低速率 (Paranoid 模式审计失败时触发)
    Throttle { 
        limit_kbps: u32, 
        duration_sec: u32 
    },
    /// 服务广播：在流中插入广告
    ServiceAdvertisement {
        service_hash: [u8; 32],
        metadata: Vec<u8>,
    }
}

// 简单的辅助函数，用于快速创建 Padding
impl Frame {
    pub fn new_padding(size: usize) -> Self {
        // 在实际生产中，这里应该填充随机数据，而不是0
        // 但为了调试方便，MVP先填0，序列化前再随机化也可以
        Frame::Padding(vec![0u8; size])
    }
}
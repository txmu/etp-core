// etp-core/src/wire/frame.rs

use serde::{Serialize, Deserialize};
use crate::{NodeID, Signature};
use crate::common::NodeInfo;
use std::net::SocketAddr;

/// 单个 Frame 的最大允许大小 (防炸弹)
const MAX_FRAME_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Frame {
    /// 填充帧 (0x00)
    Padding(Vec<u8>),

    /// 主数据流 (0x01)
    Stream {
        stream_id: u32,
        offset: u64,
        fin: bool,
        data: Vec<u8>,
    },

    /// 确认帧 (0x02)
    Ack {
        largest_acknowledged: u64,
        delay_time_micros: u64,
        ranges: Vec<(u64, u64)>, 
    },

    /// 关闭连接 (0x03)
    Close {
        error_code: u16,
        reason: String,
    },

    /// 路由发现 (0x04)
    Gossip {
        nodes: Vec<NodeInfo>,
    },

    /// 中继指令 (0x05)
    Relay {
        next_hop: NodeID,
        payload: Vec<u8>, // 内层加密包
    },

    /// 纠错码 (0x06) - 预留
    Fec {
        group_id: u64,
        index: u8,
        data: Vec<u8>,
    },

    /// 控制注入 (0x07)
    Injection {
        target_session: u32,
        injector_id: NodeID,
        command: InjectionCommand,
        signature: Signature,
    },

    // --- 新增帧类型 (Step 1) ---

    /// 侧信道数据 (0x08)
    /// 侧信道拥有独立的逻辑流，不阻塞主 Stream，适用于信令控制或低优传输
    SideChannel {
        channel_id: u32,
        data: Vec<u8>,
    },

    /// NAT 穿透信令 (0x09)
    /// 用于交换 ICE 候选地址或 STUN 探测
    NatSignal {
        signal_type: NatSignalType,
        payload: Vec<u8>, // 候选者列表序列化数据
    },

    /// 安全协商 (0x0A)
    /// 包含 ZKP 证明或加密的能力位图
    Negotiate {
        protocol_version: u16,
        zkp_proof: Vec<u8>, // 零知识证明数据
        flavor_bitmap: Vec<u8>, // 加密后的支持列表
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionCommand {
    RouteHint { 
        target_node: NodeID, 
        suggested_next_hop: NodeInfo 
    },
    Throttle { 
        limit_kbps: u32, 
        duration_sec: u32 
    },
    ServiceAdvertisement {
        service_hash: [u8; 32],
        metadata: Vec<u8>,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NatSignalType {
    CandidateOffer, // 我发现了我的公网地址
    Ping,           // 打洞探测
    Pong,           // 打洞响应
}

impl Frame {
    pub fn new_padding(size: usize) -> Self {
        // 限制最大 Padding 防止滥用
        let safe_size = size.min(1400); 
        Frame::Padding(vec![0u8; safe_size])
    }

    /// 验证 Frame 大小是否合法 (Anti-Spam / Anti-DoS)
    pub fn validate_size(&self) -> bool {
        match self {
            Frame::Stream { data, .. } => data.len() <= MAX_FRAME_SIZE,
            Frame::Padding(data) => data.len() <= 1400, // Padding 不应过大
            Frame::Relay { payload, .. } => payload.len() <= MAX_FRAME_SIZE,
            Frame::SideChannel { data, .. } => data.len() <= MAX_FRAME_SIZE,
            Frame::NatSignal { payload, .. } => payload.len() <= 1024, // 信令通常很小
            Frame::Negotiate { zkp_proof, .. } => zkp_proof.len() <= 4096,
            Frame::Injection { command, .. } => {
                match command {
                    InjectionCommand::ServiceAdvertisement { metadata, .. } => metadata.len() <= 2048,
                    _ => true,
                }
            },
            _ => true,
        }
    }
}
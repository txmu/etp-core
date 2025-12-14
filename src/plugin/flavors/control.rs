// etp-core/src/plugin/flavors/control.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use log::{debug, warn, error, info};
use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::transport::side_channel::{SideChannelPolicy, ChannelMode};

// ============================================================================
//  1. 协议常量定义
// ============================================================================

/// 虚拟控制流 ID
/// 这是一个约定的特殊 Stream ID。底层 SideChannel 收到的数据，
/// 会被 Engine 伪装成属于这个 Stream 的数据包投递给 Flavor。
pub const VIRTUAL_STREAM_SIDE_CHANNEL: u32 = 0;

/// 预定义信道 ID
pub const CHANNEL_CRITICAL: u32 = 1;  // 红色通道：关键指令
pub const CHANNEL_HEARTBEAT: u32 = 2; // 蓝色通道：心跳/定位
pub const CHANNEL_METADATA: u32 = 3;  // 绿色通道：元数据同步

// ============================================================================
//  2. 控制指令分类与策略
// ============================================================================

/// 控制指令分类
/// 用于在发送端快速选择正确的 QoS 策略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCategory {
    /// 关键指令 (Critical)
    /// 用于：紧急刹车、密钥轮换、权限变更
    /// 特性：最高优先级、必须送达 (Reliable)、较长超时
    Critical,

    /// 心跳/遥测 (Heartbeat)
    /// 用于：GPS定位、存活检测、RTT 测量
    /// 特性：高优先级、允许丢包 (Datagram)、短超时
    Heartbeat,

    /// 元数据 (Metadata)
    /// 用于：DHT 索引同步、路由表交换
    /// 特性：中低优先级、必须送达 (Reliable)、长超时
    Metadata,
    
    /// 自定义扩展 (Custom)
    /// 允许用户定义特定的 Channel ID
    Custom(u32),
}

impl ControlCategory {
    /// 获取对应的信道 ID
    pub fn id(&self) -> u32 {
        match self {
            Self::Critical => CHANNEL_CRITICAL,
            Self::Heartbeat => CHANNEL_HEARTBEAT,
            Self::Metadata => CHANNEL_METADATA,
            Self::Custom(id) => *id,
        }
    }

    /// 获取对应的传输策略 (QoS Policy)
    pub fn policy(&self) -> SideChannelPolicy {
        match self {
            Self::Critical => SideChannelPolicy {
                mode: ChannelMode::ReliableMessage, 
                priority: 255, // 顶格优先级，抢占所有带宽
                timeout: Duration::from_secs(10),
            },
            Self::Heartbeat => SideChannelPolicy {
                mode: ChannelMode::Datagram,        
                priority: 200, // 高于普通视频流
                timeout: Duration::from_secs(5),
            },
            Self::Metadata => SideChannelPolicy {
                mode: ChannelMode::ReliableMessage,
                priority: 50,  // 低于普通交互流，作为背景传输
                timeout: Duration::from_secs(60),
            },
            Self::Custom(_) => SideChannelPolicy::default(), // 默认策略
        }
    }
}

// ============================================================================
//  3. Flavor 实现
// ============================================================================

/// 控制枢纽 Flavor (Control Nexus)
/// 它是 ETP 节点的“神经中枢”，负责处理通过 SideChannel 传入的高优先级指令。
pub struct ControlNexusFlavor {
    // 将接收到的指令通过 Channel 上报给业务层主循环
    // 格式: (Source, Category, Payload)
    cmd_tx: mpsc::Sender<(SocketAddr, ControlCategory, Vec<u8>)>,
}

impl ControlNexusFlavor {
    /// 创建新的控制枢纽
    pub fn new(cmd_tx: mpsc::Sender<(SocketAddr, ControlCategory, Vec<u8>)>) -> Arc<Self> {
        Arc::new(Self { cmd_tx })
    }
    
    /// 内部辅助：根据 ID 反推分类
    fn map_id_to_category(id: u32) -> ControlCategory {
        match id {
            CHANNEL_CRITICAL => ControlCategory::Critical,
            CHANNEL_HEARTBEAT => ControlCategory::Heartbeat,
            CHANNEL_METADATA => ControlCategory::Metadata,
            _ => ControlCategory::Custom(id),
        }
    }
}

impl CapabilityProvider for ControlNexusFlavor {
    fn capability_id(&self) -> String { 
        "etp.flavor.control.v1".into() 
    }
}

impl Flavor for ControlNexusFlavor {
    fn priority(&self) -> u8 {
        254 // 仅次于 Router/Composite，确保它是第一个处理具体业务的 Flavor
    }

    /// 处理逻辑：
    /// 1. 拦截 Stream 0 (虚拟控制流)。
    /// 2. 解析 [ChannelID (4B)] [Payload...]。
    /// 3. 分类并上报。
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 1. 严格过滤：非控制流直接放行 (返回 false)
        // 这保证了 ControlNexus 可以被安全地放在 Composite 的任何位置，或者作为 Default Flavor
        if ctx.stream_id != VIRTUAL_STREAM_SIDE_CHANNEL {
            return false;
        }

        // 2. 格式校验：至少包含 ChannelID (4字节)
        if data.len() < 4 {
            warn!("ControlNexus: Malformed packet on virtual stream (len < 4) from {}", ctx.src_addr);
            return true; // 格式错误，吞掉，防止未定义的行为传递给后续 Flavor
        }

        // 3. 解析 Channel ID (Big Endian)
        let channel_id_bytes: [u8; 4] = data[0..4].try_into().unwrap();
        let channel_id = u32::from_be_bytes(channel_id_bytes);
        let payload = &data[4..];

        // 4. 分类映射
        let category = Self::map_id_to_category(channel_id);

        // 5. 日志记录 (仅 Debug 模式，避免泄露敏感指令)
        debug!("ControlNexus: Handling {:?} cmd from {} ({} bytes)", category, ctx.src_addr, payload.len());

        // 6. 异步分发 (避免阻塞 Flavor 处理链)
        // 这里的 channel 容量有限，如果满了说明上层处理不过来，我们选择丢弃并报警
        // 对于 Critical 指令，这可能需要更强的保障机制，但那是业务层的事了
        let tx = self.cmd_tx.clone();
        let src = ctx.src_addr;
        let payload_vec = payload.to_vec();

        tokio::spawn(async move {
            match tx.send((src, category, payload_vec)).await {
                Ok(_) => {},
                Err(e) => {
                    // 这通常意味着接收端已经关闭 (Node Shutdown)
                    error!("ControlNexus: Failed to dispatch command: {}", e);
                }
            }
        });

        // 返回 true，表示 Stream 0 的数据已被完全消费，不再传递给其他 Flavor
        true
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 可以在此初始化默认的心跳侧信道，或者记录连接状态
        debug!("ControlNexus: Control link ready for {}", peer);
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        // 连接断开时，不需要特殊清理，因为 SideChannelManager 会负责清理底层信道
        debug!("ControlNexus: Control link severed for {}", peer);
    }
}
// etp-core/src/transport/side_channel.rs

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use log::{debug, warn, trace};
use crate::wire::frame::Frame;

// --- 配置常量 ---
const MAX_SIDE_CHANNELS: usize = 64; // 单个连接允许的最大并发侧信道数
const DEFAULT_CHANNEL_TIMEOUT: Duration = Duration::from_secs(30); // 信道空闲超时
const MAX_BUFFER_PER_CHANNEL: usize = 1024 * 1024; // 1MB 缓冲区限制

/// 侧信道传输模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
    /// 数据报模式：发后即忘，允许丢包，不保序。
    /// 适用：NAT 打洞、心跳、实时语音。
    Datagram,
    /// 消息模式：简单的可靠传输（停等协议或分片重组），保序。
    /// 适用：DHT 查询、ZKP 协商、控制指令。
    ReliableMessage,
}

/// 侧信道策略配置
#[derive(Debug, Clone)]
pub struct SideChannelPolicy {
    pub mode: ChannelMode,
    pub priority: u8, // 0-255, 越高越优先
    pub timeout: Duration,
}

impl Default for SideChannelPolicy {
    fn default() -> Self {
        Self {
            mode: ChannelMode::Datagram,
            priority: 100,
            timeout: DEFAULT_CHANNEL_TIMEOUT,
        }
    }
}

/// 单个侧信道状态
struct SideChannel {
    id: u32,
    policy: SideChannelPolicy,
    created_at: Instant,
    last_active: Instant,
    
    /// 待发送队列 (Frames ready to go)
    tx_queue: VecDeque<Vec<u8>>,
    /// 接收缓冲区 (已收到的 Payload)
    rx_buffer: VecDeque<Vec<u8>>,
    
    // 统计信息
    bytes_sent: usize,
    bytes_received: usize,
}

impl SideChannel {
    fn new(id: u32, policy: SideChannelPolicy) -> Self {
        Self {
            id,
            policy,
            created_at: Instant::now(),
            last_active: Instant::now(),
            tx_queue: VecDeque::new(),
            rx_buffer: VecDeque::new(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn push_send(&mut self, data: Vec<u8>) -> bool {
        // 检查缓冲区配额
        let current_size: usize = self.tx_queue.iter().map(|v| v.len()).sum();
        if current_size + data.len() > MAX_BUFFER_PER_CHANNEL {
            return false;
        }
        self.tx_queue.push_back(data);
        self.last_active = Instant::now();
        true
    }

    fn push_recv(&mut self, data: Vec<u8>) {
        // 接收端也需要配额检查，防止内存攻击
        let current_size: usize = self.rx_buffer.iter().map(|v| v.len()).sum();
        if current_size + data.len() > MAX_BUFFER_PER_CHANNEL {
            warn!("SideChannel {}: RX buffer overflow, dropping packet", self.id);
            return;
        }
        self.bytes_received += data.len();
        self.rx_buffer.push_back(data);
        self.last_active = Instant::now();
    }

    fn pop_recv(&mut self) -> Option<Vec<u8>> {
        self.rx_buffer.pop_front()
    }

    fn is_expired(&self) -> bool {
        self.last_active.elapsed() > self.policy.timeout
    }
}

/// 侧信道管理器
/// 集成在 SessionContext 中
pub struct SideChannelManager {
    channels: HashMap<u32, SideChannel>,
    /// 下一个可用的本地信道 ID (从 1 开始，偶数/奇数策略可用于避免冲突，此处简化递增)
    next_local_id: u32,
}

impl SideChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            next_local_id: 1, // 0 保留给特殊用途
        }
    }

    /// 创建一个新的侧信道 (Outbound)
    /// 返回 ChannelID
    pub fn create_channel(&mut self, policy: SideChannelPolicy) -> Option<u32> {
        if self.channels.len() >= MAX_SIDE_CHANNELS {
            warn!("Max side channels reached");
            return None;
        }

        let id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(1);
        if self.next_local_id == 0 { self.next_local_id = 1; }

        let channel = SideChannel::new(id, policy);
        self.channels.insert(id, channel);
        debug!("Created outbound side channel {}", id);
        Some(id)
    }

    /// 注册一个远端发起的侧信道 (Inbound)
    /// 当收到未知的 ChannelID 数据包时调用
    pub fn register_remote_channel(&mut self, id: u32, policy: SideChannelPolicy) -> bool {
        if self.channels.contains_key(&id) {
            return true; // 已存在
        }
        if self.channels.len() >= MAX_SIDE_CHANNELS {
            warn!("Max side channels reached, rejecting inbound channel {}", id);
            return false;
        }
        let channel = SideChannel::new(id, policy);
        self.channels.insert(id, channel);
        debug!("Registered inbound side channel {}", id);
        true
    }

    /// 向指定信道写入数据 (发送)
    pub fn send_message(&mut self, id: u32, data: Vec<u8>) -> bool {
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.push_send(data)
        } else {
            false
        }
    }

    /// 处理接收到的侧信道帧
    /// 返回: true 如果处理成功, false 如果信道不存在或被拒绝
    pub fn on_frame_received(&mut self, id: u32, data: Vec<u8>) -> bool {
        // 如果信道不存在，是否自动创建？
        // 策略：对于 Datagram 模式，自动创建默认策略的信道。
        // 对于 Reliable 模式，通常需要显式 Open 指令 (但在 Frame::SideChannel 定义中我们简化了)。
        // 生产级：采用 Lazy Creation，假设对端发来就是合法的。
        
        if !self.channels.contains_key(&id) {
            // 自动注册一个默认策略的入站信道
            // 这里的策略应该尽可能保守 (Datagram, Low Priority)
            let policy = SideChannelPolicy {
                mode: ChannelMode::Datagram,
                priority: 50,
                timeout: Duration::from_secs(10), // 短超时
            };
            if !self.register_remote_channel(id, policy) {
                return false;
            }
        }

        if let Some(ch) = self.channels.get_mut(&id) {
            ch.push_recv(data);
            return true;
        }
        false
    }

    /// 从指定信道读取数据 (接收)
    pub fn recv_message(&mut self, id: u32) -> Option<Vec<u8>> {
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.pop_recv()
        } else {
            None
        }
    }

    /// 轮询待发送的数据帧
    /// 实现了加权公平调度 (Weighted Fair Queuing)
    /// limit: 建议的最大字节数 (MTU or Congestion window)
    /// 返回: Vec<Frame>
    pub fn pop_outgoing_frames(&mut self, limit_bytes: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut total_bytes = 0;

        // 获取所有有待发数据的信道 ID
        let active_ids: Vec<u32> = self.channels.iter()
            .filter(|(_, ch)| !ch.tx_queue.is_empty())
            .map(|(id, _)| *id)
            .collect();

        // 简化的调度：按优先级排序
        // 生产级优化：应该使用带状态的 DRR (Deficit Round Robin) 算法
        // 这里使用简单的排序遍历 + 贪婪提取
        let mut sorted_channels: Vec<_> = active_ids.iter()
            .filter_map(|id| self.channels.get_mut(id))
            .collect();
        
        sorted_channels.sort_by(|a, b| b.policy.priority.cmp(&a.policy.priority));

        for ch in sorted_channels {
            if total_bytes >= limit_bytes {
                break;
            }

            // 每个信道每次轮询最多取 3 个包，防止高优先信道饿死低优先
            // 或者直到填满 limit
            let mut taken = 0;
            while taken < 3 && total_bytes < limit_bytes {
                if let Some(data) = ch.tx_queue.pop_front() {
                    let len = data.len();
                    ch.bytes_sent += len;
                    total_bytes += len;
                    
                    frames.push(Frame::SideChannel {
                        channel_id: ch.id,
                        data,
                    });
                    taken += 1;
                } else {
                    break;
                }
            }
        }

        frames
    }

    /// 清理维护 (Tick)
    /// 移除超时信道
    pub fn maintenance(&mut self) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (id, ch) in self.channels.iter() {
            if ch.is_expired() {
                to_remove.push(*id);
            }
        }

        for id in to_remove {
            debug!("SideChannel {} expired, cleaning up", id);
            self.channels.remove(&id);
        }
    }
    
    /// 获取信道统计
    pub fn stats(&self) -> (usize, usize) {
        (self.channels.len(), 0) // count, reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_side_channel_lifecycle() {
        let mut manager = SideChannelManager::new();
        
        // 1. Create
        let id = manager.create_channel(SideChannelPolicy::default()).unwrap();
        assert!(manager.channels.contains_key(&id));

        // 2. Send (Queueing)
        let data = vec![1, 2, 3, 4];
        manager.send_message(id, data.clone());
        
        // 3. Pop Outgoing
        let frames = manager.pop_outgoing_frames(1024);
        assert_eq!(frames.len(), 1);
        if let Frame::SideChannel { channel_id, data: d } = &frames[0] {
            assert_eq!(*channel_id, id);
            assert_eq!(*d, data);
        } else {
            panic!("Wrong frame type");
        }

        // 4. Recv
        let incoming = vec![5, 6, 7, 8];
        manager.on_frame_received(id, incoming.clone());
        let read_back = manager.recv_message(id).unwrap();
        assert_eq!(read_back, incoming);
    }

    #[test]
    fn test_priority_scheduling() {
        let mut manager = SideChannelManager::new();
        
        // High Priority
        let hi_pol = SideChannelPolicy { priority: 200, ..Default::default() };
        let hi_id = manager.create_channel(hi_pol).unwrap();
        
        // Low Priority
        let lo_pol = SideChannelPolicy { priority: 10, ..Default::default() };
        let lo_id = manager.create_channel(lo_pol).unwrap();

        manager.send_message(lo_id, vec![0xBB]);
        manager.send_message(hi_id, vec![0xAA]);

        // Should pop high priority first
        let frames = manager.pop_outgoing_frames(1024);
        assert_eq!(frames.len(), 2);
        
        if let Frame::SideChannel { channel_id, .. } = &frames[0] {
            assert_eq!(*channel_id, hi_id);
        } else { panic!("First should be high prio"); }
        
        if let Frame::SideChannel { channel_id, .. } = &frames[1] {
            assert_eq!(*channel_id, lo_id);
        } else { panic!("Second should be low prio"); }
    }
    
    #[test]
    fn test_auto_cleanup() {
        let mut manager = SideChannelManager::new();
        let pol = SideChannelPolicy { 
            timeout: Duration::from_millis(1), 
            ..Default::default() 
        };
        let id = manager.create_channel(pol).unwrap();
        
        std::thread::sleep(Duration::from_millis(10));
        manager.maintenance();
        
        assert!(!manager.channels.contains_key(&id));
    }
}
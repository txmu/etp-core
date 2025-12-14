// etp-core/src/transport/side_channel.rs

use std::collections::{HashMap, VecDeque, BTreeMap};
use std::time::{Duration, Instant};
use log::{debug, warn, trace, error};
use crate::wire::frame::Frame;

// --- 配置常量 ---
const MAX_SIDE_CHANNELS: usize = 64; 
const DEFAULT_CHANNEL_TIMEOUT: Duration = Duration::from_secs(60); 
const MAX_BUFFER_PER_CHANNEL: usize = 2 * 1024 * 1024; // 2MB buffer limit
const DEFAULT_BURST_SIZE: usize = 16 * 1024; // 16KB burst allow

/// 侧信道传输模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
    /// 数据报模式：无序、允许丢包、低延迟 (e.g. Heartbeat, Real-time Voice)
    Datagram,
    /// 可靠消息模式：严格保序、逻辑层去重 (e.g. Control Commands, Key Exchange)
    ReliableMessage,
}

/// 隐私填充模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingMode {
    /// 不填充 (即时性最高)
    None,
    /// 填充至固定大小 (例如 256 字节，隐藏指令长度特征)
    Fixed(usize),
    /// 填充至块对齐 (例如 16 字节倍数)
    BlockAligned(usize),
}

/// 侧信道策略配置
#[derive(Debug, Clone)]
pub struct SideChannelPolicy {
    pub mode: ChannelMode,
    pub priority: u8, // 0-255, 越高越优先
    pub timeout: Duration,
    
    // --- 新增特性 ---
    /// 速率限制 (字节/秒)，0 表示无限制
    pub rate_limit: usize,
    /// 隐私填充策略
    pub padding: PaddingMode,
}

impl Default for SideChannelPolicy {
    fn default() -> Self {
        Self {
            mode: ChannelMode::Datagram,
            priority: 100,
            timeout: DEFAULT_CHANNEL_TIMEOUT,
            rate_limit: 0,
            padding: PaddingMode::None,
        }
    }
}

/// 令牌桶限流器
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate_per_sec: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate: usize, burst: usize) -> Self {
        Self {
            capacity: burst as f64,
            tokens: burst as f64,
            rate_per_sec: rate as f64,
            last_update: Instant::now(),
        }
    }

    fn consume(&mut self, amount: usize) -> bool {
        if self.rate_per_sec <= 0.0 { return true; } // Unlimited

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        
        // Refill
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last_update = now;

        if self.tokens >= amount as f64 {
            self.tokens -= amount as f64;
            true
        } else {
            false
        }
    }
}

/// 单个侧信道状态
struct SideChannel {
    id: u32,
    policy: SideChannelPolicy,
    created_at: Instant,
    last_active: Instant,
    
    /// 发送队列
    tx_queue: VecDeque<Vec<u8>>,
    /// 接收缓冲区 (用于流控)
    rx_buffer_size: usize,
    
    /// 限流器
    rate_limiter: TokenBucket,

    // --- 保序与去重 (Reliable Mode Only) ---
    /// 发送序列号
    next_tx_seq: u64,
    /// 期望的下一个接收序列号
    next_rx_seq: u64,
    /// 乱序缓存: Seq -> Data
    reorder_buffer: BTreeMap<u64, Vec<u8>>,

    // 统计
    bytes_sent: usize,
    bytes_received: usize,
}

impl SideChannel {
    fn new(id: u32, policy: SideChannelPolicy) -> Self {
        let rate = policy.rate_limit;
        Self {
            id,
            policy,
            created_at: Instant::now(),
            last_active: Instant::now(),
            tx_queue: VecDeque::new(),
            rx_buffer_size: 0,
            rate_limiter: TokenBucket::new(rate, DEFAULT_BURST_SIZE),
            next_tx_seq: 0,
            next_rx_seq: 0,
            reorder_buffer: BTreeMap::new(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn push_send(&mut self, mut data: Vec<u8>) -> bool {
        // 1. 缓冲区检查
        let current_size: usize = self.tx_queue.iter().map(|v| v.len()).sum();
        if current_size + data.len() > MAX_BUFFER_PER_CHANNEL {
            warn!("SideChannel {}: TX buffer overflow", self.id);
            return false;
        }

        // 2. 速率限制检查 (Anti-DoS)
        if !self.rate_limiter.consume(data.len()) {
            warn!("SideChannel {}: Rate limit exceeded, dropping packet", self.id);
            return false;
        }

        // 3. 应用隐私填充 (Padding)
        self.apply_padding(&mut data);

        // 4. 封装序列号 (仅 Reliable 模式需要逻辑上的 seq，物理层可靠性由底层保证)
        // 注意：这里的 Seq 是为了应用层逻辑顺序，Frame::SideChannel 内部不带 seq 字段。
        // 为了实现简单，我们将 seq 编码进 data 头部？
        // *设计决策*：为了保持 Frame 定义的纯洁，我们假定底层 ReliabilityLayer 已经保证了 Frame 的到达。
        // 但如果底层是 Datagram 模式，或者是 ParallelMulti 模式下的不同包，
        // SideChannel 内部实现保序是双重保险。
        // 在此实现中，我们采用：
        // 如果是 ReliableMessage，我们在 data 头部插入 8 字节 Sequence Number。
        
        if self.policy.mode == ChannelMode::ReliableMessage {
            let mut seq_data = Vec::with_capacity(8 + data.len());
            seq_data.extend_from_slice(&self.next_tx_seq.to_be_bytes());
            seq_data.extend(data);
            data = seq_data;
            self.next_tx_seq += 1;
        }

        self.tx_queue.push_back(data);
        self.last_active = Instant::now();
        true
    }

    /// 处理接收数据 (含去重与保序)
    /// 返回：可供上层消费的数据列表 (可能包含之前缓存的乱序包)
    fn process_ingress(&mut self, data: Vec<u8>) -> Vec<Vec<u8>> {
        self.last_active = Instant::now();
        self.bytes_received += data.len();

        if self.policy.mode == ChannelMode::Datagram {
            // 数据报模式：直接交付，不保序
            return vec![data];
        }

        // ReliableMessage 模式：解析 Seq
        if data.len() < 8 {
            warn!("SideChannel {}: Malformed reliable packet (too short)", self.id);
            return vec![];
        }

        let seq_bytes: [u8; 8] = data[0..8].try_into().unwrap();
        let seq = u64::from_be_bytes(seq_bytes);
        let payload = data[8..].to_vec();

        // 去重与乱序处理
        if seq < self.next_rx_seq {
            trace!("SideChannel {}: Duplicate seq {}, ignoring", self.id, seq);
            return vec![];
        }

        if seq == self.next_rx_seq {
            let mut result = vec![payload];
            self.next_rx_seq += 1;

            // 检查缓存中是否有后续包
            while let Some(payload) = self.reorder_buffer.remove(&self.next_rx_seq) {
                result.push(payload);
                self.next_rx_seq += 1;
            }
            return result;
        } else {
            // 乱序到达 (Gap Detected)，缓存之
            // 限制缓存大小防止内存攻击
            if self.reorder_buffer.len() < 100 {
                debug!("SideChannel {}: Gap detected, buffered seq {} (expecting {})", self.id, seq, self.next_rx_seq);
                self.reorder_buffer.insert(seq, payload);
            } else {
                warn!("SideChannel {}: Reorder buffer full, dropping seq {}", self.id, seq);
            }
            return vec![];
        }
    }

    fn apply_padding(&self, data: &mut Vec<u8>) {
        let current_len = data.len();
        match self.policy.padding {
            PaddingMode::None => {},
            PaddingMode::Fixed(size) => {
                if current_len < size {
                    let pad_len = size - current_len;
                    data.resize(size, 0); // 简单填0，加密层会使其随机化
                    // 实际上应该填随机数，但在 RawPacket 层会再次加密，填0也是安全的
                }
            },
            PaddingMode::BlockAligned(block) => {
                if block > 0 {
                    let rem = current_len % block;
                    if rem != 0 {
                        let pad_len = block - rem;
                        data.resize(current_len + pad_len, 0);
                    }
                }
            }
        }
    }

    fn is_expired(&self) -> bool {
        self.last_active.elapsed() > self.policy.timeout
    }
}

/// 侧信道管理器
pub struct SideChannelManager {
    channels: HashMap<u32, SideChannel>,
    /// 接收缓冲区 (ChannelID -> List of Messages)
    /// 存储已完成保序处理、等待 Flavor 取走的数据
    rx_outbox: HashMap<u32, VecDeque<Vec<u8>>>,
    next_local_id: u32,
}

impl SideChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            rx_outbox: HashMap::new(),
            next_local_id: 1000, // 自动生成的 ID 从 1000 开始，保留 0-999 给固定 ID
        }
    }

    /// 注册或更新一个指定 ID 的本地信道 (固定 ID 模式)
    /// 适用于 ControlNexusFlavor 等预定义服务
    pub fn register_or_update_channel(&mut self, id: u32, policy: SideChannelPolicy) -> bool {
        if self.channels.len() >= MAX_SIDE_CHANNELS && !self.channels.contains_key(&id) {
            return false;
        }
        // 如果存在则更新策略，如果不存在则创建
        self.channels.entry(id)
            .and_modify(|ch| ch.policy = policy.clone())
            .or_insert_with(|| SideChannel::new(id, policy));
        true
    }

    /// 创建动态信道 (自动分配 ID)
    pub fn create_dynamic_channel(&mut self, policy: SideChannelPolicy) -> Option<u32> {
        if self.channels.len() >= MAX_SIDE_CHANNELS { return None; }
        
        let id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(1);
        if self.next_local_id < 1000 { self.next_local_id = 1000; }

        self.channels.insert(id, SideChannel::new(id, policy));
        Some(id)
    }

    /// 发送消息 (入队)
    pub fn send_message(&mut self, id: u32, data: Vec<u8>) -> bool {
        if let Some(ch) = self.channels.get_mut(&id) {
            ch.push_send(data)
        } else {
            false
        }
    }

    /// 处理从网络接收到的原始帧
    /// 返回: true (成功处理), false (信道拒绝或不存在)
    pub fn on_frame_received(&mut self, id: u32, data: Vec<u8>) -> bool {
        // 自动创建默认信道 (Lazy Accept)
        if !self.channels.contains_key(&id) {
            // 默认策略：不可靠、低优先、短超时，防止恶意创建大量状态
            let default_policy = SideChannelPolicy {
                mode: ChannelMode::Datagram,
                priority: 50,
                timeout: Duration::from_secs(10),
                rate_limit: 1024 * 10, // 10KB/s 限制
                padding: PaddingMode::None,
            };
            if !self.register_or_update_channel(id, default_policy) {
                return false;
            }
        }

        if let Some(ch) = self.channels.get_mut(&id) {
            // 处理保序和去重
            let ready_msgs = ch.process_ingress(data);
            
            // 将就绪消息放入 Outbox 供上层提取
            if !ready_msgs.is_empty() {
                let queue = self.rx_outbox.entry(id).or_insert_with(VecDeque::new);
                for msg in ready_msgs {
                    // 防止接收端 Outbox 无限膨胀 (DoS)
                    if queue.iter().map(|v| v.len()).sum::<usize>() < MAX_BUFFER_PER_CHANNEL {
                        queue.push_back(msg);
                    } else {
                        warn!("SideChannel {}: RX Outbox full, dropping message", id);
                    }
                }
            }
            return true;
        }
        false
    }

    /// 上层提取接收到的消息
    pub fn recv_message(&mut self, id: u32) -> Option<Vec<u8>> {
        self.rx_outbox.get_mut(&id).and_then(|q| q.pop_front())
    }

    /// 获取所有有待处理消息的信道 ID
    pub fn active_channel_ids(&self) -> Vec<u32> {
        self.rx_outbox.keys().cloned().collect()
    }

    /// 提取待发送的帧 (Traffic Shaping & Scheduling)
    pub fn pop_outgoing_frames(&mut self, limit_bytes: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut total_bytes = 0;

        // 1. 获取所有有发送数据的信道
        let mut candidates: Vec<&mut SideChannel> = self.channels.values_mut()
            .filter(|ch| !ch.tx_queue.is_empty())
            .collect();

        // 2. 优先级排序 (Simple Priority)
        // 生产级优化：此处应使用 Deficit Round Robin (DRR) 以兼顾公平性
        candidates.sort_by(|a, b| b.policy.priority.cmp(&a.policy.priority));

        // 3. 填充配额
        for ch in candidates {
            if total_bytes >= limit_bytes { break; }

            // 每个信道每次调度的配额 (Burst)，防止高优先级饿死低优先级
            // 高优先级的 Burst 更大
            let burst_limit = (ch.policy.priority as usize * 64).max(1024); 
            let mut sent_this_round = 0;

            while sent_this_round < burst_limit && total_bytes < limit_bytes {
                if let Some(data) = ch.tx_queue.pop_front() {
                    let len = data.len();
                    // 这里不再次检查 Rate Limit，因为入队时已经检查过了
                    // 入队是 Token Bucket 生产控制，出队是 Priority 调度控制
                    
                    ch.bytes_sent += len;
                    total_bytes += len;
                    sent_this_round += len;

                    frames.push(Frame::SideChannel {
                        channel_id: ch.id,
                        data,
                    });
                } else {
                    break;
                }
            }
        }

        frames
    }

    /// 定时维护 (清理超时信道)
    pub fn maintenance(&mut self) {
        let mut to_remove = Vec::new();
        for (id, ch) in self.channels.iter() {
            if ch.is_expired() {
                to_remove.push(*id);
            }
        }
        for id in to_remove {
            debug!("SideChannel {} expired, cleaning up", id);
            self.channels.remove(&id);
            self.rx_outbox.remove(&id);
        }
    }
}
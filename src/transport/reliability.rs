// etp-core/src/transport/reliability.rs

use std::collections::{BTreeMap, VecDeque, HashSet, HashMap};
use std::time::{Duration, Instant};
use bytes::Bytes;
use crate::wire::frame::Frame;
use crate::PacketNumber;
use super::congestion::{CongestionControlAlgo, NewReno};
use super::padding::{PaddingStrategy, NoPadding};

// 配置
const MAX_SACK_RANGES: usize = 32;
const MAX_ACK_DELAY_MS: u64 = 25;
const TIMER_WHEEL_SLOTS: usize = 2048;
const TIMER_TICK_MS: u64 = 1;

/// 多路复用模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiplexingMode {
    /// 严格单流模式 (TCP-Like): 无论 Frame 中的 StreamID 是多少，都按到达顺序全局合并。
    /// 强制 HOL 阻塞，适合伪装成 TLS/TCP，特征最少。
    StrictSingle,
    /// 并行多流模式 (QUIC-Like): 每个 StreamID 独立重组，互不阻塞。
    /// 适合高性能并发传输，尤其是 FakeQUIC 场景。
    ParallelMulti,
}

/// 飞行中的包元数据
#[derive(Debug)]
struct InFlightPacket {
    sent_time: Instant,
    frames: Vec<Frame>,
    size: usize,
    retransmitted: bool,
}

/// SACK 区间
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange(pub u64, pub u64);

/// 高精度时间轮定时器
struct TimerWheel {
    slots: Vec<HashSet<PacketNumber>>,
    current_tick: usize,
    start_time: Instant,
    lookup: BTreeMap<PacketNumber, (usize, Instant)>,
}

impl TimerWheel {
    fn new() -> Self {
        let slots = vec![HashSet::new(); TIMER_WHEEL_SLOTS];
        Self {
            slots,
            current_tick: 0,
            start_time: Instant::now(),
            lookup: BTreeMap::new(),
        }
    }

    fn tick(&mut self) -> Vec<PacketNumber> {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.start_time).as_millis() as u64;
        let target_tick = (elapsed_ms / TIMER_TICK_MS) as usize;
        
        let mut expired = Vec::new();
        while self.current_tick <= target_tick {
            let slot_idx = self.current_tick % TIMER_WHEEL_SLOTS;
            let ids: Vec<PacketNumber> = self.slots[slot_idx].drain().collect();
            for id in ids {
                if let Some((_, expiry)) = self.lookup.get(&id) {
                    if *expiry <= now {
                        expired.push(id);
                        self.lookup.remove(&id);
                    } else {
                        // 未超时，重新调度 (处理时间轮多圈情况或哈希冲突)
                        // 简化版：这里重新 schedule 会更新 lookup
                        let _ = self.schedule(id, *expiry); 
                    }
                }
            }
            self.current_tick += 1;
        }
        expired
    }

    fn schedule(&mut self, pn: PacketNumber, expiry: Instant) {
        self.cancel(pn);
        let now = Instant::now();
        let delay = if expiry > now { expiry - now } else { Duration::ZERO };
        let delay_ticks = (delay.as_millis() as u64 / TIMER_TICK_MS) as usize;
        let target_tick = self.current_tick + delay_ticks;
        let slot_idx = target_tick % TIMER_WHEEL_SLOTS;
        self.slots[slot_idx].insert(pn);
        self.lookup.insert(pn, (target_tick, expiry));
    }

    fn cancel(&mut self, pn: PacketNumber) {
        if let Some((tick, _)) = self.lookup.remove(&pn) {
            let slot_idx = tick % TIMER_WHEEL_SLOTS;
            self.slots[slot_idx].remove(&pn);
        }
    }
}

/// 零拷贝流重组器
#[derive(Debug)]
pub struct StreamReassembler {
    next_expected_offset: u64,
    buffer: BTreeMap<u64, Bytes>, 
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self { next_expected_offset: 0, buffer: BTreeMap::new() }
    }

    pub fn push(&mut self, offset: u64, data: Bytes) -> Vec<Bytes> {
        let len = data.len() as u64;
        let end_offset = offset + len;
        
        if end_offset <= self.next_expected_offset {
            return Vec::new(); // 既往数据，丢弃
        }
        if offset >= self.next_expected_offset {
            self.buffer.insert(offset, data);
        }

        let mut result = Vec::new();
        while let Some(entry) = self.buffer.first_entry() {
            let chunk_offset = *entry.key();
            if chunk_offset == self.next_expected_offset {
                let chunk = entry.remove();
                self.next_expected_offset += chunk.len() as u64;
                result.push(chunk);
            } else if chunk_offset < self.next_expected_offset {
                // 处理部分重叠
                let chunk = entry.remove();
                let overlap = self.next_expected_offset - chunk_offset;
                if overlap < chunk.len() as u64 {
                    let new_chunk = chunk.slice((overlap as usize)..);
                    self.next_expected_offset += new_chunk.len() as u64;
                    result.push(new_chunk);
                }
            } else {
                break; // 乱序，等待前序包
            }
        }
        result
    }
}

/// 流管理器：处理单流或多流策略
pub enum StreamManager {
    Single(StreamReassembler),
    Multi(HashMap<u32, StreamReassembler>),
}

impl StreamManager {
    fn new(mode: MultiplexingMode) -> Self {
        match mode {
            MultiplexingMode::StrictSingle => StreamManager::Single(StreamReassembler::new()),
            MultiplexingMode::ParallelMulti => StreamManager::Multi(HashMap::new()),
        }
    }

    /// 推送数据片段
    /// 返回: Vec<(StreamID, DataChunk)>
    fn push(&mut self, stream_id: u32, offset: u64, data: Bytes) -> Vec<(u32, Vec<u8>)> {
        match self {
            StreamManager::Single(reassembler) => {
                // 单流模式下，强制忽略 stream_id 的差异，全部视为同一流处理 (Sequence必须全局单调)
                // 这里我们将数据放入唯一的重组器，但返回时仍带上原始 stream_id，
                // 以便上层 RouterFlavor 可以继续通过 Header 分流。
                let chunks = reassembler.push(offset, data);
                chunks.into_iter().map(|b| (stream_id, b.to_vec())).collect() 
            },
            StreamManager::Multi(map) => {
                let reassembler = map.entry(stream_id).or_insert_with(StreamReassembler::new);
                let chunks = reassembler.push(offset, data);
                chunks.into_iter().map(|b| (stream_id, b.to_vec())).collect()
            }
        }
    }
}

/// 可靠性层：集成了 Mod 和 Strategies
pub struct ReliabilityLayer {
    // --- 发送端 ---
    next_packet_num: PacketNumber,
    sent_queue: BTreeMap<PacketNumber, InFlightPacket>,
    timer_wheel: TimerWheel,
    
    // Mods (策略)
    pub congestion: Box<dyn CongestionControlAlgo>,
    pub padding_strategy: Box<dyn PaddingStrategy>,
    
    // --- 接收端 ---
    largest_received: PacketNumber,
    received_ranges: VecDeque<AckRange>, 
    ack_needed: bool,
    ack_alarm: Option<Instant>,

    // --- 应用层流管理 ---
    pub stream_manager: StreamManager,
}

impl ReliabilityLayer {
    pub fn new(mode: MultiplexingMode) -> Self {
        Self {
            next_packet_num: 1,
            sent_queue: BTreeMap::new(),
            timer_wheel: TimerWheel::new(),
            // 默认策略
            congestion: Box::new(NewReno::new()), 
            padding_strategy: Box::new(NoPadding),
            
            largest_received: 0,
            received_ranges: VecDeque::new(),
            ack_needed: false,
            ack_alarm: None,
            
            stream_manager: StreamManager::new(mode),
        }
    }

    /// 注入拥塞控制 Mod
    pub fn set_congestion_algo(&mut self, algo: Box<dyn CongestionControlAlgo>) {
        self.congestion = algo;
    }

    /// 注入填充策略 Mod
    pub fn set_padding_strategy(&mut self, strategy: Box<dyn PaddingStrategy>) {
        self.padding_strategy = strategy;
    }

    pub fn get_next_packet_num(&mut self) -> PacketNumber {
        let pn = self.next_packet_num;
        self.next_packet_num += 1;
        pn
    }

    pub fn can_send(&self) -> bool {
        let bytes_inflight = self.sent_queue.values().map(|p| p.size as u64).sum();
        self.congestion.can_send(bytes_inflight) && self.congestion.get_pacing_delay() == Duration::ZERO
    }

    pub fn time_until_send(&self) -> Duration {
        self.congestion.get_pacing_delay()
    }

    /// 计算建议的填充大小
    pub fn calculate_padding(&self, current_len: usize) -> usize {
        let mtu = self.congestion.get_mss() as usize;
        self.padding_strategy.calculate_padding(current_len, mtu)
    }

    pub fn on_packet_sent(&mut self, pn: PacketNumber, frames: Vec<Frame>, size: usize) {
        let reliable_frames: Vec<Frame> = frames.into_iter().filter(|f| {
            matches!(f, Frame::Stream { .. } | Frame::Injection { .. } | Frame::Gossip { .. } | Frame::Relay { .. })
        }).collect();

        if !reliable_frames.is_empty() {
            self.sent_queue.insert(pn, InFlightPacket {
                sent_time: Instant::now(),
                frames: reliable_frames,
                size,
                retransmitted: false,
            });
            
            let rto = self.congestion.get_rto();
            self.timer_wheel.schedule(pn, Instant::now() + rto);
            
            self.congestion.on_packet_sent(1, size);
        }
    }

    /// 处理接收包
    /// 返回: (IsDuplicate, ReassembledData)
    pub fn on_packet_received(&mut self, pn: PacketNumber, frames: Vec<Frame>) -> (bool, Vec<(u32, Vec<u8>)>) {
        if self.is_duplicate(pn) {
            return (true, Vec::new());
        }
        if pn > self.largest_received {
            self.largest_received = pn;
        }
        self.add_to_ranges(pn);
        self.ack_needed = true;
        if self.ack_alarm.is_none() {
            self.ack_alarm = Some(Instant::now() + Duration::from_millis(MAX_ACK_DELAY_MS));
        }

        let mut ready_data = Vec::new();
        // 处理 Frame 中的 Stream 数据
        for frame in frames {
            if let Frame::Stream { stream_id, offset, data, .. } = frame {
                let chunks = self.stream_manager.push(stream_id, offset, Bytes::from(data));
                ready_data.extend(chunks);
            }
        }

        (false, ready_data)
    }

    pub fn on_ack_frame_received(&mut self, largest_acked: PacketNumber, ranges: &[(u64, u64)]) {
        let now = Instant::now();
        let mut rtt_sample = None;
        let mut acked_bytes = 0;
        let mut acked_cnt = 0;

        let mut acked_pns = Vec::new();
        if ranges.is_empty() {
            let keys: Vec<u64> = self.sent_queue.keys().cloned().filter(|&k| k <= largest_acked).collect();
            acked_pns.extend(keys);
        } else {
            for &(start, end) in ranges {
                let keys: Vec<u64> = self.sent_queue.range(start..=end).map(|(k, _)| *k).collect();
                acked_pns.extend(keys);
            }
        }

        for pn in acked_pns {
            if let Some(pkt) = self.sent_queue.remove(&pn) {
                self.timer_wheel.cancel(pn);
                if !pkt.retransmitted {
                    rtt_sample = Some(now.duration_since(pkt.sent_time));
                }
                acked_bytes += pkt.size;
                acked_cnt += 1;
            }
        }

        if acked_cnt > 0 {
            self.congestion.on_ack_received(acked_cnt, rtt_sample);
        }
    }

    pub fn get_lost_frames(&mut self) -> Vec<Frame> {
        let expired_pns = self.timer_wheel.tick();
        let mut lost_frames = Vec::new();
        let mut has_loss = false;

        for pn in expired_pns {
            if let Some(pkt) = self.sent_queue.get_mut(&pn) {
                has_loss = true;
                lost_frames.extend(pkt.frames.clone());
                pkt.retransmitted = true;
            }
            self.sent_queue.remove(&pn); 
        }

        if has_loss {
            self.congestion.on_packet_lost();
        }

        lost_frames
    }

    pub fn should_send_ack(&self) -> bool {
        self.ack_needed && self.ack_alarm.map(|t| Instant::now() >= t).unwrap_or(false)
    }

    pub fn generate_ack(&mut self) -> Frame {
        self.ack_needed = false;
        self.ack_alarm = None;
        let ranges: Vec<(u64, u64)> = self.received_ranges.iter().map(|r| (r.0, r.1)).collect();
        Frame::Ack {
            largest_acknowledged: self.largest_received,
            delay_time_micros: 0,
            ranges,
        }
    }

    fn is_duplicate(&self, pn: PacketNumber) -> bool {
        for r in &self.received_ranges {
            if pn >= r.0 && pn <= r.1 { return true; }
        }
        false
    }

    fn add_to_ranges(&mut self, pn: PacketNumber) {
        self.received_ranges.push_back(AckRange(pn, pn));
        let mut ranges: Vec<AckRange> = self.received_ranges.iter().cloned().collect();
        ranges.sort_by_key(|r| r.0);

        let mut merged = VecDeque::new();
        if let Some(first) = ranges.first() {
            let mut current = *first;
            for next in ranges.iter().skip(1) {
                if next.0 <= current.1 + 1 {
                    current.1 = std::cmp::max(current.1, next.1);
                } else {
                    merged.push_back(current);
                    current = *next;
                }
            }
            merged.push_back(current);
        }
        while merged.len() > MAX_SACK_RANGES { merged.pop_front(); }
        self.received_ranges = merged;
    }
}
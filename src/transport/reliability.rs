// etp-core/src/transport/reliability.rs

use std::collections::{BTreeMap, VecDeque, HashSet};
use std::time::{Duration, Instant};
use bytes::Bytes;
use crate::wire::frame::Frame;
use crate::PacketNumber;
use super::congestion::CongestionController;

// 配置
const MAX_SACK_RANGES: usize = 32;
const MAX_ACK_DELAY_MS: u64 = 25;
const TIMER_WHEEL_SLOTS: usize = 2048; // 时间轮槽位
const TIMER_TICK_MS: u64 = 1; // 1ms 精度

/// 飞行中的包元数据
#[derive(Debug)]
struct InFlightPacket {
    sent_time: Instant,
    frames: Vec<Frame>, // Frame 内部应当持有 Bytes
    size: usize,
    retransmitted: bool,
}

/// SACK 区间
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange(pub u64, pub u64);

/// 高精度时间轮定时器 (Hashed Timing Wheel)
/// 用于 O(1) 插入和 O(1) 触发超时
struct TimerWheel {
    /// 槽位：每个槽是一个 Set，存储在该时间点超时的 PacketNumber
    slots: Vec<HashSet<PacketNumber>>,
    /// 当前指针位置
    current_tick: usize,
    /// 启动时间
    start_time: Instant,
    /// PacketNumber 到 (Tick, ExpiryTime) 的映射，用于取消定时器
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

    /// 推进时间并返回超时的包
    fn tick(&mut self) -> Vec<PacketNumber> {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.start_time).as_millis() as u64;
        let target_tick = (elapsed_ms / TIMER_TICK_MS) as usize;
        
        let mut expired = Vec::new();
        
        // 处理追赶（如果 tick 调用间隔较大）
        while self.current_tick <= target_tick {
            let slot_idx = self.current_tick % TIMER_WHEEL_SLOTS;
            // 取出当前槽位的所有包
            let ids: Vec<PacketNumber> = self.slots[slot_idx].drain().collect();
            
            for id in ids {
                // 验证是否真的超时（处理哈希冲突/多轮次）
                if let Some((_, expiry)) = self.lookup.get(&id) {
                    if *expiry <= now {
                        expired.push(id);
                        self.lookup.remove(&id);
                    } else {
                        // 未超时（可能是下一轮的时间），重新放入
                        // 简化版轮子通常不需要处理这个，因为 insert 会算准 slot
                        // 这里作为防御
                        let _ = self.schedule(id, *expiry); 
                    }
                }
            }
            self.current_tick += 1;
        }
        
        expired
    }

    /// 安排一个超时任务
    fn schedule(&mut self, pn: PacketNumber, expiry: Instant) {
        // 先移除旧的
        self.cancel(pn);

        let now = Instant::now();
        let delay = if expiry > now { expiry - now } else { Duration::ZERO };
        let delay_ticks = (delay.as_millis() as u64 / TIMER_TICK_MS) as usize;
        
        // 计算绝对 tick
        let target_tick = self.current_tick + delay_ticks;
        let slot_idx = target_tick % TIMER_WHEEL_SLOTS;

        self.slots[slot_idx].insert(pn);
        self.lookup.insert(pn, (target_tick, expiry));
    }

    /// 取消定时器
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
    // 使用 Bytes 避免拷贝
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
            return Vec::new();
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
                // 部分重叠处理 (简化: 丢弃头部重叠部分)
                let chunk = entry.remove();
                let overlap = self.next_expected_offset - chunk_offset;
                if overlap < chunk.len() as u64 {
                    let new_chunk = chunk.slice((overlap as usize)..);
                    self.next_expected_offset += new_chunk.len() as u64;
                    result.push(new_chunk);
                }
            } else {
                break;
            }
        }
        result
    }
}

pub struct ReliabilityLayer {
    // --- 发送端 ---
    next_packet_num: PacketNumber,
    sent_queue: BTreeMap<PacketNumber, InFlightPacket>,
    timer_wheel: TimerWheel,
    
    // 公开拥塞控制器以供上层查询 Pacing
    pub congestion: CongestionController,
    
    // --- 接收端 ---
    largest_received: PacketNumber,
    received_ranges: VecDeque<AckRange>, 
    ack_needed: bool,
    ack_alarm: Option<Instant>,

    // --- 应用层流 ---
    pub reassembler: StreamReassembler,
}

impl ReliabilityLayer {
    pub fn new() -> Self {
        Self {
            next_packet_num: 1,
            sent_queue: BTreeMap::new(),
            timer_wheel: TimerWheel::new(),
            congestion: CongestionController::new(),
            
            largest_received: 0,
            received_ranges: VecDeque::new(),
            ack_needed: false,
            ack_alarm: None,
            
            reassembler: StreamReassembler::new(),
        }
    }

    pub fn get_next_packet_num(&mut self) -> PacketNumber {
        let pn = self.next_packet_num;
        self.next_packet_num += 1;
        pn
    }

    /// 检查是否可以发送 (综合窗口和 Pacing)
    pub fn can_send(&self) -> bool {
        self.congestion.can_send_window() && self.congestion.get_pacing_delay() == Duration::ZERO
    }

    /// 获取建议的 Pacing 等待时间
    pub fn time_until_send(&self) -> Duration {
        self.congestion.get_pacing_delay()
    }

    pub fn on_packet_sent(&mut self, pn: PacketNumber, frames: Vec<Frame>, size: usize) {
        let reliable_frames: Vec<Frame> = frames.into_iter().filter(|f| {
            matches!(f, Frame::Stream { .. } | Frame::Injection { .. } | Frame::Gossip { .. } | Frame::Relay { .. })
        }).collect();

        if !reliable_frames.is_empty() {
            // 注册到 Sent Queue
            self.sent_queue.insert(pn, InFlightPacket {
                sent_time: Instant::now(),
                frames: reliable_frames,
                size,
                retransmitted: false,
            });
            
            // 注册超时定时器 (RTO)
            let rto = self.congestion.current_rto();
            self.timer_wheel.schedule(pn, Instant::now() + rto);
            
            // 更新拥塞控制
            self.congestion.on_packet_sent(1, size);
        }
    }

    pub fn on_packet_received(&mut self, pn: PacketNumber) -> bool {
        if self.is_duplicate(pn) {
            return true;
        }
        if pn > self.largest_received {
            self.largest_received = pn;
        }
        self.add_to_ranges(pn);
        self.ack_needed = true;
        if self.ack_alarm.is_none() {
            self.ack_alarm = Some(Instant::now() + Duration::from_millis(MAX_ACK_DELAY_MS));
        }
        false
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
                // 取消定时器
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

    /// 获取丢失的帧 (由 Timer Wheel 驱动)
    pub fn get_lost_frames(&mut self) -> Vec<Frame> {
        // 推进时间轮，获取过期的 PN
        let expired_pns = self.timer_wheel.tick();
        
        let mut lost_frames = Vec::new();
        let mut has_loss = false;

        for pn in expired_pns {
            if let Some(pkt) = self.sent_queue.get_mut(&pn) {
                // 确认是丢失
                has_loss = true;
                lost_frames.extend(pkt.frames.clone());
                pkt.retransmitted = true;
                
                // 重置定时器 (Backoff RTO) - 虽然这里我们可能会移除并重新入队(分配新PN)，
                // 但如果设计为原地重传，则需要重新 schedule。
                // ETP 策略：将 Frames 取出，分配新 PN 发送。旧 PN 留在队列中等待最终清理或由于 RTO 依然没 ACK 而被视为彻底丢失。
                // 为了简化，这里我们标记为 retransmitted，并不移除旧条目，防止对旧 ACK 的误判 RTT。
                // 但我们不再为旧 PN 调度定时器。
            }
            // 从 sent_queue 移除？通常 QUIC 也是保留直到确认或彻底放弃。
            // 这里简化：取出 Frame 重新发送，旧 PN 记录仅用于去重，不再追踪超时。
            self.sent_queue.remove(&pn); 
            if self.congestion.bytes_in_flight > 0 {
                 self.congestion.bytes_in_flight -= 1; 
            }
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
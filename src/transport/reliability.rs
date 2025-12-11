// etp-core/src/transport/reliability.rs

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};
use crate::wire::frame::Frame;
use crate::PacketNumber;
use super::congestion::CongestionController;

// 生产级常量配置
const RTO_INITIAL_MS: u64 = 300;
const RTO_MIN_MS: u64 = 100;
const MAX_ACK_DELAY_MS: u64 = 25;
const MAX_SACK_RANGES: usize = 32; // 最大 ACK 区间数，防止头部膨胀
const REORDERING_THRESHOLD: u64 = 3;

/// 飞行中的包元数据
#[derive(Debug)]
struct InFlightPacket {
    sent_time: Instant,
    frames: Vec<Frame>,
    size: usize,
    retransmitted: bool,
}

/// SACK 区间 (Start, End) Inclusive
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange(pub u64, pub u64);

/// 流重组器：处理乱序数据
#[derive(Debug)]
pub struct StreamReassembler {
    next_expected_offset: u64,
    // Offset -> Data. 使用 BTreeMap 自动排序
    buffer: BTreeMap<u64, Vec<u8>>,
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self { next_expected_offset: 0, buffer: BTreeMap::new() }
    }

    /// 接收数据片段，返回可以按序读取的数据
    pub fn push(&mut self, offset: u64, data: Vec<u8>) -> Vec<u8> {
        let end_offset = offset + data.len() as u64;
        
        // 1. 如果数据已经处理过 (Duplicate)，直接丢弃
        if end_offset <= self.next_expected_offset {
            return Vec::new();
        }

        // 2. 存入缓冲区 (处理重叠逻辑略复杂，这里假设 ETP 切片不对齐重叠)
        // 生产级应处理字节级去重，这里简化为块级插入
        if offset >= self.next_expected_offset {
            self.buffer.insert(offset, data);
        }

        // 3. 尝试组装连续数据
        let mut result = Vec::new();
        while let Some(entry) = self.buffer.first_entry() {
            let chunk_offset = *entry.key();
            
            if chunk_offset == self.next_expected_offset {
                let chunk = entry.remove();
                self.next_expected_offset += chunk.len() as u64;
                result.extend(chunk);
            } else {
                // 遇到空洞 (Gap)，停止组装
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
    srtt: Duration,
    rttvar: Duration,
    pub congestion: CongestionController,
    
    // --- 接收端 ---
    largest_received: PacketNumber,
    // SACK 区间集合: 存储已收到的包序号区间
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
            srtt: Duration::from_millis(RTO_INITIAL_MS),
            rttvar: Duration::from_millis(RTO_INITIAL_MS / 2),
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

    pub fn can_send(&self) -> bool {
        self.congestion.can_send()
    }

    pub fn on_packet_sent(&mut self, pn: PacketNumber, frames: Vec<Frame>, size: usize) {
        // 筛选可靠帧
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
            self.congestion.on_packet_sent(1);
        }
    }

    /// 处理接收到的包序号，维护 SACK Ranges
    pub fn on_packet_received(&mut self, pn: PacketNumber) -> bool {
        // 1. 检查是否重复
        if self.is_duplicate(pn) {
            return true;
        }

        // 2. 更新最大序号
        if pn > self.largest_received {
            self.largest_received = pn;
        }

        // 3. 更新 Ranges (区间合并算法)
        self.add_to_ranges(pn);

        // 4. 触发 ACK
        self.ack_needed = true;
        if self.ack_alarm.is_none() {
            self.ack_alarm = Some(Instant::now() + Duration::from_millis(MAX_ACK_DELAY_MS));
        }

        false
    }

    /// 处理接收到的 ACK 帧 (支持 SACK)
    pub fn on_ack_frame_received(&mut self, largest_acked: PacketNumber, ranges: &[(u64, u64)]) {
        let now = Instant::now();
        let mut rtt_sample = None;

        // 收集所有被确认的包序号
        // 如果 ranges 为空，视为累计确认到 largest_acked
        let mut acked_pns = Vec::new();

        if ranges.is_empty() {
            // Cumulative ACK
            let keys: Vec<u64> = self.sent_queue.keys().cloned().filter(|&k| k <= largest_acked).collect();
            acked_pns.extend(keys);
        } else {
            // SACK Logic
            // Ranges 通常是相对于 largest_acked 的 Gap，或者绝对值。
            // 这里假设 Frame 里的 ranges 是绝对值 (Start, End) Inclusive
            for &(start, end) in ranges {
                let keys: Vec<u64> = self.sent_queue.range(start..=end).map(|(k, _)| *k).collect();
                acked_pns.extend(keys);
            }
        }

        for pn in acked_pns {
            if let Some(pkt) = self.sent_queue.remove(&pn) {
                if !pkt.retransmitted {
                    rtt_sample = Some(now.duration_since(pkt.sent_time));
                }
                self.congestion.on_ack_received(1);
            }
        }

        if let Some(rtt) = rtt_sample {
            self.update_rtt(rtt);
        }
    }

    pub fn get_lost_frames(&mut self) -> Vec<Frame> {
        let now = Instant::now();
        let rto = self.current_rto();
        let mut lost_frames = Vec::new();
        let mut lost_pns = Vec::new();

        // 超时检测
        for (pn, pkt) in self.sent_queue.iter_mut() {
            if now.duration_since(pkt.sent_time) > rto {
                lost_pns.push(*pn);
                lost_frames.extend(pkt.frames.clone());
                pkt.retransmitted = true;
                pkt.sent_time = now; // Reset timer for backoff
            }
        }

        if !lost_pns.is_empty() {
            self.congestion.on_packet_lost();
        }

        // 移除旧包，由新序号承载
        for pn in lost_pns {
            self.sent_queue.remove(&pn);
            // 修正拥塞窗口计数 (因为重发会再次 add)
            if self.congestion.bytes_in_flight > 0 {
                self.congestion.bytes_in_flight -= 1;
            }
        }

        lost_frames
    }

    pub fn should_send_ack(&self) -> bool {
        self.ack_needed && self.ack_alarm.map(|t| Instant::now() >= t).unwrap_or(false)
    }

    pub fn generate_ack(&mut self) -> Frame {
        self.ack_needed = false;
        self.ack_alarm = None;
        
        // 将内部 Ranges 转换为 Frame 格式
        let ranges: Vec<(u64, u64)> = self.received_ranges.iter()
            .map(|r| (r.0, r.1))
            .collect();

        Frame::Ack {
            largest_acknowledged: self.largest_received,
            delay_time_micros: 0,
            ranges,
        }
    }

    // --- Helpers ---

    fn is_duplicate(&self, pn: PacketNumber) -> bool {
        for r in &self.received_ranges {
            if pn >= r.0 && pn <= r.1 { return true; }
        }
        false
    }

    fn add_to_ranges(&mut self, pn: PacketNumber) {
        // 简单的区间合并算法
        // 1. 放入队列
        self.received_ranges.push_back(AckRange(pn, pn));
        // 2. 排序 (虽然通常是顺序到达，但为了正确性)
        let mut ranges: Vec<AckRange> = self.received_ranges.iter().cloned().collect();
        ranges.sort_by_key(|r| r.0);

        // 3. 合并
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
        
        // 4. 限制数量 (丢弃最旧的 ranges)
        while merged.len() > MAX_SACK_RANGES {
            merged.pop_front();
        }
        
        self.received_ranges = merged;
    }

    fn update_rtt(&mut self, latest_rtt: Duration) {
        if self.srtt.as_millis() == RTO_INITIAL_MS as u128 {
            self.srtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
        } else {
            let rttvar_sample = if self.srtt > latest_rtt { self.srtt - latest_rtt } else { latest_rtt - self.srtt };
            self.rttvar = self.rttvar.mul_f32(0.75) + rttvar_sample.mul_f32(0.25);
            self.srtt = self.srtt.mul_f32(0.875) + latest_rtt.mul_f32(0.125);
        }
    }

    fn current_rto(&self) -> Duration {
        let rto = self.srtt + self.rttvar * 4;
        std::cmp::max(rto, Duration::from_millis(RTO_MIN_MS))
    }
}
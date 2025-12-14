// etp-core/src/transport/congestion.rs

use std::time::{Duration, Instant};
use std::cmp;
use std::fmt::Debug;

/// 拥塞控制算法接口 (Strategy/Mod)
/// 允许用户替换内核的拥塞控制逻辑（例如实现 Brutal, BBR, Cubic 等）
pub trait CongestionControlAlgo: Send + Sync + Debug {
    /// 事件：数据包发送
    /// amount: 包数量, bytes: 数据字节数
    fn on_packet_sent(&mut self, amount: usize, bytes: usize);
    
    /// 事件：收到 ACK
    /// amount: 确认的包数量, rtt_sample: 采样到的 RTT (如果是重传包则为 None)
    fn on_ack_received(&mut self, amount: usize, rtt_sample: Option<Duration>);
    
    /// 事件：检测到丢包
    fn on_packet_lost(&mut self);
    
    /// 检查是否允许发送 (基于拥塞窗口)
    /// bytes_in_flight: 当前在途未确认的字节数 (部分算法可能需要此参数)
    fn can_send(&self, bytes_in_flight: u64) -> bool;
    
    /// 获取当前的 Pacing 延迟 (0 表示立即发送)
    /// 用于流量整形，平滑突发流量
    fn get_pacing_delay(&self) -> Duration;
    
    /// 获取当前的重传超时时间 (RTO)
    fn get_rto(&self) -> Duration;
    
    /// 获取当前的最大报文段长度 (MSS)
    fn get_mss(&self) -> u64;
}

// --- 默认实现: NewReno + Pacing ---

// 初始窗口大小 (RFC 6928 建议 10)
const INITIAL_WINDOW: u64 = 10;
// 最小窗口大小 (防止死锁)
const MIN_WINDOW: u64 = 2;
// 初始慢启动阈值 (无穷大)
const INITIAL_SSTHRESH: u64 = u64::MAX;
// 最小 RTT (避免除零)
const MIN_RTT: Duration = Duration::from_micros(1);

/// 拥塞控制状态机
#[derive(Debug, Clone, PartialEq)]
enum State {
    SlowStart,
    CongestionAvoidance,
    Recovery,
}

/// 生产级 NewReno 拥塞控制器，内置 Pacing 支持
#[derive(Debug, Clone)]
pub struct NewReno {
    // --- 标准参数 ---
    pub cwnd: u64,
    pub ssthresh: u64,
    pub bytes_in_flight: u64, // 内部追踪 In-Flight
    state: State,
    
    // --- 辅助计算 ---
    ca_accumulator: u64,
    recovery_start_time: Option<Instant>,
    loss_streak: u32,
    
    // --- Pacing 参数 ---
    srtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
    
    pacing_rate: u64,
    next_departure_time: Instant,
    pacing_gain: f64,
    pub mss: u64,
}

impl NewReno {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            cwnd: INITIAL_WINDOW,
            ssthresh: INITIAL_SSTHRESH,
            bytes_in_flight: 0,
            state: State::SlowStart,
            ca_accumulator: 0,
            recovery_start_time: None,
            loss_streak: 0,
            
            srtt: Duration::from_millis(100), 
            rttvar: Duration::from_millis(50),
            min_rtt: Duration::from_secs(1),
            
            pacing_rate: 0,
            next_departure_time: now,
            pacing_gain: 1.25, // 允许 1.25 倍速率探测带宽
            
            mss: 1350, // 默认保守 MSS，适配 UDP
        }
    }

    fn update_rtt(&mut self, rtt_sample: Duration) {
        let rtt = cmp::max(rtt_sample, MIN_RTT);
        
        if self.min_rtt == Duration::from_secs(1) || rtt < self.min_rtt {
            self.min_rtt = rtt;
        }

        if self.srtt.as_millis() == 100 { 
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let rttvar_sample = if self.srtt > rtt { self.srtt - rtt } else { rtt - self.srtt };
            self.rttvar = self.rttvar.mul_f32(0.75) + rttvar_sample.mul_f32(0.25);
            self.srtt = self.srtt.mul_f32(0.875) + rtt.mul_f32(0.125);
        }
    }

    fn update_pacing_rate(&mut self) {
        let rtt_micros = self.srtt.as_micros() as u64;
        if rtt_micros == 0 { return; }

        let effective_cwnd = if self.cwnd == 0 { 1 } else { self.cwnd };
        let cwnd_bytes = effective_cwnd * self.mss;
        let bandwidth_bps = (cwnd_bytes as u128 * 1_000_000) / rtt_micros as u128;
        let paced_rate = (bandwidth_bps as f64 * self.pacing_gain) as u64;
        const MIN_PACING_RATE: u64 = 10 * 1024; // 10 KB/s 最小保活
        
        self.pacing_rate = std::cmp::max(paced_rate, MIN_PACING_RATE);
    }
}

impl CongestionControlAlgo for NewReno {
    fn on_packet_sent(&mut self, amount: usize, bytes: usize) {
        self.bytes_in_flight += amount as u64;
        
        if self.pacing_rate > 0 {
            // 计算发送该包需要的时间增量
            let delay_micros = (bytes as u64 * 1_000_000) / self.pacing_rate;
            let delay = Duration::from_micros(delay_micros);
            let now = Instant::now();
            
            // 如果上次计划时间已过，重置为当前时间，避免 Burst
            if self.next_departure_time < now {
                self.next_departure_time = now + delay;
            } else {
                self.next_departure_time += delay;
            }
        }
    }

    fn on_ack_received(&mut self, amount: usize, rtt_sample: Option<Duration>) {
        let amount = amount as u64;
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(amount);

        if let Some(rtt) = rtt_sample {
            self.update_rtt(rtt);
            self.update_pacing_rate();
        }

        self.loss_streak = 0;

        // 收到 ACK 视为恢复成功 (NewReno 简化逻辑)
        if let Some(_) = self.recovery_start_time {
            self.state = State::CongestionAvoidance;
            self.recovery_start_time = None;
        }

        match self.state {
            State::SlowStart => {
                self.cwnd += amount;
                if self.cwnd >= self.ssthresh {
                    self.state = State::CongestionAvoidance;
                }
            },
            State::CongestionAvoidance => {
                self.ca_accumulator += amount;
                if self.ca_accumulator >= self.cwnd {
                    self.cwnd += 1;
                    self.ca_accumulator = 0;
                }
            },
            State::Recovery => {
                // Recovery 期间维持窗口或微调，不进行增长
            }
        }
    }

    fn on_packet_lost(&mut self) {
        let now = Instant::now();
        // 防抖动：一个 RTT 内只减窗一次
        if let Some(last_loss) = self.recovery_start_time {
            if now.duration_since(last_loss) < self.srtt { return; }
        }

        self.state = State::Recovery;
        self.recovery_start_time = Some(now);
        self.loss_streak += 1;

        // Multiplicative Decrease
        self.ssthresh = cmp::max(self.cwnd / 2, MIN_WINDOW);
        self.cwnd = self.ssthresh;

        // 严重丢包回退到最小窗口
        if self.loss_streak > 3 {
             self.cwnd = MIN_WINDOW;
        }
    }

    fn can_send(&self, _external_inflight: u64) -> bool {
        // NewReno 信任内部计数，也可扩展为校验 external_inflight
        self.bytes_in_flight < self.cwnd
    }

    fn get_pacing_delay(&self) -> Duration {
        let now = Instant::now();
        if self.next_departure_time > now {
            self.next_departure_time - now
        } else {
            Duration::ZERO
        }
    }

    fn get_rto(&self) -> Duration {
        let rto = self.srtt + self.rttvar * 4;
        let base_rto = cmp::max(rto, Duration::from_millis(100));
        
        if self.loss_streak == 0 {
            base_rto
        } else {
            // 指数退避
            let shift = cmp::min(self.loss_streak, 6); 
            let factor = 1 << shift;
            let backed_off = base_rto * factor;
            cmp::min(backed_off, Duration::from_secs(60))
        }
    }

    fn get_mss(&self) -> u64 {
        self.mss
    }
}
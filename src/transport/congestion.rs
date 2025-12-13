// etp-core/src/transport/congestion.rs

use std::time::{Duration, Instant};
use std::cmp;

// 初始窗口大小 (RFC 6928 建议 10)
const INITIAL_WINDOW: u64 = 10;
// 最小窗口大小 (防止死锁)
const MIN_WINDOW: u64 = 2;
// 初始慢启动阈值 (无穷大)
const INITIAL_SSTHRESH: u64 = u64::MAX;
// 最小 RTT (避免除零)
const MIN_RTT: Duration = Duration::from_micros(1);

/// 拥塞控制状态
#[derive(Debug, Clone, PartialEq)]
enum State {
    /// 慢启动: 窗口指数增长
    SlowStart,
    /// 拥塞避免: 窗口线性增长
    CongestionAvoidance,
    /// 恢复模式: 发生丢包，窗口减半
    Recovery,
}

/// 生产级 NewReno 拥塞控制器，增强了 Pacing 支持
#[derive(Debug, Clone)]
pub struct CongestionController {
    // --- 标准拥塞控制参数 ---
    /// 拥塞窗口大小 (单位: MSS / 包数量)
    pub cwnd: u64,
    /// 慢启动阈值
    pub ssthresh: u64,
    /// 当前在途的负载量 (In Flight)
    pub bytes_in_flight: u64,
    /// 内部状态机
    state: State,
    
    // --- 辅助计算 ---
    /// 拥塞避免阶段的累加器
    ca_accumulator: u64,
    /// 恢复期的起始时间 (防抖动)
    recovery_start_time: Option<Instant>,
    /// 连续超时计数器
    loss_streak: u32,
    
    // --- Pacing (起搏器) 参数 ---
    /// 平滑 RTT (Smoothed RTT)
    srtt: Duration,
    /// RTT 变化量
    rttvar: Duration,
    /// 最小 RTT 观测值 (用于计算带宽上限)
    min_rtt: Duration,
    
    /// 当前估算的起搏速率 (Bytes / sec)
    pacing_rate: u64,
    /// 下一次允许发包的时间 (用于平滑突发流量)
    next_departure_time: Instant,
    /// Pacing 增益 (通常 1.0 或 1.25)
    pacing_gain: f64,
    /// 最大报文段长度 (Bytes)，通常由握手协商或 PMTUD 决定
    pub mss: u64,
}

impl CongestionController {
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
            
            // 初始化为较大的保守值
            srtt: Duration::from_millis(100), 
            rttvar: Duration::from_millis(50),
            min_rtt: Duration::from_secs(1),
            
            pacing_rate: 0,
            next_departure_time: now,
            pacing_gain: 1.25, // 允许稍微超发以探测带宽
            
            // 默认保守值，通常 IPv6 为 1232，IPv4 为 1460。
            // 生产环境应从配置读取或设为 1200 (兼顾最差情况)
            mss: 1460, 
        }
    }

    /// 检查当前拥塞窗口是否允许发送
    pub fn can_send_window(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }
    
    /// 获取 Pacing 延迟
    /// 返回需要等待的时间。如果为 ZERO，则表示可以立即发送。
    pub fn get_pacing_delay(&self) -> Duration {
        let now = Instant::now();
        if self.next_departure_time > now {
            self.next_departure_time - now
        } else {
            Duration::ZERO
        }
    }

    /// 事件：数据包已发送
    /// amount: 包数量 (用于 cwnd 计数)
    /// bytes: 字节数 (用于 Pacing 计算)
    pub fn on_packet_sent(&mut self, amount: usize, bytes: usize) {
        self.bytes_in_flight += amount as u64;
        
        // 更新 Pacing 下次发送时间
        if self.pacing_rate > 0 {
            // 时间增量 = 字节数 / 速率
            // 避免浮点运算，使用微秒整数运算
            // rate is bytes/sec. time = bytes / rate.
            // time_micros = bytes * 1_000_000 / rate
            let delay_micros = (bytes as u64 * 1_000_000) / self.pacing_rate;
            let delay = Duration::from_micros(delay_micros);
            
            let now = Instant::now();
            // 如果 next_departure_time 滞后太久，重置为 now，避免积累爆发
            if self.next_departure_time < now {
                self.next_departure_time = now + delay;
            } else {
                self.next_departure_time += delay;
            }
        }
    }

    /// 事件：收到 ACK
    pub fn on_ack_received(&mut self, amount: usize, rtt_sample: Option<Duration>) {
        let amount = amount as u64;
        
        // 1. 更新 In Flight
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(amount);

        // 2. 更新 RTT 和 Pacing Rate
        if let Some(rtt) = rtt_sample {
            self.update_rtt(rtt);
            self.update_pacing_rate();
        }

        self.loss_streak = 0;

        // 3. 退出恢复模式逻辑
        if let Some(_) = self.recovery_start_time {
            // NewReno 简化逻辑：收到 ACK 视为恢复成功
            self.state = State::CongestionAvoidance;
            self.recovery_start_time = None;
        }

        // 4. 调整窗口
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
                // 恢复期间保持窗口，或略微增加 (Proportional Rate Reduction 的简化)
            }
        }
    }

    /// 事件：发生丢包
    pub fn on_packet_lost(&mut self) {
        let now = Instant::now();

        // 防抖动
        if let Some(last_loss) = self.recovery_start_time {
            if now.duration_since(last_loss) < self.srtt {
                return;
            }
        }

        self.state = State::Recovery;
        self.recovery_start_time = Some(now);
        self.loss_streak += 1;

        // Multiplicative Decrease
        self.ssthresh = cmp::max(self.cwnd / 2, MIN_WINDOW);
        self.cwnd = self.ssthresh;

        // 严重丢包回退
        if self.loss_streak > 3 {
             self.cwnd = MIN_WINDOW;
        }
    }

    /// 计算 RTO
    pub fn current_rto(&self) -> Duration {
        // Jacobson/Karels Algorithm
        let rto = self.srtt + self.rttvar * 4;
        // 加上指数退避
        let base_rto = cmp::max(rto, Duration::from_millis(100)); // Min RTO 100ms
        
        if self.loss_streak == 0 {
            base_rto
        } else {
            let shift = cmp::min(self.loss_streak, 6); 
            let factor = 1 << shift;
            let backed_off = base_rto * factor;
            cmp::min(backed_off, Duration::from_secs(60))
        }
    }

    // --- 内部计算 ---

    fn update_rtt(&mut self, rtt_sample: Duration) {
        let rtt = cmp::max(rtt_sample, MIN_RTT);
        
        if self.min_rtt == Duration::from_secs(1) || rtt < self.min_rtt {
            self.min_rtt = rtt;
        }

        if self.srtt.as_millis() == 100 { // Initial
            self.srtt = rtt;
            self.rttvar = rtt / 2;
        } else {
            let rttvar_sample = if self.srtt > rtt { self.srtt - rtt } else { rtt - self.srtt };
            self.rttvar = self.rttvar.mul_f32(0.75) + rttvar_sample.mul_f32(0.25);
            self.srtt = self.srtt.mul_f32(0.875) + rtt.mul_f32(0.125);
        }
    }

    /// 更新 Pacing Rate (起搏速率)
    /// 
    /// 基于当前的拥塞窗口 (cwnd)、平滑 RTT (srtt) 和 最大报文段长度 (MSS) 计算目标发送速率。
    /// 
    /// 公式: Rate = (Cwnd * MSS / SRTT) * Gain
    fn update_pacing_rate(&mut self) {
        // 1. 获取微秒级 SRTT，防止除零错误
        let rtt_micros = self.srtt.as_micros() as u64;
        if rtt_micros == 0 {
            return; // 无法计算，保持原有速率或默认值
        }

        // 2. 计算拥塞窗口的字节当量
        // 生产级实现必须依赖真实的 MSS (Maximum Segment Size)，而不是假设固定值。
        // self.mss 应在连接建立时协商，或通过 PMTUD (Path MTU Discovery) 动态更新。
        // 如果 cwnd 为 0 (极罕见)，强制设为 1 以保证最小保活流量。
        let effective_cwnd = if self.cwnd == 0 { 1 } else { self.cwnd };
        let cwnd_bytes = effective_cwnd * self.mss;

        // 3. 计算基础带宽 (Bandwidth in Bytes/sec)
        // 使用 u128 防止乘法溢出 (cwnd_bytes * 1,000,000 可能超过 u64 范围)
        let bandwidth_bps = (cwnd_bytes as u128 * 1_000_000) / rtt_micros as u128;

        // 4. 应用 Pacing Gain (起搏增益)
        // Pacing Gain 通常设为 > 1.0 (如 1.25)，允许发送速率略高于估算带宽，
        // 以便探测额外的可用带宽并容忍 ACK 压缩 (ACK Compression)。
        // 
        // 这里的计算方法：Rate = Bw * Gain
        // 我们避免浮点运算以保证内核级或嵌入式环境的兼容性及确定性。
        // 假设 pacing_gain 为 f64 (如 1.25)
        let paced_rate = (bandwidth_bps as f64 * self.pacing_gain) as u64;

        // 5. 设置下限 (Min Pacing Rate)
        // 防止速率过低导致连接超时。假设最小 1 MSS / RTT 或一个保守值 (如 10KB/s)。
        // 这里使用 10 KB/s 作为绝对底线。
        const MIN_PACING_RATE: u64 = 10 * 1024; 
        
        self.pacing_rate = std::cmp::max(paced_rate, MIN_PACING_RATE);
    }
}
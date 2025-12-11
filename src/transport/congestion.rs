// etp-core/src/transport/congestion.rs

use std::time::{Duration, Instant};
use std::cmp;

// 初始窗口大小 (RFC 6928 建议 10)
const INITIAL_WINDOW: u64 = 10;
// 最小窗口大小 (防止死锁)
const MIN_WINDOW: u64 = 2;
// 初始慢启动阈值 (无穷大)
const INITIAL_SSTHRESH: u64 = u64::MAX;

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

/// 生产级 NewReno 拥塞控制器
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// 拥塞窗口大小 (Congestion Window)
    /// 单位: 负载单位 (通常为包数量，也可以配置为字节)
    pub cwnd: u64,
    
    /// 慢启动阈值 (Slow Start Threshold)
    /// 当 cwnd >= ssthresh 时，切换到拥塞避免模式
    pub ssthresh: u64,
    
    /// 当前在途的负载量 (In Flight)
    /// 已发送但未收到 ACK 的量
    pub bytes_in_flight: u64,
    
    /// 内部状态机
    state: State,
    
    /// 拥塞避免阶段的累加器
    /// 用于在整数运算下模拟 cwnd += 1/cwnd 的浮点增长
    ca_accumulator: u64,

    /// 恢复期的起始时间
    /// 用于防止在同一个 RTT 内多次触发窗口减半 (Debouncing)
    recovery_start_time: Option<Instant>,
    
    /// 连续超时计数器 (用于 RTO 退避)
    loss_streak: u32,
}

impl CongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            ssthresh: INITIAL_SSTHRESH,
            bytes_in_flight: 0,
            state: State::SlowStart,
            ca_accumulator: 0,
            recovery_start_time: None,
            loss_streak: 0,
        }
    }

    /// 检查当前是否允许发送数据
    /// 如果在途数据量小于拥塞窗口，则允许发送
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /// 事件：数据包已发送
    /// amount: 发送的量 (包数量或字节数，需与 Ack 保持一致)
    pub fn on_packet_sent(&mut self, amount: usize) {
        self.bytes_in_flight += amount as u64;
    }

    /// 事件：收到 ACK
    /// amount: 被确认的量 (通常为 1 个包)
    pub fn on_ack_received(&mut self, amount: usize) {
        let amount = amount as u64;
        
        // 1. 更新 In Flight
        if self.bytes_in_flight >= amount {
            self.bytes_in_flight -= amount;
        } else {
            // 防御性编程：防止下溢
            self.bytes_in_flight = 0;
        }

        // 2. 如果之前处于超时/丢包状态，现在收到了 ACK，说明网络恢复
        // 重置连续丢包计数
        self.loss_streak = 0;

        // 3. 检查是否退出恢复模式
        // NewReno 通常在收到覆盖了恢复点的 ACK 时退出，
        // 这里简化为：只要网络通畅且过了一定时间，就尝试退出恢复
        if let Some(start) = self.recovery_start_time {
            // 这里我们用一种简单的启发式：如果恢复期持续超过了 1 秒 (或者基于 RTT)，重置状态
            // 但标准 NewReno 是基于 Packet Number 的。
            // 为了适配 ETP 的架构，我们简单处理：收到 ACK 就视为这一波恢复有进展。
            // 如果处于 Recovery 状态，NewReno 不增加窗口，只维持。
            // 但为了性能，如果我们确认了数据，我们可以尝试慢慢恢复。
            
            // 策略：收到 ACK 后，如果是 Recovery，我们保持窗口不变或微调。
            // 此处实现：Recovery 期间不增长窗口，直到显式退出 (通常由外部逻辑或超时重置)。
            // 但为了防止永久卡在 Recovery，我们在这里设定：收到 ACK 就转回 CongestionAvoidance
            // 除非外部显式再次触发丢包。
            self.state = State::CongestionAvoidance;
            self.recovery_start_time = None;
        }

        // 4. 调整窗口
        match self.state {
            State::SlowStart => {
                // 慢启动: 每收到一个 ACK，窗口 +1 (指数增长)
                // cwnd += acknowledged
                self.cwnd += amount;
                
                // 检查是否达到阈值
                if self.cwnd >= self.ssthresh {
                    self.state = State::CongestionAvoidance;
                }
            },
            State::CongestionAvoidance => {
                // 拥塞避免: 每个 RTT 窗口 +1 (线性增长)
                // 公式: cwnd += 1 / cwnd
                // 整数实现: 使用累加器
                self.ca_accumulator += amount;
                
                // 当累加器达到当前窗口大小时，窗口加 1
                if self.ca_accumulator >= self.cwnd {
                    self.cwnd += 1;
                    self.ca_accumulator = 0;
                }
            },
            State::Recovery => {
                // 恢复模式下，通常不增加窗口，或者仅进行部分恢复
                // 这里保持窗口不变，等待退出恢复模式
            }
        }
    }

    /// 事件：发生丢包 (超时或重复 ACK)
    /// 触发快速重传/快速恢复逻辑
    pub fn on_packet_lost(&mut self) {
        let now = Instant::now();

        // 防抖动 (Debouncing): 
        // 防止在同一个 RTT 窗口内，因为多个包同时超时而连续多次减半窗口。
        // 如果距离上次进入恢复模式还不到 500ms (或者 1 RTT)，则忽略这次窗口调整。
        if let Some(last_loss) = self.recovery_start_time {
            if now.duration_since(last_loss) < Duration::from_millis(500) {
                return;
            }
        }

        // 进入恢复模式
        self.state = State::Recovery;
        self.recovery_start_time = Some(now);
        self.loss_streak += 1;

        // 乘法减小 (Multiplicative Decrease)
        // ssthresh = max(cwnd / 2, 2)
        self.ssthresh = cmp::max(self.cwnd / 2, MIN_WINDOW);
        
        // cwnd = ssthresh
        // 某些算法这里会设置为 1 (Timeout) 或 ssthresh (Fast Retransmit)
        // ETP 采用 NewReno 策略：设置为 ssthresh
        self.cwnd = self.ssthresh;

        // 如果连续丢包严重，回退到 1 (类似 TCP RTO)
        if self.loss_streak > 3 {
             self.cwnd = MIN_WINDOW;
        }
    }

    /// 计算 RTO 退避 (Exponential Backoff)
    /// base_rto: 基于 RTT 计算出的基础 RTO
    pub fn backoff_rto(&self, base_rto: Duration) -> Duration {
        if self.loss_streak == 0 {
            return base_rto;
        }
        
        // 指数退避: rto * 2^loss_streak
        // 限制最大退避次数，防止溢出或等待过久
        let shift = cmp::min(self.loss_streak, 6); // 最大 64 倍
        let factor = 1 << shift;
        
        let mut backed_off = base_rto * factor;
        
        // 设定上限，例如最大 60 秒
        if backed_off > Duration::from_secs(60) {
            backed_off = Duration::from_secs(60);
        }
        
        backed_off
    }
    
    // 调试辅助
    pub fn debug_state(&self) -> String {
        format!(
            "Cwnd: {}, InFlight: {}, SST: {}, State: {:?}, LossStreak: {}", 
            self.cwnd, self.bytes_in_flight, self.ssthresh, self.state, self.loss_streak
        )
    }
}
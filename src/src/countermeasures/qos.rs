// etp-core/src/countermeasures/qos.rs

use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// 抗 QoS 策略引擎
pub struct QosGuardian {
    last_packet_time: Instant,
    rtt_history: VecDeque<u64>,
    
    // 配置
    heartbeat_interval: Duration,
    fec_ratio: f32, // 冗余比例
}

impl QosGuardian {
    pub fn new() -> Self {
        Self {
            last_packet_time: Instant::now(),
            rtt_history: VecDeque::new(),
            heartbeat_interval: Duration::from_millis(50), // 模拟 VoIP 高频小包
            fec_ratio: 0.1,
        }
    }

    /// 记录 RTT 用于抖动分析
    pub fn record_rtt(&mut self, rtt_ms: u64) {
        if self.rtt_history.len() > 20 {
            self.rtt_history.pop_front();
        }
        self.rtt_history.push_back(rtt_ms);
    }

    /// 检测是否需要发送保活包
    /// 运营商通常会对长静默的 UDP 连接断流，或者对只有下行没有上行的连接限速
    pub fn needs_heartbeat(&self) -> bool {
        self.last_packet_time.elapsed() > self.heartbeat_interval
    }

    /// 动态 FEC 计算
    /// 如果发现 RTT 抖动变大（意味着网络拥塞或 QoS 干扰），增加冗余度
    pub fn calculate_dynamic_fec(&self) -> usize {
        if self.rtt_history.len() < 2 { return 0; }
        
        let sum: u64 = self.rtt_history.iter().sum();
        let avg = sum as f64 / self.rtt_history.len() as f64;
        
        let variance: f64 = self.rtt_history.iter()
            .map(|&x| (x as f64 - avg).powi(2))
            .sum::<f64>() / self.rtt_history.len() as f64;
        let jitter = variance.sqrt();

        // 简单的自适应逻辑：抖动越大，冗余越多
        if jitter > 50.0 {
            3 // High redundancy
        } else if jitter > 20.0 {
            1 // Low redundancy
        } else {
            0
        }
    }

    pub fn mark_sent(&mut self) {
        self.last_packet_time = Instant::now();
    }
}
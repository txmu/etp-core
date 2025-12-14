use tokio::time::{sleep_until, Instant, Duration};
use rand::Rng;

/// 安全配置档案
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityProfile {
    /// 极速模式：无额外延迟，仅用于传输
    Turbo,
    /// 平衡模式：引入随机抖动 (Jitter)，破坏指纹
    Balanced,
    /// 偏执模式：恒定比特率 (CBR)，抗高级流量分析
    /// 强制每隔固定时间发送固定大小的包
    Paranoid {
        interval_ms: u64, // 发包间隔 (如 20ms)
        target_size: usize, // 目标包大小 (如 1350 bytes)
    },
}

/// 流量整形器
pub struct TrafficShaper {
    profile: SecurityProfile,
    next_packet_time: Instant,
}

impl TrafficShaper {
    pub fn new(profile: SecurityProfile) -> Self {
        Self {
            profile,
            next_packet_time: Instant::now(),
        }
    }

    /// 计算下一次发包前的等待时间，并返回建议的包大小
    /// 如果返回 size > 0，说明必须填充到该大小
    pub async fn wait_for_slot(&mut self) -> Option<usize> {
        match self.profile {
            SecurityProfile::Turbo => {
                // 不等待，不强制填充
                None
            },
            SecurityProfile::Balanced => {
                // 随机延迟 1ms - 10ms，破坏精确时序
                let jitter = rand::thread_rng().gen_range(1..10);
                tokio::time::sleep(Duration::from_millis(jitter)).await;
                // Balanced 模式通常不强制 CBR，但可以随机填充
                None 
            },
            SecurityProfile::Paranoid { interval_ms, target_size } => {
                // CBR 核心逻辑
                let interval = Duration::from_millis(interval_ms);
                
                // 如果当前时间已经晚于计划时间，立即发送并更新下一次时间
                // 如果当前时间早于计划时间，睡眠等待
                let now = Instant::now();
                if self.next_packet_time <= now {
                    self.next_packet_time = now + interval;
                } else {
                    sleep_until(self.next_packet_time).await;
                    self.next_packet_time += interval;
                }
                
                // 返回强制填充大小
                Some(target_size)
            }
        }
    }

    /// 判断当前是否处于静默期需要发送“心跳/填充包” (Cover Traffic)
    /// 在 Paranoid 模式下，即使没有应用数据，也必须发送 Padding 帧
    pub fn needs_cover_traffic(&self) -> bool {
        matches!(self.profile, SecurityProfile::Paranoid { .. })
    }
}
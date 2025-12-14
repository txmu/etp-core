// etp-core/src/anonymity/canary.rs

use std::sync::Arc;
use std::collections::HashSet;
use std::time::Duration;
use parking_lot::RwLock;
use log::{warn, error, info};
use anyhow::{Result, anyhow};
use rand::Rng;

use crate::plugin::{Interceptor, InterceptorContext, CapabilityProvider};
use crate::transport::injection::AclManager; // 需要引用 ACL 管理器进行封禁操作
use crate::NodeID;

/// 金丝雀防御拦截器
/// 负责检测非法的内部状态访问、特定陷阱流的触碰以及流量中的蜜罐标记
#[derive(Debug)]
pub struct CanaryInterceptor {
    /// 陷阱 Stream ID 列表
    /// 任何尝试向这些 ID 发送数据的行为都视为敌对探测
    trap_streams: RwLock<HashSet<u32>>,
    
    /// 蜜罐 Token (Honeytoken)
    /// 这是一个预埋在内存或配置中的假密钥/假字符串。
    /// 如果在解密后的流量中发现了这个字符串，说明内存已泄露且攻击者正在重放。
    honey_token: Vec<u8>,

    /// 全局 ACL 管理器引用 (用于执行封禁)
    acl: Arc<AclManager>,
}

impl CanaryInterceptor {
    pub fn new(acl: Arc<AclManager>) -> Self {
        let mut traps = HashSet::new();
        // 注册常见端口作为陷阱 Stream ID，诱捕习惯性扫描
        traps.insert(22);   // SSH
        traps.insert(80);   // HTTP
        traps.insert(443);  // HTTPS
        traps.insert(3306); // MySQL
        traps.insert(0);    // Reserved
        
        // 假定这是一个特定的假密钥，部署时应随机生成或从配置读取
        let honey_token = b"ETP_SECRET_ADMIN_KEY_DO_NOT_SHARE".to_vec();

        Self {
            trap_streams: RwLock::new(traps),
            honey_token,
            acl,
        }
    }

    /// 执行熔断操作
    async fn trigger_meltdown(&self, src_id: Option<NodeID>, reason: &str) {
        error!("🚨 SECURITY MELTDOWN TRIGGERED: {}", reason);
        
        // 1. ACL 永久拉黑 (如果知道 NodeID)
        if let Some(id) = src_id {
            self.acl.block_node(id);
            warn!("Canary: Node {:?} has been permanently blacklisted.", hex::encode(id));
        }

        // 2. Tarpit (时间陷阱)
        // 随机睡眠 1-5 秒，拖慢攻击者的自动化脚本扫描速度
        // 注意：由于 Interceptor 在 Session 锁内运行，这会阻塞该 Session 的处理，
        // 但不会阻塞整个 Engine (如果是多线程 Runtime)。
        let delay = rand::thread_rng().gen_range(1000..5000);
        warn!("Canary: Engaging Tarpit for {}ms...", delay);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

impl CapabilityProvider for CanaryInterceptor {
    fn capability_id(&self) -> String { "etp.security.canary.v1".into() }
}

impl Interceptor for CanaryInterceptor {
    fn on_ingress(&self, ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // 1. 检查是否触碰陷阱 Stream
        if self.trap_streams.read().contains(&ctx.stream_id) {
            // 这是一个严重的安全事件
            // 我们需要在这里执行异步操作，但在同步 trait 方法中需要 block_on 或者 spawn。
            // 既然我们要 Tarpit，阻塞当前线程是可接受的（甚至是目的）。
            
            // 为了获取当前 Session 的对端 ID，Context 可能不够用。
            // 目前 InterceptorContext 比较简单。我们假设攻击者是匿名的，或者由上层 Session 处理断开。
            // 在这里我们尽力拖延时间并报错。
            
            let _ = std::thread::sleep(Duration::from_secs(2)); // Sync Sleep for Tarpit
            
            error!("Canary: Intrusion detected on Trap Stream {}", ctx.stream_id);
            return Err(anyhow!("Connection Refused by Security Policy (Code: Canary)"));
        }

        // 2. 检查 Honeytoken (O(N) 搜索，生产环境可用 Aho-Corasick 优化)
        if data.windows(self.honey_token.len()).any(|window| window == self.honey_token) {
            let _ = std::thread::sleep(Duration::from_secs(5)); // Deeper Tarpit
            error!("Canary: HONEYTOKEN DETECTED! Memory content leakage confirmed.");
            // 这里应该触发更高级别的报警，例如发送 HTTP 请求给管理员 (Side Channel)
            return Err(anyhow!("Critical Security Fault"));
        }

        Ok(Some(data))
    }

    fn on_egress(&self, _ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // 出站 DLP (Data Loss Prevention) 检查
        // 防止我们自己因为 Bug 意外泄露 Honeytoken
        if data.windows(self.honey_token.len()).any(|window| window == self.honey_token) {
            error!("Canary: Prevented outbound leak of Honeytoken!");
            return Err(anyhow!("Outbound Security Block"));
        }
        Ok(Some(data))
    }
}
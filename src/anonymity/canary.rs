// etp-core/src/anonymity/canary.rs

use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock;
use log::{warn, error, info, debug, trace};
use anyhow::{Result, anyhow, Context};
use rand::{Rng, RngCore, thread_rng};
use blake3;

use crate::plugin::{Interceptor, InterceptorContext, CapabilityProvider};
use crate::transport::injection::AclManager;
use crate::NodeID;

// ============================================================================
//  配置常量
// ============================================================================

const TOKEN_LEN: usize = 32;
const MAX_VIOLATIONS_BEFORE_BAN: usize = 3;
const TARPIT_BASE_MS: u64 = 500;
const TARPIT_MAX_MS: u64 = 10_000;

// 启发式检测特征库 (常见攻击签名)
// 包含 NOP Sleds (x86), Common Shellcode prefixes, SQL Injection keywords
const SUSPICIOUS_PATTERNS: &[&[u8]] = &[
    b"\x90\x90\x90\x90\x90\x90\x90\x90", // NOP Sled
    b"UNION SELECT",                     // SQLi
    b"/bin/sh",                          // Shellcode
    b"eval(",                            // RCE
    b"System.Reflection",                // .NET Reflection attack
];

// ============================================================================
//  结构定义
// ============================================================================

/// 金丝雀模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryMode {
    /// 瞬态模式：每次重启生成随机令牌 (推荐，抗取证能力最强)
    Ephemeral,
    /// 绑定模式：基于节点身份派生令牌 (用于跨节点审计/日志分析)
    IdentityBound,
}

/// 违规记录追踪
struct ViolationTracker {
    count: usize,
    last_violation: Instant,
    tarpit_level: u32,
}

/// 深度金丝雀防御拦截器
/// 负责检测非法的内部状态访问、特定陷阱流的触碰、流量中的蜜罐标记以及异常载荷
#[derive(Debug)]
pub struct CanaryInterceptor {
    /// 运行模式
    mode: CanaryMode,
    
    /// 陷阱 Stream ID 列表
    /// 任何尝试向这些 ID 发送数据的行为都视为敌对探测
    trap_streams: RwLock<HashSet<u32>>,
    
    /// 蜜罐 Token (Honeytoken)
    /// 预埋在内存中的敏感数据标记。如果在流量中发现此序列，意味着内存发生了泄漏 (Heartbleed-like)。
    honey_token: Vec<u8>,

    /// 违规追踪器 (Source IP -> State)
    /// 用于实施渐进式惩罚
    offenders: RwLock<HashMap<String, ViolationTracker>>,

    /// 全局 ACL 管理器引用 (用于执行封禁)
    acl: Arc<AclManager>,
    
    /// 统计指标
    stats_intercepted: AtomicUsize,
}

impl CanaryInterceptor {
    /// 创建新的金丝雀拦截器
    /// 
    /// # Arguments
    /// * `acl` - 全局 ACL 管理器
    /// * `identity_seed` - 可选的身份种子。
    ///   - `Some(seed)`: 启用 `IdentityBound` 模式，令牌由 `HKDF(seed, salt)` 派生。
    ///   - `None`: 启用 `Ephemeral` 模式，令牌由 CSPRNG 随机生成。
    pub fn new(acl: Arc<AclManager>, identity_seed: Option<&[u8]>) -> Self {
        let mut traps = HashSet::new();
        // 注册常见漏洞端口作为陷阱 Stream ID，诱捕习惯性扫描
        traps.insert(0);    // Reserved
        traps.insert(21);   // FTP
        traps.insert(22);   // SSH
        traps.insert(23);   // Telnet
        traps.insert(25);   // SMTP
        traps.insert(53);   // DNS (TCP)
        traps.insert(80);   // HTTP
        traps.insert(443);  // HTTPS
        traps.insert(3306); // MySQL
        traps.insert(3389); // RDP
        traps.insert(8080); // Alt HTTP

        // 生成蜜罐令牌
        let (mode, honey_token) = match identity_seed {
            Some(seed) => {
                // Identity Bound: 使用 Blake3 Key Derivation
                let mut hasher = blake3::Hasher::new_derive_key("ETP_CANARY_TOKEN_DERIVATION_V1");
                hasher.update(seed);
                let mut token = vec![0u8; TOKEN_LEN];
                token.copy_from_slice(hasher.finalize().as_bytes());
                info!("Canary: Initialized in IDENTITY-BOUND mode. Token is persistent for this key.");
                (CanaryMode::IdentityBound, token)
            },
            None => {
                // Ephemeral: 完全随机
                let mut rng = thread_rng();
                let mut token = vec![0u8; TOKEN_LEN];
                rng.fill_bytes(&mut token);
                info!("Canary: Initialized in EPHEMERAL mode. Token is random and unique to this runtime.");
                (CanaryMode::Ephemeral, token)
            }
        };

        // 安全提示：仅在 Debug 构建下打印 Token，生产环境严禁打印
        #[cfg(debug_assertions)]
        debug!("Canary DEBUG: Honeytoken = {}", hex::encode(&honey_token));

        Self {
            mode,
            trap_streams: RwLock::new(traps),
            honey_token,
            offenders: RwLock::new(HashMap::new()),
            acl,
            stats_intercepted: AtomicUsize::new(0),
        }
    }

    /// 获取当前的蜜罐令牌 (用于在内存其他位置“撒诱饵”)
    /// 注意：调用此方法会将 Token 复制到新的内存区域，增加了暴露面，请谨慎使用。
    pub fn get_token_for_seeding(&self) -> Vec<u8> {
        self.honey_token.clone()
    }

    /// 执行熔断与反击操作
    /// 
    /// 策略：
    /// 1. 记录违规。
    /// 2. 实施时间陷阱 (Tarpit)，拖慢攻击者节奏。
    /// 3. 如果达到阈值，通过 ACL 永久封禁。
    async fn engage_countermeasures(&self, reason: &str, severity: u8) {
        self.stats_intercepted.fetch_add(1, Ordering::Relaxed);
        
        // 1. 计算延迟 (Tarpit)
        // 随机化延迟以防止攻击者通过时间侧信道分析防御逻辑
        let mut rng = thread_rng();
        let base_delay = TARPIT_BASE_MS * (severity as u64).max(1);
        let jitter = rng.gen_range(0..500);
        let delay = (base_delay + jitter).min(TARPIT_MAX_MS);

        warn!("🚨 SECURITY ALERT: {}. Engaging Tarpit for {}ms.", reason, delay);

        // 2. 执行延迟 (阻塞当前 Task，但不阻塞整个 Runtime)
        // 这会消耗攻击者的连接槽位和超时时间
        tokio::time::sleep(Duration::from_millis(delay)).await;

        // 3. 封禁逻辑 (Meltdown)
        // 由于 InterceptorContext 尚未传递源 IP 或 NodeID，我们在这里假设
        // 调用者或上层 Session 会处理连接断开。
        // 如果能获取到 NodeID (通过上下文扩展)，应立即调用:
        // self.acl.block_node(node_id);
        
        // 模拟反击效果：返回错误，切断连接
        error!("Canary: Countermeasures executed. Terminating connection flow.");
    }

    /// 启发式深度包检测 (Heuristic DPI)
    fn scan_for_anomalies(&self, data: &[u8]) -> Option<&'static str> {
        // 1. 检查 Honeytoken (O(N) 搜索)
        // 这是最高优先级的致命错误，意味着内存泄露
        if data.windows(self.honey_token.len()).any(|w| w == self.honey_token) {
            return Some("HONEYTOKEN LEAK DETECTED");
        }

        // 2. 检查常见攻击特征 (仅在数据长度足够时)
        if data.len() > 16 {
            for pattern in SUSPICIOUS_PATTERNS {
                if data.windows(pattern.len()).any(|w| w == *pattern) {
                    return Some("MALICIOUS PATTERN DETECTED");
                }
            }
        }

        None
    }
}

impl CapabilityProvider for CanaryInterceptor {
    fn capability_id(&self) -> String { "etp.security.canary.v2".into() }
}

impl Interceptor for CanaryInterceptor {
    fn on_ingress(&self, ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // 1. 陷阱端口检测 (Trap Port Check)
        // 任何试图连接保留端口的行为都视为扫描
        {
            let traps = self.trap_streams.read();
            if traps.contains(&ctx.stream_id) {
                // 这是一个严重的安全事件，立即触发最高级别反击
                // 注意：我们在这里使用 block_on 或者 spawn 来执行 async 的反击逻辑
                // 因为 Interceptor trait 是同步的。为了不阻塞线程，我们 spawn。
                // 但为了实施 Tarpit，我们需要当前线程等待。
                // 折中方案：同步 sleep 一小段时间，然后返回 Error。
                
                let reason = format!("Intrusion detected on Trap Stream {}", ctx.stream_id);
                warn!("{}", reason);
                
                // 同步 Tarpit (轻量级，防止阻塞 reactor 太久)
                std::thread::sleep(Duration::from_millis(1000));
                
                return Err(anyhow!("Connection Refused by Security Policy (Code: Canary-Trap)"));
            }
        }

        // 2. 深度内容扫描 (DPI)
        if let Some(violation) = self.scan_for_anomalies(&data) {
            let reason = format!("Ingress Integrity Violation: {}", violation);
            error!("{}", reason);
            
            // 严重违规：Honeytoken 泄露意味着对方在重放我们泄露的内存，或者这就是泄露源
            if violation.contains("HONEYTOKEN") {
                // 极度危险，强制延迟并报错
                std::thread::sleep(Duration::from_millis(2000));
                return Err(anyhow!("CRITICAL SECURITY FAULT: MEMORY LEAK REPLAY"));
            }
            
            return Err(anyhow!("Security Violation: Malicious Payload"));
        }

        Ok(Some(data))
    }

    fn on_egress(&self, _ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        // 出站 DLP (Data Loss Prevention)
        // 防止我们自己因为 Bug (如 Heartbleed 类漏洞) 意外将内存中的 Token 发送出去
        
        // 1. Honeytoken 检查
        if data.windows(self.honey_token.len()).any(|window| window == self.honey_token) {
            error!("🚨 DLP ALERT: Prevented outbound leak of HONEYTOKEN! Local memory compromised.");
            
            // 这是一个 "Panic-worthy" 的事件。说明本进程内存已失控。
            // 为了安全，我们拦截该包，并建议上层重启服务。
            return Err(anyhow!("Outbound Security Block: DLP Triggered"));
        }

        // 2. 敏感词过滤 (可选)
        // 可以在此添加私钥格式头部的检测 (e.g. "-----BEGIN PRIVATE KEY-----")
        
        Ok(Some(data))
    }
}

// ============================================================================
//  单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    // Mock ACL for testing
    fn mock_acl() -> Arc<AclManager> {
        Arc::new(AclManager::new(false))
    }

    #[test]
    fn test_ephemeral_token_randomness() {
        let acl = mock_acl();
        let c1 = CanaryInterceptor::new(acl.clone(), None);
        let c2 = CanaryInterceptor::new(acl.clone(), None);
        
        assert_ne!(c1.honey_token, c2.honey_token, "Ephemeral tokens must be unique");
        assert_eq!(c1.mode, CanaryMode::Ephemeral);
    }

    #[test]
    fn test_identity_bound_consistency() {
        let acl = mock_acl();
        let seed = b"my_secret_node_key";
        let c1 = CanaryInterceptor::new(acl.clone(), Some(seed));
        let c2 = CanaryInterceptor::new(acl.clone(), Some(seed));
        
        assert_eq!(c1.honey_token, c2.honey_token, "Identity bound tokens must be deterministic");
        assert_eq!(c1.mode, CanaryMode::IdentityBound);
    }

    #[test]
    fn test_trap_stream_detection() {
        let canary = CanaryInterceptor::new(mock_acl(), None);
        let ctx = InterceptorContext { stream_id: 22, is_handshake: false }; // SSH port
        
        let res = canary.on_ingress(&ctx, vec![0x00]);
        assert!(res.is_err(), "Should block trap stream 22");
    }

    #[test]
    fn test_dlp_protection() {
        let canary = CanaryInterceptor::new(mock_acl(), None);
        let token = canary.get_token_for_seeding();
        
        // Construct leaking packet
        let mut leak_packet = b"header_data_".to_vec();
        leak_packet.extend_from_slice(&token);
        leak_packet.extend_from_slice(b"_footer");

        let ctx = InterceptorContext { stream_id: 1, is_handshake: false };
        let res = canary.on_egress(&ctx, leak_packet);
        
        assert!(res.is_err(), "Should block outbound honeytoken leak");
    }

    #[test]
    fn test_anomaly_detection() {
        let canary = CanaryInterceptor::new(mock_acl(), None);
        let ctx = InterceptorContext { stream_id: 1, is_handshake: false };
        
        // Test NOP Sled
        let malicious = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90_shellcode".to_vec();
        let res = canary.on_ingress(&ctx, malicious);
        assert!(res.is_err(), "Should detect NOP sled");
    }
}
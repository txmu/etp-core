// etp-core/examples/deep_features_test.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use log::{info, warn, error};
use env_logger::Env;
use anyhow::Result;
use colored::*;

use etp_core::network::node::{EtpEngine, NodeConfig, DeepAnonymityConfig, DeepSecurityConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::{PluginRegistry, CapabilityProvider, Agent, AgentContext};
use etp_core::plugin::flavors::control::ControlCategory;
use etp_core::transport::reliability::MultiplexingMode;
use etp_core::transport::shaper::SecurityProfile;

// ============================================================================
//  1. 自定义智能体 (The Autonomous Agent)
// ============================================================================

#[derive(Debug)]
struct NetworkHealthAgent;

impl CapabilityProvider for NetworkHealthAgent {
    fn capability_id(&self) -> String { "etp.agent.health.v1".into() }
}

#[async_trait::async_trait]
impl Agent for NetworkHealthAgent {
    async fn run(&self, ctx: AgentContext) {
        let node_short = hex::encode(&ctx.node_id[0..4]);
        info!("[Agent] 🤖 Unit {} online. Autonomously monitoring threat levels...", node_short);
        
        // 模拟智能体的主动行为
        loop {
            sleep(Duration::from_secs(5)).await;
            // 在真实场景中，这里会读取 Metrics 或系统负载
            // 这里我们模拟 Agent 发现环境安全，并打印日志
            info!("[Agent] 🛡️  Sector Clear. Maintaining radio silence protocols.");
        }
    }
}

// ============================================================================
//  2. 辅助函数：启动服务端 (Command Center)
// ============================================================================

async fn spawn_server(addr: &str) -> (SocketAddr, Vec<u8>) {
    let keys = KeyPair::generate();
    let pub_key = keys.public.clone();
    
    let config = NodeConfig {
        bind_addr: addr.to_string(),
        keypair: keys,
        // 服务端使用多流模式以处理并发
        multiplexing_mode: MultiplexingMode::ParallelMulti,
        profile: SecurityProfile::Turbo,
        ..NodeConfig::default()
    };

    let registry = Arc::new(PluginRegistry::new());
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));
    // 注册 ControlNexus 以便服务端能解析侧信道指令 (隐式包含在 Engine 逻辑中，但 Flavor 需注册)
    // 注意：在最新 node.rs 中，Engine 会桥接 Stream 0 到 Flavor。
    // 为了接收指令，Server 需要注册一个处理 Stream 0 的 Flavor，或者使用 Router。
    // 这里为了简化，假设 Server 的 Default Flavor 能打印日志即可 (StandardFlavor 忽略数据)。
    
    let (engine, _, _) = EtpEngine::new(config, registry).await.unwrap();
    
    tokio::spawn(async move {
        engine.run().await.unwrap();
    });

    sleep(Duration::from_millis(100)).await;
    ("127.0.0.1:9000".parse().unwrap(), pub_key)
}

// ============================================================================
//  3. 主程序：客户端 (Silent Observer)
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    println!("\n{}", "========================================================".blue().bold());
    println!("{}", "   ETP Core: Deep Anonymity & Security Test".blue().bold());
    println!("{}", "========================================================".blue().bold());

    // 1. 启动服务端
    let (server_addr, server_pub) = spawn_server("127.0.0.1:9000").await;
    info!("Command Center running at {}", server_addr);

    // 2. 配置客户端：开启所有黑科技
    let client_keys = KeyPair::generate();
    
    // --- 深度配置 ---
    let anonymity_conf = DeepAnonymityConfig {
        enable_cover_traffic: true,       // <--- 开启掩护流量
        target_min_bitrate: 50 * 1024,    // <--- 强制维持 50KB/s 的底噪
        jitter_ms_range: (5, 20),         // <--- 强制抖动
    };

    let security_conf = DeepSecurityConfig {
        strict_rekey_interval_secs: 3,    // <--- 极端的 3秒密钥轮换 (测试用)
        handshake_zero_tolerance: true,   // <--- 零容忍
        allow_dynamic_side_channels: true,
    };

    let mut config = NodeConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        keypair: client_keys,
        multiplexing_mode: MultiplexingMode::StrictSingle, // 伪装 TCP
        profile: SecurityProfile::Paranoid { // 偏执模式
            interval_ms: 50,
            target_size: 1000,
        },
        anonymity: anonymity_conf,
        security: security_conf,
        ..NodeConfig::default()
    };

    // 3. 注册插件与智能体
    let registry = Arc::new(PluginRegistry::new());
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));
    
    // 注入自主智能体
    registry.register_agent(Arc::new(NetworkHealthAgent));

    // 4. 启动客户端引擎
    let (engine, handle, _) = EtpEngine::new(config, registry).await?;
    
    tokio::spawn(async move {
        engine.run().await.unwrap();
    });

    sleep(Duration::from_millis(500)).await;

    // 5. 建立连接
    info!("\n[{}] Connecting to Server...", "INIT".yellow());
    handle.connect(server_addr, server_pub).await?;
    
    // 等待握手完成
    sleep(Duration::from_secs(1)).await;

    // 6. 测试阶段 A: 观察掩护流量 (Cover Traffic)
    println!("\n[{}] Phase A: Observing Cover Traffic...", "TEST".purple());
    println!("   Main thread is sleeping. No user data is being sent.");
    println!("   Expect 'Cover' metrics to increase due to 'target_min_bitrate'.");
    
    let stats_before = handle.get_stats().await?;
    sleep(Duration::from_secs(5)).await; // 睡眠 5 秒
    let stats_after = handle.get_stats().await?;
    
    info!("Stats Before: {}", stats_before);
    info!("Stats After:  {}", stats_after);
    
    // 验证逻辑：即便我们没发包，流量统计也应该增加
    // 注意：get_stats 返回字符串，这里人工观察日志即可，或者解析字符串
    if stats_after != stats_before {
        println!("{}", "[PASS] Cover Traffic Engine is active. Background noise generated.".gre
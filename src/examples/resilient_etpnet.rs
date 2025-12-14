// etp-core/examples/resilient_etpnet.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use log::{info, error, warn, debug};
use env_logger::Env;
use anyhow::{Result, anyhow, Context};
use rand::Rng;

// ETP Core Imports
use etp_core::network::node::{EtpEngine, NodeConfig, DeepSecurityConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::{PluginRegistry, CapabilityProvider, Dialect};
use etp_core::plugin::flavors::composite::CompositeFlavor;
use etp_core::plugin::flavors::chat::ChatFlavor;
use etp_core::transport::reliability::MultiplexingMode;
use etp_core::transport::shaper::SecurityProfile;

// Config & Extensions
use etp_core::extensions::{ConfigManager, DynamicConfig};
use etp_core::extensions::config::EnsProvider;

// Conditional Import for ENS Gateway Sidecar
#[cfg(feature = "ens-gateway")]
use etp_core::extensions::{EnsGatewayConfig, run_ens_gateway};

// ============================================================================
//  1. 自定义对抗型方言 (Mimic TLS 1.3)
// ============================================================================

#[derive(Debug)]
struct MimicTlsDialect;

impl CapabilityProvider for MimicTlsDialect {
    fn capability_id(&self) -> String { "etp.dialect.mimic.tls.v1".into() }
}

impl Dialect for MimicTlsDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        // 模拟 TLS Application Data (0x17)
        // Header: [Type: 0x17] [Ver: 0x0303] [Len: u16]
        let len = (payload.len() as u16).to_be_bytes();
        let mut header = Vec::with_capacity(5);
        header.push(0x17);       // Content Type: Application Data
        header.push(0x03);       // Version Major
        header.push(0x03);       // Version Minor (TLS 1.2 legacy mapping for 1.3)
        header.extend_from_slice(&len);

        // 原地修改：Header + Payload
        let mut new_packet = Vec::with_capacity(5 + payload.len());
        new_packet.extend(header);
        new_packet.append(payload);
        *payload = new_packet;
    }

    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        // 校验 TLS 头部特征
        if data.len() < 5 {
            return Err(anyhow!("Packet too short for TLS header"));
        }
        if data[0] != 0x17 || data[1] != 0x03 {
            return Err(anyhow!("Invalid TLS Record Header"));
        }
        // 提取 Payload
        Ok(data[5..].to_vec())
    }

    fn probe(&self, data: &[u8]) -> bool {
        // 快速特征匹配
        data.len() >= 5 && data[0] == 0x17 && data[1] == 0x03
    }
}

// ============================================================================
//  2. 辅助函数：环境准备
// ============================================================================

fn get_trust_anchor() -> String {
    // 优先从环境变量读取生产环境的公钥
    match std::env::var("ETP_ADMIN_PUBKEY") {
        Ok(key) => {
            info!("Trust Anchor loaded from environment variable.");
            key
        },
        Err(_) => {
            // 如果未配置，生成一个临时的有效公钥以保证程序能跑通 (演示模式)
            warn!("ETP_ADMIN_PUBKEY not set. Generating temporary trust anchor for demonstration.");
            let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            hex::encode(signing_key.verifying_key())
        }
    }
}

fn get_rpc_endpoint() -> String {
    std::env::var("ETH_RPC_URL")
        .unwrap_or_else(|_| "https://eth-mainnet.public.blastapi.io".to_string())
}

// ============================================================================
//  3. 主程序入口
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 初始化日志系统
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("=== ETP Resilient Node (Production) ===");

    // 2. 启动 Sidecar 服务 (ENS Gateway)
    // 这是一个独立的微服务，负责将 HTTP 协议转换为 Ethereum JSON-RPC 协议
    let gateway_port = 3050;
    let gateway_url = format!("http://127.0.0.1:{}", gateway_port);

    #[cfg(feature = "ens-gateway")]
    {
        let ens_conf = EnsGatewayConfig {
            bind_addr: format!("127.0.0.1:{}", gateway_port).parse().context("Invalid Gateway Bind Address")?,
            eth_rpc_url: get_rpc_endpoint(),
            timeout_secs: 15,
        };

        info!("Sidecar: Spawning ENS Gateway on {}...", gateway_port);
        // 使用 tokio::spawn 运行 Sidecar，使其不阻塞主线程
        tokio::spawn(async move {
            run_ens_gateway(ens_conf).await;
        });

        // 等待 Sidecar 端口就绪 (简单的自旋检查)
        let start = std::time::Instant::now();
        loop {
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", gateway_port)).is_ok() {
                debug!("Sidecar is ready.");
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                warn!("Sidecar startup timed out, proceeding anyway (requests might fail).");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(not(feature = "ens-gateway"))]
    {
        warn!("Feature 'ens-gateway' is disabled. Ensure an external gateway is running at {}", gateway_url);
    }

    // 3. 初始化配置管理器
    // 加载信任锚点 (Admin Public Key) 用于验证远程配置签名
    let trust_anchor_hex = get_trust_anchor();
    let mut config_mgr = ConfigManager::new(serde_json::json!({}), Some(trust_anchor_hex))
        .context("Failed to initialize ConfigManager")?;

    // 注册标准配置提供者
    config_mgr.register_defaults();

    // 注册 ENS 提供者，指向上一步启动的本地 Gateway
    // 该 Provider 负责处理 ens:// 协议，通过 HTTP 请求本地网关
    config_mgr.register_provider(EnsProvider {
        rpc_url: gateway_url,
        client: reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
    });

    // 4. 远程配置加载
    // 逻辑流: ens://resilient.etp -> Gateway -> (Resolve) -> ipfs://QmHash -> IpfsProvider -> (Verify Sig) -> Config
    let config_uri = std::env::var("ETP_CONFIG_URI").unwrap_or_else(|_| "ens://resilient-node.etp".to_string());
    info!("Bootstrapping: Loading configuration from {}", config_uri);

    if let Err(e) = config_mgr.load_from_uri(&config_uri) {
        // 在生产环境中，配置加载失败通常意味着无法安全启动。
        // 但为了保证节点的可用性，这里降级使用默认配置并发出告警。
        error!("CRITICAL: Failed to load remote config: {}. Using hardcoded defaults.", e);
    } else {
        info!("Remote configuration loaded and verified successfully.");
    }

    // 获取最新的动态配置快照
    let dyn_cfg = config_mgr.get_config();

    // 5. 节点参数组装
    // 优先使用动态配置中的值，缺省使用安全默认值
    let bind_port = dyn_cfg.get::<u16>("network.port").unwrap_or(8443);
    let rekey_interval = dyn_cfg.get::<u64>("security.rekey_interval").unwrap_or(600);
    let cover_traffic = dyn_cfg.get::<bool>("anonymity.enable_cover_traffic").unwrap_or(true);

    let node_keys = KeyPair::generate();
    info!("Node Identity Generated: {}", hex::encode(blake3::hash(&node_keys.public).as_bytes()));

    let config = NodeConfig {
        bind_addr: format!("0.0.0.0:{}", bind_port),
        keypair: node_keys.clone(),
        
        // 抗干扰核心配置
        multiplexing_mode: MultiplexingMode::ParallelMulti, // 多流并发，避免队头阻塞
        profile: SecurityProfile::Balanced,                 // 平衡延迟与特征隐藏
        
        // 深度安全配置
        security: DeepSecurityConfig {
            strict_rekey_interval_secs: rekey_interval,
            handshake_zero_tolerance: true,                 // 零容忍：非法握手直接拉黑 IP
            allow_dynamic_side_channels: true,
        },
        
        // 深度匿名配置
        anonymity: etp_core::network::node::DeepAnonymityConfig {
            enable_cover_traffic: cover_traffic,
            target_min_bitrate: 10 * 1024, // 10KB/s 底噪
            jitter_ms_range: (5, 25),      // 随机抖动
        },

        default_dialect: "etp.dialect.mimic.tls.v1".to_string(),
        default_flavor: "etp.flavor.composite.v1".to_string(),
        
        ..NodeConfig::default()
    };

    // 6. 插件体系组装
    let registry = Arc::new(PluginRegistry::new());
    
    // 注册拟态方言
    registry.register_dialect(Arc::new(MimicTlsDialect));

    // 组装业务层 (Chat + DHT + Composite)
    let (chat_tx, _chat_rx) = mpsc::channel(2048);
    let (dht_tx, _dht_rx) = mpsc::channel(1024);
    
    let key_bytes: [u8; 32] = node_keys.private.as_slice().try_into()
        .map_err(|_| anyhow!("Invalid Key Length"))?;

    // 初始化聊天模块 (持久化存储)
    let chat_flavor = ChatFlavor::new(
        "resilient_chat.db", 
        &key_bytes, 
        &key_bytes, 
        dht_tx, 
        chat_tx
    ).context("Failed to initialize ChatFlavor")?;

    // 初始化复合分流器
    let composite = Arc::new(CompositeFlavor::new(chat_flavor.clone()));
    
    // 绑定 Stream ID 2 为聊天专用流
    composite.bind_stream(2, chat_flavor.clone());
    
    // 注册入口 Flavor
    registry.register_flavor(composite);

    // 7. 启动内核引擎
    info!("Initializing ETP Kernel...");
    let (engine, _handle, _) = EtpEngine::new(config, registry).await
        .context("Failed to start ETP Engine")?;

    info!("ETP Resilient Node is running.");
    info!("Listening Port: {}", bind_port);
    info!("Features Active: ENS-Config, MimicTLS, ParallelMulti, CoverTraffic");

    // 8. 阻塞运行
    engine.run().await?;

    Ok(())
}
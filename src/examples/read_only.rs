// etp-core/examples/read_only.rs

#![cfg(feature = "persistence")] // 这仅仅是因为该示例演示了一个只读网关，使用了 TnsFlavor 来解析域名。不是要存储什么。

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use anyhow::Result;
use log::{info, warn};
use env_logger::Env;
use clap::Parser;

use etp_core::network::node::{EtpEngine, NodeConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::PluginRegistry;
use etp_core::plugin::flavors::{
    tns::TnsFlavor,
    fileshare::FileShareFlavor,
    http_gateway::HttpGatewayFlavor,
};

#[derive(Parser)]
struct Cli {
    /// 引导节点地址 (例如 remote_etpnet 的地址)
    #[arg(long)]
    bootstrap: String,

    /// 引导节点公钥 (Hex)
    #[arg(long)]
    bootstrap_key: String,

    /// HTTP 网关监听端口 (默认 8080)
    #[arg(long, default_value_t = 8080)]
    http_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();

    info!("Starting ETP Read-Only Gateway...");

    // 1. 临时身份 (只读节点不需要持久化身份)
    let keys = KeyPair::generate();
    let key_bytes: [u8; 32] = keys.private.as_slice().try_into()?;
    let data_dir = PathBuf::from("./etp_gateway_cache");
    std::fs::create_dir_all(&data_dir)?;

    // 2. 注册表
    let registry = Arc::new(PluginRegistry::new());
    // 支持所有方言以便连接任何类型的种子节点
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));
    registry.register_dialect(Arc::new(etp_core::plugin::FakeTlsDialect));

    let (net_tx, mut net_rx) = mpsc::channel(1024);
    let (dht_tx, mut dht_rx) = mpsc::channel(1024);

    // 3. 初始化核心 Flavors (用于获取数据)
    // TNS 用于解析 .etp 域名
    let tns = TnsFlavor::new(
        data_dir.join("tns_cache.db").to_str().unwrap(),
        &key_bytes, dht_tx.clone(), net_tx.clone()
    )?;
    
    // FileShare 用于下载内容
    let fs = FileShareFlavor::new(
        data_dir.join("fs_cache").to_str().unwrap(),
        net_tx.clone()
    )?;

    // 4. 初始化 Gateway Flavor
    // 注意：HttpGatewayFlavor 会启动一个 TCP Listener 绑定到 0.0.0.0 (在源码中可配置)
    // 这里我们传入 TNS 和 FS 的引用，Gateway 会调用它们的方法来响应 HTTP 请求
    let _gateway = HttpGatewayFlavor::new(cli.http_port, tns.clone(), fs.clone());

    // 注册这些 Flavor 以便处理回包
    registry.register_flavor(tns);
    registry.register_flavor(fs);
    // Gateway 本身也是 Flavor (为了 ID 注册)，但不处理流数据
    registry.register_flavor(_gateway);

    // 5. 配置节点
    let bootstrap_addr: SocketAddr = cli.bootstrap.parse()?;
    let bootstrap_key_bytes = hex::decode(&cli.bootstrap_key)?;

    let config = NodeConfig {
        bind_addr: "0.0.0.0:0".to_string(), // 随机端口
        keypair: keys,
        bootstrap_peers: vec![bootstrap_addr], // 重要：连接到生态网络
        ..NodeConfig::default()
    };

    let (engine, handle, _) = EtpEngine::new(config, registry).await?;

    // 6. 辅助任务
    let h_net = handle.clone();
    tokio::spawn(async move {
        while let Some((target, data)) = net_rx.recv().await {
            let _ = h_net.send_data(target, data).await;
        }
    });

    let h_dht = handle.clone();
    tokio::spawn(async move {
        while let Some(req) = dht_rx.recv().await {
            // Gateway 通常不存储数据，但可能需要转发查询
            // 这里作为 Client，主要是发起 FindNode/GetValue
            let _ = h_dht.dht_store(req.key, req.value, req.ttl).await;
        }
    });

    // 7. 自动连接引导节点
    info!("Connecting to bootstrap node {}...", bootstrap_addr);
    handle.connect(bootstrap_addr, bootstrap_key_bytes).await?;

    info!("Gateway is Ready!");
    info!("Access TNS via: http://<YOUR_IP>:{}/tns/<name.etp>", cli.http_port);
    info!("This node is READ-ONLY for HTTP clients, but participates in ETP network.");

    engine.run().await?;
    Ok(())
}
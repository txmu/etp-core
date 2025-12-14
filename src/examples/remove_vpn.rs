// etp-core/examples/remote_vpn.rs

use std::sync::Arc;
use std::path::Path;
use std::fs;
use tokio::sync::mpsc;
use log::{info, warn, error};
use env_logger::Env;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};

use etp_core::network::node::{EtpEngine, NodeConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::PluginRegistry;
use etp_core::plugin::flavors::vpn::{VpnFlavor, VpnConfig};
use etp_core::transport::reliability::MultiplexingMode;
use etp_core::transport::shaper::SecurityProfile;

// --- 身份持久化逻辑 ---
#[derive(Serialize, Deserialize)]
struct NodeIdentity {
    public_hex: String,
    private_hex: String,
    node_id: String,
}

fn load_or_save_identity(path: &str) -> Result<KeyPair> {
    let path = Path::new(path);
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let id: NodeIdentity = serde_json::from_str(&content)?;
        info!("Loaded Identity: {}", id.node_id);
        Ok(KeyPair {
            public: hex::decode(id.public_hex)?,
            private: hex::decode(id.private_hex)?,
        })
    } else {
        info!("Generating new Identity...");
        let keys = KeyPair::generate();
        let id_struct = NodeIdentity {
            public_hex: hex::encode(&keys.public),
            private_hex: hex::encode(&keys.private),
            node_id: hex::encode(blake3::hash(&keys.public).as_bytes()),
        };
        fs::write(path, serde_json::to_string_pretty(&id_struct)?)?;
        info!("Created new Identity: {}", id_struct.node_id);
        Ok(keys)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 初始化
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("=== ETP Remote VPN Exit Node ===");

    // 2. 加载身份
    let identity_path = "./vpn_identity.json";
    let server_keys = load_or_save_identity(identity_path)?;
    info!("Server Public Key: {}", hex::encode(&server_keys.public));

    // 3. 插件注册
    let registry = Arc::new(PluginRegistry::new());
    
    // 注册方言 (FakeTLS 用于伪装。注意，它并不可靠，没有完整的协议栈。建议自行切换)
    registry.register_dialect(Arc::new(etp_core::plugin::FakeTlsDialect));
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));

    // 4. 配置 VPN Flavor
    let (vpn_tx, mut vpn_rx) = mpsc::channel(4096);
    
    // 配置 VPN 网段与拟态
    let vpn_config = VpnConfig {
        virtual_ip: "10.8.0.1".parse().unwrap(),
        virtual_mask: "255.255.255.0".parse().unwrap(),
        mtu: 1420,
        morphing_enabled: true, // 开启流量整形，伪装成视频流
    };

    let vpn_flavor = VpnFlavor::new(vpn_tx, Some(vpn_config));
    registry.register_flavor(vpn_flavor.clone());

    // 5. 节点配置
    let config = NodeConfig {
        bind_addr: "0.0.0.0:443".to_string(), // 监听 443
        keypair: server_keys,
        
        // 关键：单流模式配合 FakeTLS，最大程度模拟 HTTPS TCP 连接
        multiplexing_mode: MultiplexingMode::StrictSingle,
        
        // 关键：平衡模式，引入随机抖动抗时序分析
        profile: SecurityProfile::Balanced, 
        
        default_dialect: "etp.dialect.tls.v1".to_string(),
        default_flavor: "etp.flavor.vpn.v1".to_string(),
        
        ..NodeConfig::default()
    };

    // 6. 启动
    let (engine, handle, _) = EtpEngine::new(config, registry).await?;

    // 7. VPN 回路桥接 (Explicit Stream 1)
    let h_bridge = handle.clone();
    tokio::spawn(async move {
        while let Some((target, data)) = vpn_rx.recv().await {
            // 虽然 StrictSingle 模式下底层会合并所有流，
            // 但显式指定 Stream 1 是良好的编程习惯，也是协议约定的默认 VPN 流。
            if let Err(e) = h_bridge.send_stream(target, 1, data).await {
                warn!("VPN bridge error: {}", e);
            }
        }
    });

    // 8. 运行引擎
    info!("VPN Node Running. Waiting for connections...");
    engine.run().await?;

    Ok(())
}
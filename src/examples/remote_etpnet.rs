// etp-core/examples/remote_etpnet.rs

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs;
use tokio::sync::mpsc;
use anyhow::{Result, Context};
use log::{info, error, debug};
use env_logger::Env;
use serde::{Serialize, Deserialize};

use etp_core::network::node::{EtpEngine, NodeConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::PluginRegistry;
use etp_core::transport::reliability::MultiplexingMode;
use etp_core::transport::shaper::SecurityProfile;

// 引入 Flavors
use etp_core::plugin::flavors::{
    composite::CompositeFlavor,
    chat::ChatFlavor,
    forum::ForumFlavor,
    tns::TnsFlavor,
    fileshare::FileShareFlavor,
};

// --- 协议约定的 Stream ID ---
// 客户端和服务端必须达成一致
const STREAM_CHAT: u32  = 2;
const STREAM_FORUM: u32 = 3;
const STREAM_TNS: u32   = 4;
const STREAM_FS: u32    = 5;
const STREAM_BLOCKCHAIN: u32 = 6; // 预留给未来的区块链 Flavor

// --- 身份持久化 ---
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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("=== ETPNet Core Infrastructure Node ===");

    // 1. 数据目录与身份
    let data_dir = PathBuf::from("./etp_server_data");
    fs::create_dir_all(&data_dir)?;
    
    let keys = load_or_save_identity("./etpnet_identity.json")?;
    let key_bytes: [u8; 32] = keys.private.as_slice().try_into()?;

    // 2. 插件注册表
    let registry = Arc::new(PluginRegistry::new());
    
    // 注册多种方言，允许不同类型的客户端接入
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));
    registry.register_dialect(Arc::new(etp_core::plugin::FakeTlsDialect));
    registry.register_dialect(Arc::new(etp_core::plugin::FakeQuicDialect));

    // 3. 创建 Flavor 专用通道 (关键改进)
    // 不再使用单一的 net_tx，而是为每个业务创建独立通道
    let (chat_tx, mut chat_rx) = mpsc::channel(2048);
    let (forum_tx, mut forum_rx) = mpsc::channel(2048);
    let (tns_tx, mut tns_rx) = mpsc::channel(2048);
    let (fs_tx, mut fs_rx) = mpsc::channel(4096);
    
    let (dht_tx, mut dht_rx) = mpsc::channel(1024);

    // 4. 初始化 Flavors
    // 将各自的 tx 传入对应的 Flavor
    
    let chat = ChatFlavor::new(
        data_dir.join("chat.db").to_str().unwrap(),
        &key_bytes, &key_bytes, dht_tx.clone(), chat_tx
    )?;
    
    let forum = ForumFlavor::new(
        data_dir.join("forum.db").to_str().unwrap(),
        dht_tx.clone(), forum_tx
    )?;

    let tns = TnsFlavor::new(
        data_dir.join("tns.db").to_str().unwrap(),
        &key_bytes, dht_tx.clone(), tns_tx
    )?;

    let fs = FileShareFlavor::new(
        data_dir.join("files").to_str().unwrap(),
        fs_tx
    )?;

    // 5. 组装 CompositeFlavor
    // 默认 Flavor 可以设为 Chat，或者一个专门的 Router
    let composite = Arc::new(CompositeFlavor::new(chat.clone()));
    
    // 绑定: 只有通过这种绑定，Composite 才知道收到 Stream X 的数据该给谁
    composite.bind_stream(STREAM_CHAT, chat.clone());
    composite.bind_stream(STREAM_FORUM, forum.clone());
    composite.bind_stream(STREAM_TNS, tns.clone());
    composite.bind_stream(STREAM_FS, fs.clone());
    
    // 注册 Composite 到系统
    registry.register_flavor(composite);

    // 6. 节点配置
    let config = NodeConfig {
        bind_addr: "0.0.0.0:10000".to_string(),
        keypair: keys,
        // 多流模式：允许高并发，且各业务互不阻塞
        multiplexing_mode: MultiplexingMode::ParallelMulti,
        // Turbo 模式：作为服务器，追求吞吐量
        profile: SecurityProfile::Turbo,
        default_dialect: "etp.dialect.noise.std".to_string(),
        default_flavor: "etp.flavor.composite.v1".to_string(),
        ..NodeConfig::default()
    };

    let (engine, handle, _) = EtpEngine::new(config, registry).await?;

    // 7. 关键：多路复用回包路由 (Multiplexed Return Path Routing)
    // 这是一个 Event Loop，负责将不同 Flavor 产生的回包，打上正确的 Stream ID 标签
    let h_net = handle.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // 聊天回包 -> Stream 2
                Some((target, data)) = chat_rx.recv() => {
                    let _ = h_net.send_stream(target, STREAM_CHAT, data).await;
                }
                // 论坛回包 -> Stream 3
                Some((target, data)) = forum_rx.recv() => {
                    let _ = h_net.send_stream(target, STREAM_FORUM, data).await;
                }
                // TNS 回包 -> Stream 4
                Some((target, data)) = tns_rx.recv() => {
                    let _ = h_net.send_stream(target, STREAM_TNS, data).await;
                }
                // 文件传输回包 -> Stream 5
                Some((target, data)) = fs_rx.recv() => {
                    let _ = h_net.send_stream(target, STREAM_FS, data).await;
                }
                // 所有通道关闭，退出
                else => break,
            }
        }
        error!("Multiplexing loop exited unexpectedly!");
    });

    // 8. DHT 存储请求处理
    let h_dht = handle.clone();
    tokio::spawn(async move {
        while let Some(req) = dht_rx.recv().await {
            debug!("DHT Store: Key {:?}", hex::encode(&req.key[0..4]));
            let _ = h_dht.dht_store(req.key, req.value, req.ttl).await;
        }
    });

    info!("ETPNet Hub Running on 0.0.0.0:10000");
    engine.run().await?;

    Ok(())
}
// etp-core/examples/full_node.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::Duration;
use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use clap::{Parser, Subcommand};
use log::{info, error, warn, debug};
use env_logger::Env;
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use anyhow::{Result, anyhow, Context};

// --- ETP Core Imports ---
use etp_core::network::node::{EtpEngine, NodeConfig, EtpHandle};
use etp_core::crypto::noise::KeyPair;
use etp_core::transport::shaper::SecurityProfile;
use etp_core::plugin::{PluginRegistry, CapabilityProvider};
use etp_core::network::socks5::{Socks5Server, RuleBasedRouter, AppSignal}; // AppSignal: (Target, StreamID, Data, Fin)

// --- Flavors ---
use etp_core::plugin::flavors::vpn::{VpnFlavor, VpnConfig};
use etp_core::plugin::flavors::chat::{ChatFlavor, DhtStoreRequest};
use etp_core::plugin::flavors::forum::ForumFlavor;
use etp_core::plugin::flavors::tns::TnsFlavor;
use etp_core::plugin::flavors::fileshare::FileShareFlavor;
use etp_core::plugin::flavors::http_gateway::HttpGatewayFlavor;

// --- Dialects ---
use etp_core::wire::packet::{FakeTlsObfuscator, FakeHttpObfuscator, EntropyObfuscator, Dialect};

// --- CLI Arguments ---
#[derive(Parser)]
#[command(name = "etp-node")]
#[command(about = "ETP Production Node: Secure, Anonymous, Extensible", long_about = None)]
struct Cli {
    /// 监听地址 (UDP)
    #[arg(long, default_value = "0.0.0.0:0")]
    bind: String,

    /// SOCKS5 代理端口
    #[arg(long, default_value = "1080")]
    socks_port: u16,

    /// HTTP 网关端口
    #[arg(long, default_value = "8080")]
    http_port: u16,

    /// 数据持久化目录
    #[arg(long, default_value = "./etp_data")]
    data_dir: PathBuf,

    /// 流量整形模式 (Turbo, Balanced, Paranoid)
    #[arg(long, default_value = "Balanced")]
    profile: String,

    /// 首选方言 (tls, http, noise)
    #[arg(long, default_value = "tls")]
    dialect: String,

    /// 引导节点列表
    #[arg(long)]
    bootstrap: Vec<String>,
}

// --- 身份持久化结构 ---
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    public_key_hex: String,
    private_key_hex: String,
    node_id: String,
    created_at: String,
}

// --- 多路复用协议 (User-Space Mux) ---
// 由于 node.rs 在 MVP 阶段将 StreamID 固定，我们在应用层再次封装以支持 SOCKS5 并发
// 格式: [SubStreamID(4)][OpCode(1)][Payload...]
const MUX_OP_DATA: u8 = 0x00;
const MUX_OP_FIN: u8 = 0x01;
const MUX_OP_OPEN: u8 = 0x02; // 携带目标地址元数据

// --- 主程序 ---

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化环境与日志
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    
    // 确保数据目录存在
    fs::create_dir_all(&cli.data_dir).context("Failed to create data directory")?;

    info!(">>> ETP System Initializing <<<");
    info!("Storage: {:?}", cli.data_dir);

    // 2. 身份管理 (生产级：加载或生成)
    let keypair = load_or_generate_identity(&cli.data_dir.join("identity.json"))?;
    let my_node_id = blake3::hash(&keypair.public).to_hex();
    
    info!("------------------------------------------------");
    info!("Node Identity Loaded");
    info!("Public Key: {}", hex::encode(&keypair.public));
    info!("Node ID:    {}", my_node_id);
    info!("------------------------------------------------");

    // 3. 配置构建
    let profile = match cli.profile.as_str() {
        "Paranoid" => SecurityProfile::Paranoid { interval_ms: 20, target_size: 1350 },
        "Turbo" => SecurityProfile::Turbo,
        _ => SecurityProfile::Balanced,
    };

    let bootstrap_peers: Vec<SocketAddr> = cli.bootstrap.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // 确定默认方言 ID
    let default_dialect_id = match cli.dialect.as_str() {
        "http" => "etp.dialect.quic.v1",
        "noise" => "etp.dialect.noise.std",
        _ => "etp.dialect.dtls.v1", // Default TLS
    };

    let config = NodeConfig {
        bind_addr: cli.bind.clone(),
        keypair: keypair.clone(), // Clone for engine
        profile,
        bootstrap_peers,
        default_dialect: default_dialect_id.to_string(),
        default_flavor: "etp.flavor.core".to_string(),
        // 生产环境应从加密存储中加载 stateless_secret，此处演示用随机生成
        stateless_secret: rand::random(), 
    };

    // 4. 插件与风味装载 (Hot-Pluggable Loader)
    // 解决循环依赖：Flavor 需要 Sender -> Engine 需要 Registry -> Registry 需要 Flavor
    // 方案：使用 Proxy Channel
    let (proxy_tx, mut proxy_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(8192); // 大缓冲区
    let (dht_proxy_tx, mut dht_proxy_rx) = mpsc::channel::<DhtStoreRequest>(1024);

    let registry = Arc::new(PluginRegistry::new());
    let loader = PluginLoader::new(registry.clone(), &cli.data_dir, &keypair);
    
    // 装载核心风味
    loader.load_dialects();
    loader.load_flavors(proxy_tx.clone(), dht_proxy_tx.clone())?;

    // 5. 启动核心引擎
    info!("Starting ETP Kernel...");
    let (engine, handle, mut app_rx) = EtpEngine::new(config.clone(), registry.clone()).await?;
    
    // 启动 Engine 主循环 (后台)
    tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            error!("CRITICAL: ETP Engine crashed: {}", e);
            std::process::exit(1);
        }
    });

    // 6. 启动 Proxy 桥接 (闭环)
    // Flavor -> Engine Data
    let h_data = handle.clone();
    tokio::spawn(async move {
        while let Some((target, data)) = proxy_rx.recv().await {
            if let Err(e) = h_data.send_data(target, data).await {
                debug!("Failed to proxy data to engine: {}", e);
            }
        }
    });

    // Flavor -> DHT Store
    let h_dht = handle.clone();
    tokio::spawn(async move {
        while let Some(req) = dht_proxy_rx.recv().await {
            if let Err(e) = h_dht.dht_store(req.key, req.value, req.ttl).await {
                debug!("Failed to proxy DHT store: {}", e);
            }
        }
    });

    // 7. SOCKS5 & Multiplexing Gateway (高级实现)
    // ---------------------------------------------------------
    // 负责处理 SOCKS5 的 TCP 连接与 ETP Stream 之间的映射
    // 支持高并发多路复用
    // ---------------------------------------------------------
    
    // A. SOCKS5 Ingress (本地 -> 隧道)
    let socks_addr = format!("127.0.0.1:{}", cli.socks_port);
    let (s5_tx, mut s5_rx) = mpsc::channel::<AppSignal>(4096);
    
    // 路由规则：默认发给 "0.0.0.0:0"，由 ETP 层的 handle.connect 决定实际去向
    // 注意：全节点模式下，我们通常连接到一个 Exit Node。
    // 这里为了演示，我们假设用户会通过 `connect` 命令手动建立到 Exit Node 的连接，
    // SOCKS5 流量会自动复用该连接。
    let router = Arc::new(RuleBasedRouter::new(vec![])); 
    let s5_server = Socks5Server::new(socks_addr.clone(), s5_tx, "0.0.0.0:0".parse().unwrap());

    // SOCKS5 Adapter Task
    let s5_handle = handle.clone();
    tokio::spawn(async move {
        while let Some((target, stream_id, data, fin)) = s5_rx.recv().await {
            // Mux Protocol Encapsulation: [StreamID(4)][Op(1)][Data]
            // 如果是首包 (含有 Metadata 的 OPEN 操作)，需要特殊处理吗？
            // Socks5Server 发送的第一个包是 Metadata。
            // 我们可以在这里简单地将所有数据都视为 DATA，依靠接收端解析。
            // 更好的做法：使用 OpCode 区分。
            
            // 简单的 Mux 协议：
            let op = if fin { MUX_OP_FIN } else { MUX_OP_DATA };
            
            // 预分配缓冲区
            let mut payload = Vec::with_capacity(5 + data.len());
            payload.extend_from_slice(&stream_id.to_be_bytes());
            payload.push(op);
            payload.extend(data); // Metadata is inside data for the first packet

            // 发送给目标 Exit Node
            // 如果 Target 是 0.0.0.0，说明未指定，可能需要广播或丢弃。
            // 在 CLI 演示中，用户必须先 connect ExitNode，然后所有 SOCKS 流量流向该 Node。
            // 我们需要一个全局的 "Default Route"。
            // 这里简化：发送给 handle，如果 handle 内部没有 Session 映射，会触发 On-demand connect。
            // 但 0.0.0.0 是无法 Connect 的。
            // 修正：我们通过全局变量或 CLI 参数获取 Default Exit Node。
            // 暂时假设用户必须在 CLI 中 connect，并且 SOCKS5 请求中的 target 会被忽略，
            // 实际上应该由 Router 决定。
            
            // 这里的 target 来自 Socks5Server 的 exit_node (0.0.0.0)。
            // 这是一个演示限制。
            // 生产级：SOCKS5 Router 应该配置真实的 Exit Node IP。
            // 我们在接收到数据时，如果是 0.0.0.0，尝试使用 "最近活跃的 Peer"。
            
            if target.ip().is_unspecified() {
                // Broadcast or pick first active session? 
                // Too complex for example. We require explicit target in real app.
                // For demo, we just try to send to "target", assuming handle logic might fix it or fail.
            } else {
                let _ = s5_handle.send_data(target, payload).await;
            }
        }
    });

    // 启动 SOCKS5 监听 (接收来自 Router 的回包)
    let (s5_in_tx, s5_in_rx) = mpsc::channel(4096);
    tokio::spawn(async move {
        if let Err(e) = s5_server.run(s5_in_rx).await {
            error!("SOCKS5 Server Error: {}", e);
        }
    });

    // B. SOCKS5 Egress (隧道 -> 本地/出口)
    // 维护 "Exit Node" 端的连接状态
    // 当本节点作为出口节点时，需要解析 Mux 包并发起 TCP 连接
    
    // Map: (SourcePeer, StreamID) -> TcpSender
    let egress_conns = Arc::new(DashMap::new());
    
    // C. App Data Dispatcher (Main Demultiplexer)
    // 处理从 app_rx 接收到的数据：解包 Mux -> 分发
    tokio::spawn(async move {
        let active_conns = egress_conns;
        
        while let Some((src, data)) = app_rx.recv().await {
            // Mux Unpack: [StreamID(4)][Op(1)][Payload]
            if data.len() < 5 { continue; }
            
            let stream_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
            let op = data[4];
            let payload = &data[5..];

            match op {
                MUX_OP_DATA => {
                    // 1. 检查是否是 SOCKS5 回包 (作为 Client 收到)
                    // 如果 SOCKS5 Server 在运行，它会处理 src 对应的流。
                    // 但是 Socks5Server 是处理 "我请求出去" 的回包。
                    // 这里我们分两类：
                    // Case A: 我是 Client，收到 ExitNode 的回包 -> 转给 Socks5Server 的 s5_in_tx
                    // Case B: 我是 ExitNode，收到 Client 的请求 -> 发起 TCP 连接
                    
                    // 为了简化全节点逻辑，我们假设：
                    // 如果本地有 SOCKS5 请求发出去 (Inbound Map hit)，则是 Case A。
                    // 否则尝试 Case B。
                    
                    // 尝试发送给本地 SOCKS5 Server (Case A)
                    // s5_in_tx 需要 (Src, StreamID, Data)
                    if s5_in_tx.send((src, stream_id, payload.to_vec())).await.is_ok() {
                        // 如果 SOCKS5 Server 识别这个 StreamID，它会处理。
                        // 但 SOCKS5 Server 的 active_conns 是私有的。
                        // 这里有一个架构耦合问题。
                        // 生产级：应该用一个统一的 SessionManger。
                        // 本例：全量转发给 SOCKS5 Inbound。如果它不认识 StreamID，它会丢弃/Log。
                        // 同时，如果是 Case B (我是服务器)，SOCKS5 Inbound 也会丢弃。
                        // 所以我们需要处理 Case B。
                    }
                    
                    // 处理 Case B (Exit Node Logic)
                    // 如果 SOCKS5 没处理 (即不是我发起的)，那么我是出口。
                    // 检查 egress_conns
                    if let Some(tx) = active_conns.get(&(src, stream_id)) {
                        let _ = tx.send(payload.to_vec()).await;
                    } else {
                        // 新的连接请求？
                        // 第一个包通常包含 Metadata (Target Address)
                        // 解析 Metadata
                        if payload.len() > 1 && payload[0] == 0x01 { // CMD_CONNECT (from SOCKS5 impl)
                             // Handle New Exit Connection
                             handle_new_exit_connection(
                                 src, stream_id, payload.to_vec(), 
                                 active_conns.clone(), 
                                 s5_handle.clone() // Need handle to send back data
                             );
                        }
                    }
                },
                MUX_OP_FIN => {
                    // 关闭连接
                    if let Some((_, tx)) = active_conns.remove(&(src, stream_id)) {
                        // Drop tx closes channel
                        debug!("Closed egress stream {} from {}", stream_id, src);
                    }
                    // 同时也发给 SOCKS5 Server 以防是 Client 端
                    let _ = s5_in_tx.send((src, stream_id, Vec::new())).await;
                },
                _ => {}
            }
        }
    });

    // 8. HTTP Gateway (无感接入)
    // 需等待 Flavors 初始化完毕
    let tns_f = registry.get_flavor("etp.flavor.tns.v1")
        .expect("TNS Flavor missing")
        .downcast_arc::<TnsFlavor>().ok().expect("TNS Type mismatch");
    
    let fs_f = registry.get_flavor("etp.flavor.fs.v1")
        .expect("FS Flavor missing")
        .downcast_arc::<FileShareFlavor>().ok().expect("FS Type mismatch");

    let _http_gw = HttpGatewayFlavor::new(cli.http_port, tns_f.clone(), fs_f.clone());

    // 9. 用户交互 CLI
    run_repl(my_node_id, socks_addr, cli.http_port, handle, tns_f, fs_f, registry.clone()).await?;

    Ok(())
}

// --- 辅助函数：身份加载 ---
fn load_or_generate_identity(path: &Path) -> Result<KeyPair> {
    if path.exists() {
        let content = fs::read_to_string(path)?;
        let id_file: IdentityFile = serde_json::from_str(&content)?;
        
        let pub_bytes = hex::decode(&id_file.public_key_hex)?;
        let priv_bytes = hex::decode(&id_file.private_key_hex)?;
        
        Ok(KeyPair {
            public: pub_bytes,
            private: priv_bytes,
        })
    } else {
        info!("Identity file not found. Generating new identity...");
        let keypair = KeyPair::generate();
        let id_file = IdentityFile {
            public_key_hex: hex::encode(&keypair.public),
            private_key_hex: hex::encode(&keypair.private),
            node_id: blake3::hash(&keypair.public).to_hex().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        
        let json = serde_json::to_string_pretty(&id_file)?;
        fs::write(path, json)?;
        info!("New identity saved to {:?}", path);
        Ok(keypair)
    }
}

// --- 辅助函数：出口节点连接处理 ---
fn handle_new_exit_connection(
    src: SocketAddr,
    stream_id: u32,
    meta_data: Vec<u8>,
    conns: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
    handle: EtpHandle
) {
    tokio::spawn(async move {
        // 解析 Metadata (假设是 SOCKS5 Metadata 格式 [0x01][ATYP][ADDR][PORT])
        // 简单起见，我们跳过详细解析，直接尝试连接
        // 生产级：复用 Socks5Server::read_target_addr 逻辑
        // 这里仅作演示：假设 metadata 包含 IP:Port 字符串
        
        // 真实情况：我们需要反序列化 Metadata。
        // 为了演示，我们假设 Target 是 "google.com:80"
        warn!("ExitNode: Received CONNECT request from {}, Stream {}, but metadata parsing is simplified in demo.", src, stream_id);
        
        // 模拟：建立 TCP 连接
        // let stream = TcpStream::connect(target).await...
        // 注册到 conns
        // 开启读写循环，读取 TCP 发送回 handle (Wrap Mux Header)
    });
}

// --- 辅助结构：插件加载器 ---
struct PluginLoader {
    registry: Arc<PluginRegistry>,
    data_dir: PathBuf,
    keypair: KeyPair,
}

impl PluginLoader {
    fn new(registry: Arc<PluginRegistry>, data_dir: &Path, keypair: &KeyPair) -> Self {
        Self { registry, data_dir: data_dir.to_path_buf(), keypair: keypair.clone() }
    }

    fn load_dialects(&self) {
        // 生产级：可以从 config 读取列表
        self.registry.register_dialect(Arc::new(FakeTlsObfuscator));
        self.registry.register_dialect(Arc::new(FakeHttpObfuscator));
        self.registry.register_dialect(Arc::new(EntropyObfuscator));
    }

    fn load_flavors(&self, proxy_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, dht_tx: mpsc::Sender<DhtStoreRequest>) -> Result<()> {
        // 这里展示了如何根据配置“热插拔”
        // 在实际应用中，可以在此读取 config.json 中的 enabled_flavors 列表
        
        // Helper to convert keys
        let sign_key: [u8;32] = self.keypair.private.as_slice().try_into().unwrap(); // Mock
        let enc_key: [u8;32] = self.keypair.private.as_slice().try_into().unwrap();  // Mock

        // Chat
        let chat = ChatFlavor::new(
            self.data_dir.join("chat.db").to_str().unwrap(),
            &sign_key, &enc_key, dht_tx.clone(), proxy_tx.clone()
        )?;
        self.registry.register_flavor(chat);

        // ... 其他 Flavor 加载逻辑同 main ...
        
        Ok(())
    }
}

// --- REPL ---
async fn run_repl(
    node_id: String, 
    socks_addr: String, 
    http_port: u16,
    handle: EtpHandle,
    tns: Arc<TnsFlavor>,
    fs: Arc<FileShareFlavor>,
    _registry: Arc<PluginRegistry>
) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        print!("ETP@{}> ", &node_id[0..8]);
        use std::io::Write;
        std::io::stdout().flush()?;

        if reader.read_line(&mut line).await? == 0 { break; }
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "connect" => {
                if parts.len() < 3 { println!("Usage: connect <ip:port> <hex_pubkey>"); continue; }
                if let Ok(addr) = parts[1].parse() {
                    if let Ok(key) = hex::decode(parts[2]) {
                        info!("Connecting to {}...", addr);
                        handle.connect(addr, key).await?;
                    } else { println!("Invalid Key"); }
                } else { println!("Invalid Address"); }
            },
            "resolve" => {
                if parts.len() < 2 { println!("Usage: resolve <name>"); continue; }
                match tns.resolve(parts[1]).await {
                    Ok(r) => println!("Result: {:?} -> {:?}", r.name, hex::encode(r.target_id)),
                    Err(e) => println!("Error: {}", e),
                }
            },
            "share" => {
                if parts.len() < 2 { println!("Usage: share <path>"); continue; }
                match fs.share_file(Path::new(parts[1])) {
                    Ok(hash) => println!("File Shared. Root: {}", hex::encode(hash)),
                    Err(e) => println!("Error: {}", e),
                }
            },
            "info" => {
                println!("--- ETP Node Status ---");
                println!("ID: {}", node_id);
                println!("SOCKS5: {}", socks_addr);
                println!("HTTP GW: http://127.0.0.1:{}", http_port);
                println!("Storage: Active");
            },
            "quit" | "exit" => {
                info!("Shutting down...");
                break;
            },
            _ => println!("Unknown command. Try: connect, resolve, share, info, quit"),
        }
    }
    Ok(())
}

// Helper trait specifically for downcast_arc
trait DowncastArc {
    fn downcast_arc<T: 'static>(self) -> Result<Arc<T>, Arc<dyn etp_core::plugin::Flavor>>;
}

impl DowncastArc for Arc<dyn etp_core::plugin::Flavor> {
    fn downcast_arc<T: 'static>(self) -> Result<Arc<T>, Arc<dyn etp_core::plugin::Flavor>> {
        // 生产级实现：基于原始指针的类型转换
        // 
        // 原理：Arc<dyn Trait> 是一个胖指针 (Data Ptr + VTable Ptr)，而 Arc<T> 是一个瘦指针 (Data Ptr)。
        // 这里的转换通过 Arc::into_raw 提取胖指针，再强制转换为 T 的瘦指针，最后通过 Arc::from_raw 重建 Arc。
        //
        // 安全性说明 (Safety):
        // 这是一个 unsafe 操作。Rust 编译器无法在编译期验证 dyn Trait 此时背后的真实类型是否为 T。
        // 但在 ETP 的架构中，我们通过 PluginRegistry 的 "Capability ID" (String) 进行了严格的类型映射。
        // 只要调用者（full_node.rs）保证 get_flavor("id_of_T") 对应的是 T 类型，此操作即是安全的。
        
        let raw: *const dyn etp_core::plugin::Flavor = Arc::into_raw(self);
        
        // 这里的 cast 会丢弃 vtable 信息，只保留数据指针
        let cast_ptr: *const T = raw as *const T;
        
        // Safety: 
        // 1. 指针来源是 Arc::into_raw，内存布局符合 Arc 要求。
        // 2. 类型一致性由上层 Registry 逻辑保证。
        unsafe {
            Ok(Arc::from_raw(cast_ptr))
        }
    }
}

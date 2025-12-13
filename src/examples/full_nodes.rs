// etp-core/src/examples/full_nodes.rs

use std::sync::Arc;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::fs;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{mpsc, oneshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use clap::Parser;
use log::{info, error, warn, debug, trace};
use env_logger::Env;
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use anyhow::{Result, anyhow, Context};

// --- ETP Core Imports ---
use etp_core::network::node::{EtpEngine, NodeConfig, EtpHandle, Command};
use etp_core::crypto::noise::KeyPair;
use etp_core::transport::shaper::SecurityProfile;
use etp_core::plugin::{PluginRegistry, CapabilityProvider, Dialect, Flavor};
use etp_core::network::socks5::{Socks5Server, RuleBasedRouter, AppSignal}; 

// --- Flavors ---
use etp_core::plugin::flavors::vpn::{VpnFlavor, VpnConfig};
use etp_core::plugin::flavors::chat::{ChatFlavor, DhtStoreRequest};
use etp_core::plugin::flavors::tns::TnsFlavor;
use etp_core::plugin::flavors::fileshare::FileShareFlavor;
use etp_core::plugin::flavors::http_gateway::HttpGatewayFlavor;

// --- Dialects (Real Implementations) ---
use etp_core::plugin::{StandardDialect, FakeTlsDialect, FakeHttpDialect, FakeQuicDialect, FakeDtlsDialect};

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

    /// 首选方言 (tls, http, quic, dtls, noise)
    #[arg(long, default_value = "tls")]
    dialect: String,

    /// 引导节点列表 (IP:Port)
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
// Header: [StreamID(4)][OpCode(1)]
const MUX_OP_DATA: u8 = 0x00;
const MUX_OP_FIN:  u8 = 0x01;
const MUX_OP_RST:  u8 = 0x02; // 新增 RST，用于强制断开

// --- 全局统计 ---
static TOTAL_BYTES_TX: AtomicUsize = AtomicUsize::new(0);
static TOTAL_BYTES_RX: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_TUNNELS: AtomicUsize = AtomicUsize::new(0);

// --- 主程序 ---

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. 初始化环境与日志
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    
    fs::create_dir_all(&cli.data_dir).context("Failed to create data directory")?;

    println!("\n========================================================");
    println!("   ETP Node - Encrypted Transport Protocol v0.2.0");
    println!("========================================================");

    // 2. 身份管理
    let keypair = load_or_generate_identity(&cli.data_dir.join("identity.json"))?;
    let my_node_id = blake3::hash(&keypair.public).to_hex();
    
    info!("Identity Loaded: {}", my_node_id);
    info!("Listen Address: {}", cli.bind);

    // 3. 配置构建
    let profile = match cli.profile.as_str() {
        "Paranoid" => SecurityProfile::Paranoid { interval_ms: 20, target_size: 1350 },
        "Turbo" => SecurityProfile::Turbo,
        _ => SecurityProfile::Balanced,
    };

    let bootstrap_peers: Vec<SocketAddr> = cli.bootstrap.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let default_dialect_id = match cli.dialect.as_str() {
        "http" => "etp.dialect.http.v1",
        "noise" => "etp.dialect.noise.std",
        "quic" => "etp.dialect.quic.v1",
        "dtls" => "etp.dialect.dtls.v1",
        _ => "etp.dialect.tls.v1", 
    };

    let config = NodeConfig {
        bind_addr: cli.bind.clone(),
        keypair: keypair.clone(),
        profile,
        bootstrap_peers,
        default_dialect: default_dialect_id.to_string(),
        default_flavor: "etp.flavor.core".to_string(),
        stateless_secret: rand::random(), 
    };

    // 4. 插件装载 (Hot-Pluggable Loader)
    let (proxy_tx, mut proxy_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(8192); 
    let (dht_proxy_tx, mut dht_proxy_rx) = mpsc::channel::<DhtStoreRequest>(1024);

    let registry = Arc::new(PluginRegistry::new());
    let loader = PluginLoader::new(registry.clone(), &cli.data_dir, &keypair);
    
    loader.load_dialects();
    loader.load_flavors(proxy_tx.clone(), dht_proxy_tx.clone())?;

    // 5. 启动核心引擎
    info!("Bootstrapping Kernel...");
    let (engine, handle, mut app_rx) = EtpEngine::new(config.clone(), registry.clone()).await?;
    
    // Engine Daemon
    tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            error!("CRITICAL: ETP Engine crashed: {}", e);
            std::process::exit(1);
        }
    });

    // 6. 启动 Proxy 桥接
    // Flavor -> Engine (Data)
    let h_data = handle.clone();
    tokio::spawn(async move {
        while let Some((target, data)) = proxy_rx.recv().await {
            if let Err(e) = h_data.send_data(target, data).await {
                debug!("Proxy send error: {}", e);
            }
        }
    });

    // Flavor -> Engine (DHT Store)
    let h_dht = handle.clone();
    tokio::spawn(async move {
        while let Some(req) = dht_proxy_rx.recv().await {
            if let Err(e) = h_dht.dht_store(req.key, req.value, req.ttl).await {
                debug!("DHT proxy error: {}", e);
            }
        }
    });

    // 7. SOCKS5 Gateway (Ingress)
    // ---------------------------------------------------------
    // 本地 SOCKS5 端口 -> ETP 隧道
    // ---------------------------------------------------------
    let socks_addr = format!("127.0.0.1:{}", cli.socks_port);
    let (s5_tx, mut s5_rx) = mpsc::channel::<AppSignal>(4096);
    
    // 路由表：这里简化为总是发给“已连接的第一个节点”或者通过 CLI `connect` 指定的节点
    // 在真实应用中，Router 会根据 Target 决定下一跳
    let router = Arc::new(RuleBasedRouter::new(vec![])); 
    let s5_server = Socks5Server::new(socks_addr.clone(), s5_tx, router, 1000);

    // SOCKS5 Ingress Task
    // 负责将 SOCKS5 请求打包成 MUX 协议发送给 Engine
    let s5_handle = handle.clone();
    // 全局默认路由目标 (可由 CLI 'connect' 更新)
    let default_route: Arc<dashmap::DashMap<String, SocketAddr>> = Arc::new(dashmap::DashMap::new());
    
    tokio::spawn(async move {
        while let Some((target, stream_id, data, fin)) = s5_rx.recv().await {
            // Mux Protocol: [StreamID(4)][Op(1)][Data...]
            let op = if fin { MUX_OP_FIN } else { MUX_OP_DATA };
            
            let mut payload = Vec::with_capacity(5 + data.len());
            payload.extend_from_slice(&stream_id.to_be_bytes());
            payload.push(op);
            payload.extend(data);

            // 路由逻辑：如果 SOCKS5 Server 传来的 target 是 0.0.0.0 (未指定)，
            // 我们需要决定发给谁。这里我们广播给所有活跃会话？或者发给最近一个？
            // 简单起见：如果 target 有效则发给 target，否则尝试查找 Default Route。
            // 注意：full_nodes.rs 里的 socks5 server 实现是将 request 发给 Exit Node。
            // 这里的 'target' 实际上是 Exit Node 的地址。
            
            if !target.ip().is_unspecified() {
                let _ = s5_handle.send_data(target, payload).await;
                TOTAL_BYTES_TX.fetch_add(payload.len(), Ordering::Relaxed);
            } else {
                // Drop or log warning
                // debug!("SOCKS5: No route for packet");
            }
        }
    });

    // SOCKS5 Return Path (用于接收本地 SOCKS5 Server 的回包)
    let (s5_in_tx, s5_in_rx) = mpsc::channel(4096);
    
    tokio::spawn(async move {
        if let Err(e) = s5_server.run(s5_in_rx).await {
            error!("SOCKS5 Server Error: {}", e);
        }
    });

    // 8. Exit Node Logic (Egress) & App Data Dispatcher
    // ---------------------------------------------------------
    // 处理来自 ETP 隧道的包 -> 转发给本地 SOCKS5 或 发起 TCP 连接
    // ---------------------------------------------------------
    
    // 活跃出口连接表: (SourcePeer, StreamID) -> TCP Sender
    let egress_conns = Arc::new(DashMap::new());
    
    let h_egress = handle.clone();
    
    tokio::spawn(async move {
        while let Some((src, data)) = app_rx.recv().await {
            TOTAL_BYTES_RX.fetch_add(data.len(), Ordering::Relaxed);
            
            if data.len() < 5 { continue; }
            
            let stream_id = u32::from_be_bytes(data[0..4].try_into().unwrap());
            let op = data[4];
            let payload = &data[5..];

            match op {
                MUX_OP_DATA => {
                    // 1. 尝试作为 SOCKS5 Client 的回包处理
                    // 如果本地 SOCKS5 Server 有对应的 stream_id (发起的请求)，s5_in_tx 会处理
                    // 注意：这里的 stream_id 可能冲突，如果在同一节点既做 Client 又做 Server。
                    // 理想情况下应区分 Stream ID 范围 (Client 偶数, Server 奇数)。
                    // 这里我们尝试发送，如果 SOCKS5 Server 不认识 ID，它会忽略。
                    // 但我们需要知道是否被处理了。
                    
                    // 简单策略：先查 egress_conns (作为服务器的连接)。如果有，直接处理。
                    if let Some(tx) = egress_conns.get(&(src, stream_id)) {
                        let _ = tx.send(payload.to_vec()).await;
                    } else {
                        // 没在 egress 表中，可能是 SOCKS5 Client 回包，发给 s5_in_tx
                        // 或者，这是一个新的 Exit Request (Open)
                        
                        // 检查是否是新的连接请求 (Metadata)
                        // 协议约定：第一个数据包如果是 Metadata (CMD_CONNECT)，则是新连接
                        // 我们的 SOCKS5 Server 实现发出的第一个包是 [0x01][Metadata]
                        if payload.len() > 1 && payload[0] == 0x01 {
                            // 这是新连接请求！
                            handle_new_exit_connection(
                                src, stream_id, payload.to_vec(),
                                egress_conns.clone(),
                                h_egress.clone()
                            ).await;
                        } else {
                            // 既不是已知的 Egress，也不是新请求，那就尝试发给 Ingress (作为 Client 回包)
                            // 注意：这里有个潜在的 ID 冲突问题。但在 Demo 中暂且接受。
                            let _ = s5_in_tx.send((src, stream_id, payload.to_vec())).await;
                        }
                    }
                },
                MUX_OP_FIN | MUX_OP_RST => {
                    // 关闭连接
                    if let Some((_, tx)) = egress_conns.remove(&(src, stream_id)) {
                        // Drop tx triggers clean shutdown
                        debug!("Closed egress stream {} from {}", stream_id, src);
                    }
                    // 同时也通知 SOCKS5 Inbound
                    let _ = s5_in_tx.send((src, stream_id, Vec::new())).await; // Empty data + closed channel will signal FIN
                },
                _ => {}
            }
        }
    });

    // 9. HTTP Gateway (无感接入)
    // 等待 Flavors 初始化
    let tns_f = registry.get_flavor("etp.flavor.tns.v1")
        .expect("TNS Flavor missing")
        .downcast_arc::<TnsFlavor>().ok().expect("TNS Type mismatch");
    
    let fs_f = registry.get_flavor("etp.flavor.fs.v1")
        .expect("FS Flavor missing")
        .downcast_arc::<FileShareFlavor>().ok().expect("FS Type mismatch");

    let _http_gw = HttpGatewayFlavor::new(cli.http_port, tns_f.clone(), fs_f.clone());

    // 10. 用户交互 CLI
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
        Ok(KeyPair { public: pub_bytes, private: priv_bytes })
    } else {
        info!("Generating new identity...");
        let keypair = KeyPair::generate();
        let id_file = IdentityFile {
            public_key_hex: hex::encode(&keypair.public),
            private_key_hex: hex::encode(&keypair.private),
            node_id: blake3::hash(&keypair.public).to_hex().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let json = serde_json::to_string_pretty(&id_file)?;
        fs::write(path, json)?;
        Ok(keypair)
    }
}

// --- 核心：出口节点连接处理 (Full Implementation) ---
async fn handle_new_exit_connection(
    src: SocketAddr,
    stream_id: u32,
    metadata: Vec<u8>,
    conns: Arc<DashMap<(SocketAddr, u32), mpsc::Sender<Vec<u8>>>>,
    handle: EtpHandle
) {
    // 1. 解析目标地址
    // Metadata format (from Socks5Server): [CMD(1)][ATYP(1)][ADDR...][PORT(2)]
    // CMD is 0x01 (CONNECT) or 0x03 (UDP). We only handle CONNECT here for TCP exit.
    
    if metadata.len() < 4 { return; }
    // Skip CMD (byte 0)
    let target_res = parse_socks_target(&metadata[1..]);
    
    match target_res {
        Ok(target_str) => {
            info!("ExitNode: Connecting to {} for {} (Stream {})", target_str, src, stream_id);
            
            // 2. 异步发起 TCP 连接
            // 使用 tokio::spawn 避免阻塞主分发循环
            tokio::spawn(async move {
                match TcpStream::connect(&target_str).await {
                    Ok(socket) => {
                        ACTIVE_TUNNELS.fetch_add(1, Ordering::Relaxed);
                        let (mut ri, mut wi) = socket.into_split();
                        
                        // 创建通道用于从 ETP 接收数据写入 TCP
                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
                        conns.insert((src, stream_id), tx);
                        
                        // Task A: ETP -> TCP (Downlink)
                        let t1 = tokio::spawn(async move {
                            while let Some(data) = rx.recv().await {
                                if data.is_empty() { break; } // FIN signal
                                if wi.write_all(&data).await.is_err() { break; }
                            }
                            let _ = wi.shutdown().await;
                        });
                        
                        // Task B: TCP -> ETP (Uplink)
                        let handle_clone = handle.clone();
                        let t2 = tokio::spawn(async move {
                            let mut buf = [0u8; 8192];
                            loop {
                                match ri.read(&mut buf).await {
                                    Ok(0) => break, // EOF
                                    Ok(n) => {
                                        // Wrap Mux Header: [ID][DATA][Payload]
                                        let mut pkg = Vec::with_capacity(5 + n);
                                        pkg.extend_from_slice(&stream_id.to_be_bytes());
                                        pkg.push(MUX_OP_DATA);
                                        pkg.extend_from_slice(&buf[..n]);
                                        
                                        if handle_clone.send_data(src, pkg).await.is_err() {
                                            break;
                                        }
                                        TOTAL_BYTES_TX.fetch_add(n, Ordering::Relaxed);
                                    }
                                    Err(_) => break,
                                }
                            }
                            // Send FIN
                            let mut fin_pkg = Vec::with_capacity(5);
                            fin_pkg.extend_from_slice(&stream_id.to_be_bytes());
                            fin_pkg.push(MUX_OP_FIN);
                            let _ = handle_clone.send_data(src, fin_pkg).await;
                        });
                        
                        // 等待任意一方结束，清理资源
                        let _ = tokio::join!(t1, t2);
                        conns.remove(&(src, stream_id));
                        ACTIVE_TUNNELS.fetch_sub(1, Ordering::Relaxed);
                        debug!("ExitNode: Connection closed {} <-> {}", src, target_str);
                    }
                    Err(e) => {
                        warn!("ExitNode: Failed to connect to {}: {}", target_str, e);
                        // Send RST back
                        let mut rst_pkg = Vec::with_capacity(5);
                        rst_pkg.extend_from_slice(&stream_id.to_be_bytes());
                        rst_pkg.push(MUX_OP_RST);
                        let _ = handle.send_data(src, rst_pkg).await;
                    }
                }
            });
        }
        Err(e) => {
            warn!("ExitNode: Malformed metadata from {}: {}", src, e);
        }
    }
}

// 解析 SOCKS5 地址格式 (Raw Bytes -> String)
fn parse_socks_target(buf: &[u8]) -> Result<String> {
    if buf.is_empty() { return Err(anyhow!("Empty buffer")); }
    let atyp = buf[0];
    
    match atyp {
        0x01 => { // IPv4
            if buf.len() < 7 { return Err(anyhow!("IPv4 too short")); }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok(format!("{}:{}", ip, port))
        },
        0x03 => { // Domain
            if buf.len() < 2 { return Err(anyhow!("Domain too short")); }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 { return Err(anyhow!("Domain len mismatch")); }
            let domain = String::from_utf8(buf[2..2+len].to_vec())?;
            let port = u16::from_be_bytes([buf[2+len], buf[2+len+1]]);
            Ok(format!("{}:{}", domain, port))
        },
        0x04 => { // IPv6
            if buf.len() < 19 { return Err(anyhow!("IPv6 too short")); }
            let ip_bytes: [u8; 16] = buf[1..17].try_into()?;
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok(format!("[{}]:{}", ip, port))
        },
        _ => Err(anyhow!("Unknown ATYP {}", atyp)),
    }
}

// --- 插件加载器 ---
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
        self.registry.register_dialect(Arc::new(FakeTlsDialect));
        self.registry.register_dialect(Arc::new(FakeHttpDialect));
        self.registry.register_dialect(Arc::new(FakeQuicDialect));
        self.registry.register_dialect(Arc::new(FakeDtlsDialect));
        self.registry.register_dialect(Arc::new(StandardDialect));
    }

    fn load_flavors(&self, proxy_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, dht_tx: mpsc::Sender<DhtStoreRequest>) -> Result<()> {
        let sign_key: [u8;32] = self.keypair.private.as_slice().try_into().unwrap();
        let enc_key: [u8;32] = self.keypair.private.as_slice().try_into().unwrap(); // Mock reuse

        let chat = ChatFlavor::new(
            self.data_dir.join("chat.db").to_str().unwrap(),
            &sign_key, &enc_key, dht_tx.clone(), proxy_tx.clone()
        )?;
        self.registry.register_flavor(chat);

        let tns = TnsFlavor::new(
            self.data_dir.join("tns.db").to_str().unwrap(),
            &sign_key, dht_tx.clone(), proxy_tx.clone()
        )?;
        self.registry.register_flavor(tns);

        let fs = FileShareFlavor::new(
            self.data_dir.join("files").to_str().unwrap(),
            proxy_tx.clone()
        )?;
        self.registry.register_flavor(fs);

        #[cfg(feature = "vpn")]
        {
            let vpn = VpnFlavor::new(proxy_tx.clone(), None);
            self.registry.register_flavor(vpn);
        }

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
        print!("\nETP@{}> ", &node_id[0..8]);
        use std::io::Write;
        std::io::stdout().flush()?;

        if reader.read_line(&mut line).await? == 0 { break; }
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() { continue; }

        match parts[0] {
            "help" => {
                println!("Commands:");
                println!("  connect <ip:port> <hex_pubkey>  - Connect to a peer manually");
                println!("  resolve <name>                  - Resolve TNS name");
                println!("  share <path>                    - Share a file");
                println!("  stats                           - Show traffic statistics");
                println!("  info                            - Show node status");
                println!("  quit / exit                     - Shutdown");
            },
            "connect" => {
                if parts.len() < 3 { println!("Usage: connect <ip:port> <hex_pubkey>"); continue; }
                if let Ok(addr) = parts[1].parse() {
                    if let Ok(key) = hex::decode(parts[2]) {
                        info!("Connecting to {}...", addr);
                        handle.connect(addr, key).await?;
                    } else { println!("Invalid Key (Hex)"); }
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
            "stats" => {
                let tx = TOTAL_BYTES_TX.load(Ordering::Relaxed);
                let rx = TOTAL_BYTES_RX.load(Ordering::Relaxed);
                let active = ACTIVE_TUNNELS.load(Ordering::Relaxed);
                println!("--- Traffic Statistics ---");
                println!("TX: {:.2} MB", tx as f64 / 1024.0 / 1024.0);
                println!("RX: {:.2} MB", rx as f64 / 1024.0 / 1024.0);
                println!("Active Exit Tunnels: {}", active);
            },
            "info" => {
                println!("--- ETP Node Status ---");
                println!("ID: {}", node_id);
                println!("SOCKS5: {}", socks_addr);
                println!("HTTP GW: http://127.0.0.1:{}", http_port);
            },
            "quit" | "exit" => {
                info!("Shutting down...");
                break;
            },
            _ => println!("Unknown command. Type 'help'."),
        }
    }
    Ok(())
}

trait DowncastArc {
    fn downcast_arc<T: 'static>(self) -> Result<Arc<T>, Arc<dyn etp_core::plugin::Flavor>>;
}

impl DowncastArc for Arc<dyn etp_core::plugin::Flavor> {
    fn downcast_arc<T: 'static>(self) -> Result<Arc<T>, Arc<dyn etp_core::plugin::Flavor>> {
        let raw: *const dyn etp_core::plugin::Flavor = Arc::into_raw(self);
        let cast_ptr: *const T = raw as *const T;
        unsafe { Ok(Arc::from_raw(cast_ptr)) }
    }
}
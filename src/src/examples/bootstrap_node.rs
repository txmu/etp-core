// etp-core/examples/bootstrap_node.rs

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::io::Write;

use clap::Parser;
use log::{info, error, warn, debug};
use env_logger::Env;
use tokio::time;
use anyhow::{Result, Context};
use colored::*; 
use sysinfo::{System, SystemExt, CpuExt, ProcessExt};
use chrono::{DateTime, Local};

// ETP Core Imports
use etp_core::network::node::{EtpEngine, NodeConfig, EtpHandle};
use etp_core::crypto::noise::KeyPair;
use etp_core::transport::shaper::SecurityProfile;
use etp_core::plugin::PluginRegistry;
use etp_core::network::nat::NatManager;
use etp_core::NodeID;

// --- CLI Definitions ---

#[derive(Parser)]
#[command(name = "etp-sentinel")]
#[command(author = "ETP Core Team")]
#[command(version = "1.0.0")]
#[command(about = "ETP Production Bootstrap Node & Network Sentinel", long_about = None)]
struct Cli {
    /// 监听地址 (UDP)
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    bind: String,

    /// 身份密钥文件路径
    #[arg(short, long, default_value = "./sentinel_identity.json")]
    identity: PathBuf,

    /// 数据存储目录
    #[arg(long, default_value = "./sentinel_data")]
    data_dir: PathBuf,

    /// 禁用 TUI 仪表盘 (仅输出日志，适用于 Docker/Systemd)
    #[arg(long, default_value_t = false)]
    headless: bool,

    /// 允许 Bogon IP (仅限局域网测试)
    #[arg(long, default_value_t = false)]
    allow_bogon: bool,
}

// --- 身份管理 ---

#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityFile {
    public_hex: String,
    private_hex: String,
    node_id: String,
    created_at: String,
}

fn load_or_create_identity(path: &PathBuf) -> Result<KeyPair> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let id_file: IdentityFile = serde_json::from_str(&content)
            .context("Failed to parse identity file")?;
        
        let public = hex::decode(&id_file.public_hex)?;
        let private = hex::decode(&id_file.private_hex)?;
        
        info!("Loaded identity: {}", id_file.node_id);
        Ok(KeyPair { public, private })
    } else {
        info!("Generating new identity...");
        let keys = KeyPair::generate();
        let node_id = blake3::hash(&keys.public).to_hex().to_string();
        
        let id_file = IdentityFile {
            public_hex: hex::encode(&keys.public),
            private_hex: hex::encode(&keys.private),
            node_id: node_id.clone(),
            created_at: Local::now().to_rfc3339(),
        };
        
        std::fs::write(path, serde_json::to_string_pretty(&id_file)?)?;
        info!("Created new identity: {}", node_id);
        Ok(keys)
    }
}

// --- 监控指标系统 ---

struct SentinelMetrics {
    start_time: Instant,
    sys: System,
    // Network Stats
    known_peers_estimate: AtomicUsize,
    last_rtt_ms: AtomicUsize,
    public_ip: std::sync::Mutex<Option<SocketAddr>>,
}

impl SentinelMetrics {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            sys: System::new_all(),
            known_peers_estimate: AtomicUsize::new(0),
            last_rtt_ms: AtomicUsize::new(0),
            public_ip: std::sync::Mutex::new(None),
        }
    }

    fn update_system_stats(&mut self) {
        self.sys.refresh_cpu();
        self.sys.refresh_memory();
    }

    fn update_network_stats(&self, peers: usize, rtt: u64) {
        self.known_peers_estimate.store(peers, Ordering::Relaxed);
        self.last_rtt_ms.store(rtt as usize, Ordering::Relaxed);
    }
    
    fn set_public_ip(&self, addr: SocketAddr) {
        *self.public_ip.lock().unwrap() = Some(addr);
    }
}

// --- 网络探针 (Active Probing) ---
// 由于 Node 内部状态私有，我们通过 Handle 主动发起 DHT 查询来评估网络健康度
async fn probe_network(handle: &EtpHandle, self_id: NodeID) -> (usize, u64) {
    let start = Instant::now();
    // 1. 查自己 (检查入站连通性和最近邻居)
    let self_lookup = handle.dht_find_node(self_id).await;
    
    // 2. 查随机目标 (检查路由深度)
    let random_id: NodeID = rand::random();
    let rand_lookup = handle.dht_find_node(random_id).await;
    
    let rtt = start.elapsed().as_millis() as u64;
    
    let mut unique_peers = std::collections::HashSet::new();
    if let Ok(nodes) = self_lookup {
        for n in nodes { unique_peers.insert(n.id); }
    }
    if let Ok(nodes) = rand_lookup {
        for n in nodes { unique_peers.insert(n.id); }
    }
    
    (unique_peers.len(), rtt)
}

// --- 主程序 ---

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Setup
    let cli = Cli::parse();
    
    if cli.headless {
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    } else {
        // TUI 模式下禁用标准 Log 输出到 stdout，改为文件或仅 Error
        // 这里简化：为了不破坏 TUI，我们暂时只记录 Error
        env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();
    }

    std::fs::create_dir_all(&cli.data_dir)?;

    // 2. Identity
    let keys = load_or_create_identity(&cli.identity)?;
    let my_node_id = blake3::hash(&keys.public).into();
    let my_node_id_hex = hex::encode(my_node_id);

    // 3. Configure Engine
    let config = NodeConfig {
        bind_addr: cli.bind.clone(),
        keypair: keys.clone(),
        // Bootstrap 节点使用 Turbo 模式以最大化吞吐量处理路由请求
        profile: SecurityProfile::Turbo, 
        bootstrap_peers: vec![], 
        default_dialect: "etp.dialect.noise.std".to_string(),
        default_flavor: "etp.flavor.core".to_string(),
        stateless_secret: rand::random(),
    };

    // 4. Registry
    let registry = Arc::new(PluginRegistry::new());
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect));
    registry.register_flavor(Arc::new(etp_core::plugin::StandardFlavor));
    // Bootstrap node usually runs TNS/DHT logic implicitly via Engine, no specific flavor needed if just routing.
    // But we can add TNS flavor to act as a seeder.
    let (dht_tx, mut dht_rx) = tokio::sync::mpsc::channel(1024);
    let (net_tx, mut net_rx) = tokio::sync::mpsc::channel(1024);
    
    // Stub Flavor execution (Blackhole for demo logic, relying on internal DHT)
    tokio::spawn(async move {
        while let Some(_) = dht_rx.recv().await {}
    });
    tokio::spawn(async move {
        while let Some(_) = net_rx.recv().await {}
    });

    // 5. Start Engine
    let (engine, handle, _) = EtpEngine::new(config, registry).await?;
    
    // Daemon Task
    tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            error!("CRITICAL: Engine stopped: {}", e);
            std::process::exit(1);
        }
    });

    // 6. Metrics & Monitoring
    let metrics = Arc::new(tokio::sync::Mutex::new(SentinelMetrics::new()));
    
    // Task: NAT Traversal
    let port: u16 = cli.bind.split(':').last().unwrap_or("4433").parse().unwrap_or(4433);
    let m_nat = metrics.clone();
    tokio::spawn(async move {
        let mut nat = NatManager::new();
        // Loop retry UPnP every 30 mins
        loop {
            match nat.map_port_upnp(port, 3600) {
                Ok(addr) => {
                    m_nat.lock().await.set_public_ip(addr);
                },
                Err(_) => {
                    // Log internally
                }
            }
            time::sleep(Duration::from_secs(1800)).await;
        }
    });

    // Task: Network Probing (The "Get Metrics" implementation)
    let m_probe = metrics.clone();
    let h_probe = handle.clone();
    tokio::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(5)).await;
            let (peers, rtt) = probe_network(&h_probe, my_node_id).await;
            m_probe.lock().await.update_network_stats(peers, rtt);
        }
    });

    // 7. UI Loop (Main Thread)
    if cli.headless {
        info!("ETP Sentinel running in headless mode.");
        loop {
            time::sleep(Duration::from_secs(60)).await;
            let m = metrics.lock().await;
            info!("Status: Alive | Peers: {} | RTT: {}ms", 
                m.known_peers_estimate.load(Ordering::Relaxed),
                m.last_rtt_ms.load(Ordering::Relaxed)
            );
        }
    } else {
        run_tui_dashboard(metrics, &cli.bind, &my_node_id_hex).await?;
    }

    Ok(())
}

// --- TUI Dashboard Implementation ---

async fn run_tui_dashboard(metrics: Arc<tokio::sync::Mutex<SentinelMetrics>>, bind: &str, node_id: &str) -> Result<()> {
    // Clear Screen
    print!("\x1B[2J\x1B[1;1H");
    
    let mut interval = time::interval(Duration::from_millis(1000));
    
    loop {
        interval.tick().await;
        
        let mut m = metrics.lock().await;
        m.update_system_stats();
        
        let uptime = m.start_time.elapsed().as_secs();
        let uptime_str = format!("{:02}:{:02}:{:02}", uptime / 3600, (uptime % 3600) / 60, uptime % 60);
        
        let cpu_usage = m.sys.global_cpu_info().cpu_usage();
        let ram_used = m.sys.used_memory() / 1024 / 1024;
        let ram_total = m.sys.total_memory() / 1024 / 1024;
        
        let peers = m.known_peers_estimate.load(Ordering::Relaxed);
        let rtt = m.last_rtt_ms.load(Ordering::Relaxed);
        let pub_ip = m.public_ip.lock().unwrap().map(|a| a.to_string()).unwrap_or_else(|| "Detecting...".to_string());

        // Draw Dashboard using ANSI codes
        // Move to top-left
        print!("\x1B[H");
        
        println!("{}", "============================================================".blue().bold());
        println!("   {} v1.0   |   {}", "ETP SENTINEL".green().bold(), "SYSTEM ONLINE".blink().green());
        println!("{}", "============================================================".blue().bold());
        
        println!("\n{:<15} {}", "Node ID:".bold(), node_id.cyan());
        println!("{:<15} {}", "Bind Address:".bold(), bind.yellow());
        println!("{:<15} {}", "Public IP:".bold(), pub_ip.magenta());
        println!("{:<15} {}", "Uptime:".bold(), uptime_str);

        println!("\n{}", "--- System Resources ---".white().bold());
        println!("{:<15} {:.2}%", "CPU Usage:", cpu_usage);
        println!("{:<15} {} / {} MB", "RAM Usage:", ram_used, ram_total);

        println!("\n{}", "--- Network Health (Active Probing) ---".white().bold());
        println!("{:<15} {}", "DHT Neighbors:", format!("{}", peers).green());
        
        // RTT Color coding
        let rtt_colored = if rtt < 50 {
            format!("{} ms", rtt).green()
        } else if rtt < 200 {
            format!("{} ms", rtt).yellow()
        } else {
            format!("{} ms", rtt).red()
        };
        println!("{:<15} {}", "Self-Ping RTT:", rtt_colored);

        println!("\n{}", "============================================================".blue().bold());
        println!("Press {} to shutdown.", "Ctrl+C".red());
        
        std::io::stdout().flush()?;
    }
}
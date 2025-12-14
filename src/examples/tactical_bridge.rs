// etp-core/examples/tactical_bridge.rs

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use log::{info, warn, debug};
use env_logger::Env;
use anyhow::Result;
use serde::{Serialize, Deserialize};

use etp_core::network::node::{EtpEngine, NodeConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::plugin::{PluginRegistry, CapabilityProvider, Flavor, FlavorContext};
use etp_core::plugin::flavors::{
    composite::CompositeFlavor,
    router::RouterFlavor,
};
use etp_core::transport::reliability::MultiplexingMode;
use etp_core::transport::shaper::SecurityProfile;

// --- 协议定义 ---
const STREAM_VIDEO: u32 = 10;
const STREAM_CTRL: u32  = 20;

const ROUTE_TELEMETRY: u8 = 0x01;
const ROUTE_COMMAND: u8   = 0x02;
const ROUTE_HEARTBEAT: u8 = 0xFF;

// ============================================================================
//  1. 模拟业务 Flavors (Mock Implementation)
// ============================================================================

// --- A. Video Flavor (模拟大流量视频接收) ---
struct MockVideoFlavor {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, // 回传通道 (例如回传 ACK 或流控)
}
impl CapabilityProvider for MockVideoFlavor {
    fn capability_id(&self) -> String { "etp.mock.video.v1".into() }
}
impl Flavor for MockVideoFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 模拟视频解码：只记录长度，不关心内容
        debug!(">> [VIDEO STREAM] Recv Frame from {}: {} bytes", ctx.src_addr, data.len());
        // 在真实场景中，这里会将 data 写入 ffmpeg 管道
        true
    }
    fn on_connection_open(&self, _: SocketAddr) {}
    fn on_connection_close(&self, _: SocketAddr) {}
}

// --- B. Telemetry Flavor (模拟传感器数据接收) ---
struct MockTelemetryFlavor {
    tx: mpsc::Sender<(SocketAddr, String)>, // 解码后发给主逻辑
}
impl CapabilityProvider for MockTelemetryFlavor {
    fn capability_id(&self) -> String { "etp.mock.telemetry.v1".into() }
}
impl Flavor for MockTelemetryFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 模拟解析 GPS 坐标 (假设是 UTF8 字符串)
        let info = String::from_utf8_lossy(data).to_string();
        info!(">> [TELEMETRY] Sensor Update from {}: {}", ctx.src_addr, info);
        
        let tx = self.tx.clone();
        let addr = ctx.src_addr;
        tokio::spawn(async move {
            let _ = tx.send((addr, info)).await;
        });
        true
    }
    fn on_connection_open(&self, _: SocketAddr) {}
    fn on_connection_close(&self, _: SocketAddr) {}
}

// --- C. Command Flavor (模拟关键指令接收) ---
struct MockCommandFlavor {
    tx: mpsc::Sender<(SocketAddr, String)>,
}
impl CapabilityProvider for MockCommandFlavor {
    fn capability_id(&self) -> String { "etp.mock.cmd.v1".into() }
}
impl Flavor for MockCommandFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        let cmd = String::from_utf8_lossy(data).to_string();
        // 使用 Error 级别日志突出显示关键指令
        log::error!(">> [COMMAND] !!! CRITICAL SIGNAL FROM {} !!! : {}", ctx.src_addr, cmd);
        
        let tx = self.tx.clone();
        let addr = ctx.src_addr;
        tokio::spawn(async move {
            let _ = tx.send((addr, cmd)).await;
        });
        true
    }
    fn on_connection_open(&self, _: SocketAddr) {}
    fn on_connection_close(&self, _: SocketAddr) {}
}

// ============================================================================
//  2. 主程序
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // 启用详细日志以观察分流效果
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();
    info!("Starting Tactical Bridge Node (Video + Control Link)...");

    // 1. 准备身份
    let keys = KeyPair::generate();
    info!("Node ID: {}", hex::encode(blake3::hash(&keys.public).as_bytes()));

    // 2. 准备业务通道
    // Video 不需要上报给主循环，Flavor 内部消化了
    let (video_net_tx, _video_net_rx) = mpsc::channel(100); 
    
    // Telemetry 和 Command 需要上报
    let (telemetry_tx, mut telemetry_rx) = mpsc::channel(100);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(100);

    // 3. 构建 Flavors
    let video_flavor = Arc::new(MockVideoFlavor { tx: video_net_tx });
    let telemetry_flavor = Arc::new(MockTelemetryFlavor { tx: telemetry_tx });
    let cmd_flavor = Arc::new(MockCommandFlavor { tx: cmd_tx });

    // 4. === 核心：构建嵌套分流架构 ===

    // A. 组装内层 Router (Stream 20 的内部逻辑)
    // 负责解析 Header (0x01, 0x02...)
    let router = Arc::new(RouterFlavor::new());
    router.register_route(ROUTE_TELEMETRY, telemetry_flavor.clone());
    router.register_route(ROUTE_COMMAND, cmd_flavor.clone());
    // (Route 0xFF 心跳可以复用 Telemetry 或者用专门的 Flavor，这里省略)

    // B. 组装外层 Composite (全局入口)
    // 负责根据 Stream ID (10, 20) 分流
    // 默认流量设为 Video (假设大部分流量是视频)
    let composite = Arc::new(CompositeFlavor::new(video_flavor.clone()));
    
    // 绑定 Stream 10 -> Video Flavor (独占高速流)
    composite.bind_stream(STREAM_VIDEO, video_flavor.clone());
    
    // 绑定 Stream 20 -> Router Flavor (嵌套控制流)
    // 这是一个 Flavor 套 Flavor 的经典用法
    composite.bind_stream(STREAM_CTRL, router.clone());

    // 5. 注册到 Engine
    let registry = Arc::new(PluginRegistry::new());
    registry.register_dialect(Arc::new(etp_core::plugin::StandardDialect)); // 战术环境通常用 Standard (Noise) 以获最高性能
    registry.register_flavor(composite); // 只需注册顶层入口

    // 6. 配置节点
    let config = NodeConfig {
        bind_addr: "0.0.0.0:6688".to_string(),
        keypair: keys,
        
        // !!! 关键配置 !!!
        // 必须开启 ParallelMulti (多流模式)。
        // 如果开启 StrictSingle，那么 Stream 10 和 Stream 20 会被强制排队。
        // 一旦视频卡顿，控制指令也会卡顿，这是战术节点不可接受的。
        // 开启 ParallelMulti 后，Stream 20 拥有独立的重组缓冲区，互不干扰。
        multiplexing_mode: MultiplexingMode::ParallelMulti,
        
        // 战术节点通常不在乎流量特征分析，只在乎低延迟
        profile: SecurityProfile::Turbo, 
        
        default_dialect: "etp.dialect.noise.std".to_string(),
        default_flavor: "etp.flavor.composite.v1".to_string(),
        
        ..NodeConfig::default()
    };

    let (engine, handle, _) = EtpEngine::new(config, registry).await?;

    // 7. 模拟业务处理主循环
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some((src, gps)) = telemetry_rx.recv() => {
                    // 处理遥测数据 (例如存库，或在地图上更新位置)
                    // 这里仅打印
                    debug!("Dashboard Update: Unit {} at {}", src, gps);
                }
                Some((src, cmd)) = cmd_rx.recv() => {
                    // 处理高优先级指令
                    warn!("ACTION REQUIRED: Execute command '{}' from {}", cmd, src);
                    
                    // 模拟回发确认 (ACK)
                    // 注意：回发时必须严格构造数据包结构
                    // 结构：Stream 20 -> Header 0x02 -> "ACK: ..."
                    let mut resp_payload = vec![ROUTE_COMMAND]; // Header
                    resp_payload.extend_from_slice(format!("ACK: {}", cmd).as_bytes());
                    
                    let _ = handle.send_stream(src, STREAM_CTRL, resp_payload).await;
                }
            }
        }
    });

    info!("Tactical Bridge Running.");
    info!("architecture: Composite( Stream 10: Video | Stream 20: Router( 0x01:Tele | 0x02:Cmd ) )");
    
    // 8. 运行
    engine.run().await?;

    Ok(())
}
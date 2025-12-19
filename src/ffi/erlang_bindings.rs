// etp-core/src/ffi/erlang_bindings.rs

#![cfg(feature = "binding-erlang")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;

use rustler::{
    Env, Term, Encoder, NifResult, Atom, Error as NifError, 
    ResourceArc, LocalPid, OwnedEnv, Binary, NewBinary
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use lazy_static::lazy_static;
use log::{info, error, debug};

// 引入 ETP 核心
use crate::network::node::{EtpEngine, NodeConfig, EtpHandle, DeepAnonymityConfig, DeepSecurityConfig};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider, Dialect};
use crate::transport::shaper::SecurityProfile;
use crate::transport::reliability::MultiplexingMode;
use crate::crypto::noise::KeyPair;

// ============================================================================
//  1. Atoms 定义 (Erlang/Elixir 的常量)
// ============================================================================

rustler::atoms! {
    ok,
    error,
    // 事件类型
    etp_data,           // {etp_data, StreamID, SrcIP, BinaryData}
    etp_connected,      // {etp_connected, PeerIP}
    etp_disconnected,   // {etp_disconnected, PeerIP}
    // 配置项
    strict_single,
    parallel_multi,
    turbo,
    balanced,
    paranoid,
    // 错误类型
    config_error,
    engine_error,
    timeout,
}

// ============================================================================
//  2. 全局运行时与资源包装
//  BEAM 调度器是抢占式的，不能阻塞。我们使用独立的 Tokio Runtime 运行 ETP。
// ============================================================================

static TOKIO: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4) // 根据 ETP 负载调整，通常 4 个足以跑满 10Gbps
            .enable_all()
            .build()
            .expect("Failed to start Tokio runtime for ETP NIF")
    })
}

/// 包装 EtpHandle 供 Elixir 持有 (Opaque Reference)
struct EtpNodeResource {
    handle: EtpHandle,
    // 我们不需要持有 Engine 的 JoinHandle，因为它是 detach 运行的 (Let it crash)
}

// ============================================================================
//  3. 核心：Erlang Proxy Flavor (灵魂伴侣模式)
//  这是 ETP Flavor 与 Erlang Process 的连接点。
// ============================================================================

/// 将 ETP 的流量直接投递给指定的 Erlang PID
struct ErlangProxyFlavor {
    owner_pid: LocalPid,
    // 用于向 PID 发送消息的独立 Env (线程安全)
    // 注意：Rustler 的 LocalPid 只能在创建它的线程使用，
    // 这里为了简化演示，我们假设 Flavor 调用就在回调线程，或者我们需要使用 OwnedEnv。
    // 正确的做法是存储 owner_pid，并在 callback 中使用 OwnedEnv 发送。
}

impl ErlangProxyFlavor {
    fn new(pid: LocalPid) -> Arc<Self> {
        Arc::new(Self { owner_pid: pid })
    }

    /// 核心魔法：将 Rust 数据转为 Erlang 消息
    fn send_to_erlang(&self, msg_builder: impl FnOnce(Env) -> Term) {
        let pid = self.owner_pid.clone();
        let mut msg_env = OwnedEnv::new();
        
        msg_env.send_and_clear(&pid, |env| {
            msg_builder(env)
        });
    }
}

impl CapabilityProvider for ErlangProxyFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.erlang.proxy.v1".into()
    }
}

impl Flavor for ErlangProxyFlavor {
    fn priority(&self) -> u8 { 255 } // 最高优先级，接管所有流量

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 这是一个极高频调用的热路径
        // 我们需要做的是 Zero-Copy (尽可能) 地将数据扔给 Erlang VM
        
        let src_addr = ctx.src_addr.to_string();
        let stream_id = ctx.stream_id;
        
        // 我们必须拷贝数据到 Erlang 的堆/Binary 中
        // Rustler 的 NewBinary 会分配 Erlang 虚拟机管理的内存
        let data_vec = data.to_vec(); // 暂时拷贝，OwnedEnv closure 需要 move

        self.send_to_erlang(move |env| {
            // 构建 Binary
            let mut binary = NewBinary::new(env, data_vec.len());
            binary.as_mut_slice().copy_from_slice(&data_vec);
            
            // 消息格式: {:etp_data, stream_id, "1.2.3.4:80", <<...>>}
            let atom_tag = etp_data();
            let src_str = src_addr.encode(env);
            let bin_term = Binary::from(binary).to_term(env);
            
            (atom_tag, stream_id, src_str, bin_term).encode(env)
        });

        true // 表示我们已经消费了这条数据
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        let peer_str = peer.to_string();
        self.send_to_erlang(move |env| {
            (etp_connected(), peer_str).encode(env)
        });
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        let peer_str = peer.to_string();
        self.send_to_erlang(move |env| {
            (etp_disconnected(), peer_str).encode(env)
        });
    }
}

// ============================================================================
//  4. 配置解析器 (Elixir Map -> Rust Struct)
// ============================================================================

fn parse_config(env: Env, options: Term) -> NifResult<NodeConfig> {
    // 默认配置
    let mut config = NodeConfig::default();
    
    // 使用 Rustler 的 Map Iterator 解析
    // 这里为了代码紧凑，只展示关键字段的解析逻辑
    
    // 1. Bind Address
    if let Ok(addr) = options.map_get(rustler::types::atom::ok().to_term(env)) {
        // 示例：实际应查找 key 为 :bind_addr 的值
    }
    
    // 假设 options 是一个 Map %{bind: "...", profile: :paranoid, ...}
    // 我们需要编写 decode 逻辑。
    
    // 手动解析示例：
    let keys: HashMap<String, Term> = options.decode()?;
    
    if let Some(bind) = keys.get("bind") {
        config.bind_addr = bind.decode()?;
    }

    if let Some(prof) = keys.get("profile") {
        if prof.as_ref() == paranoid() {
            config.profile = SecurityProfile::Paranoid { 
                interval_ms: 20, target_size: 1350 
            };
        } else if prof.as_ref() == turbo() {
            config.profile = SecurityProfile::Turbo;
        }
    }

    if let Some(mux) = keys.get("mux") {
        if mux.as_ref() == strict_single() {
            config.multiplexing_mode = MultiplexingMode::StrictSingle;
        } else {
            config.multiplexing_mode = MultiplexingMode::ParallelMulti;
        }
    }

    // 深度匿名配置解析
    if let Some(cover) = keys.get("enable_cover_traffic") {
        config.anonymity.enable_cover_traffic = cover.decode()?;
    }
    
    // 生成新身份 (Elixir 侧通常不传私钥，而是由 Rust 生成或从文件加载)
    // config.keypair = ... 

    Ok(config)
}

// ============================================================================
//  5. NIF 导出函数
// ============================================================================

/// 启动 ETP 节点
/// pid: 接收消息的 Elixir 进程 (通常是 self())
/// options: 配置 Map
#[rustler::nif]
fn start_node(env: Env, pid: LocalPid, options: Term) -> NifResult<Term> {
    let config = parse_config(env, options)?;
    
    // 1. 构建插件系统
    let registry = Arc::new(PluginRegistry::new());
    
    // 2. 注入标准方言 (Noise)
    registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
    
    // 3. ★★★ 注入 Erlang Proxy Flavor ★★★
    // 这是将 ETP 变成 Erlang Actor 的关键
    let proxy_flavor = ErlangProxyFlavor::new(pid);
    registry.register_flavor(proxy_flavor);
    
    // 强制配置使用该 Flavor
    let mut config = config;
    config.default_flavor = "etp.flavor.erlang.proxy.v1".to_string();

    // 4. 启动引擎
    let rt = get_runtime();
    let handle_result = rt.block_on(async {
        EtpEngine::new(config, registry).await
    });

    match handle_result {
        Ok((engine, handle, _rx)) => {
            // 5. 将 Engine 放入后台运行 (Let it run/crash)
            rt.spawn(async move {
                if let Err(e) = engine.run().await {
                    error!("ETP Engine NIF crashed: {}", e);
                    // 在这里，我们可以尝试向 owner_pid 发送崩溃消息
                }
            });

            // 6. 返回资源句柄给 Elixir
            let resource = ResourceArc::new(EtpNodeResource { handle });
            Ok((ok(), resource).encode(env))
        },
        Err(e) => {
            Ok((error(), e.to_string()).encode(env))
        }
    }
}

/// 发送数据
/// resource: start_node 返回的句柄
/// target: 目标 IP 字符串
/// data: 二进制数据
#[rustler::nif]
fn send_data(env: Env, resource: ResourceArc<EtpNodeResource>, target: String, data: Binary) -> NifResult<Term> {
    let handle = resource.handle.clone();
    let data_vec = data.as_slice().to_vec();
    let rt = get_runtime();

    // 异步发送，不阻塞 BEAM 调度器
    rt.spawn(async move {
        if let Ok(addr) = target.parse::<SocketAddr>() {
            let _ = handle.send_data(addr, data_vec).await;
        }
    });

    Ok(ok().encode(env))
}

/// 发送特定 Stream 数据 (多路复用)
#[rustler::nif]
fn send_stream(env: Env, resource: ResourceArc<EtpNodeResource>, target: String, stream_id: u32, data: Binary) -> NifResult<Term> {
    let handle = resource.handle.clone();
    let data_vec = data.as_slice().to_vec();
    let rt = get_runtime();

    rt.spawn(async move {
        if let Ok(addr) = target.parse::<SocketAddr>() {
            let _ = handle.send_stream(addr, stream_id, data_vec).await;
        }
    });

    Ok(ok().encode(env))
}

/// 主动连接
#[rustler::nif]
fn connect_peer(env: Env, resource: ResourceArc<EtpNodeResource>, target: String, pub_key_hex: String) -> NifResult<Term> {
    let handle = resource.handle.clone();
    let rt = get_runtime();

    // 这是一个有状态的操作，我们需要返回 Result
    // 但 NIF 必须立即返回。我们有两个选择：
    // 1. 返回 :ok，结果通过消息异步发回 (推荐)
    // 2. 使用 rustler::schedule (Dirty NIF)
    
    // 这里采用 Fire-and-forget 风格，因为连接成功后 Flavor 会收到 on_connection_open 回调
    rt.spawn(async move {
        if let Ok(addr) = target.parse::<SocketAddr>() {
            if let Ok(key) = hex::decode(&pub_key_hex) {
                if let Err(e) = handle.connect(addr, key).await {
                    error!("Connect failed: {}", e);
                }
            }
        }
    });

    Ok(ok().encode(env))
}

/// 获取统计信息 (同步调用，因为很快)
#[rustler::nif]
fn get_stats(env: Env, resource: ResourceArc<EtpNodeResource>) -> NifResult<Term> {
    let handle = resource.handle.clone();
    let rt = get_runtime();
    
    // 等待结果，可能会轻微阻塞调度器，但在 get_stats 这种低频操作中可接受
    let stats_str = rt.block_on(async {
        handle.get_stats().await.unwrap_or("Error".to_string())
    });
    
    Ok(stats_str.encode(env))
}

/// 停止节点
#[rustler::nif]
fn stop_node(env: Env, resource: ResourceArc<EtpNodeResource>) -> NifResult<Term> {
    let handle = resource.handle.clone();
    let rt = get_runtime();
    rt.spawn(async move {
        let _ = handle.shutdown().await;
    });
    Ok(ok().encode(env))
}

// ============================================================================
//  6. 初始化 NIF
// ============================================================================

fn load(env: Env, _info: Term) -> bool {
    rustler::resource!(EtpNodeResource, env);
    true
}

rustler::init!(
    "Elixir.Etp.Native", // Elixir 端的模块名
    [
        start_node,
        send_data,
        send_stream,
        connect_peer,
        get_stats,
        stop_node
    ],
    load = load
);
// etp-core/src/ffi/mod.rs

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void, c_ulonglong, c_uint};
use std::sync::{Arc, OnceLock};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;
use std::net::SocketAddr;
use std::ptr;
use std::slice;

use tokio::runtime::Runtime;
use log::{Level, Metadata, Record, SetLoggerError};
use serde_json::json;

// 引入 ETP Core 内部模块
use crate::plugin::{
    Flavor, Dialect, FlavorContext, CapabilityProvider, PluginRegistry,
    Interceptor, InterceptorContext
};
use crate::network::node::{EtpEngine, NodeConfig, PacketHandler, PacketTransport, EtpHandle};
use crate::transport::congestion::CongestionControlAlgo;
use crate::transport::reliability::MultiplexingMode;
use crate::transport::shaper::SecurityProfile;

// ============================================================================
//  1. 语言特定超级绑定导出 (Module Exports)
//  根据 Cargo Features 按需编译，保持二进制纯净
// ============================================================================

// --- 主流应用开发 ---
#[cfg(feature = "binding-python")]
pub mod python_bindings;

#[cfg(feature = "binding-node")]
pub mod node_bindings;

#[cfg(feature = "binding-go")]
pub mod go_bindings;

#[cfg(feature = "binding-java")]
pub mod java_hybrid; // JNI + FFM 双重支持

#[cfg(feature = "binding-ruby")]
pub mod ruby_bindings;

// --- 高并发/虚拟机 ---
#[cfg(feature = "binding-erlang")]
pub mod erlang_bindings;

#[cfg(feature = "binding-lua")]
pub mod lua_bindings;

// --- Lisp 家族 ---
#[cfg(any(feature = "binding-lisp", feature = "binding-elisp"))]
pub mod lisp_bindings;

#[cfg(feature = "binding-scheme")]
pub mod scheme_bindings;

// --- 脚本与系统 ---
#[cfg(feature = "binding-perl")]
pub mod perl_bindings;

#[cfg(feature = "binding-shell")]
pub mod shell_bindings;

#[cfg(feature = "binding-powershell")]
pub mod powershell_bindings;

// --- 新兴与高性能 ---
#[cfg(feature = "binding-zig")]
pub mod zig_bindings;

#[cfg(feature = "binding-experimental")]
pub mod experimental_bindings; // Nushell, Ring, Haxe, Fusion, Carbon

// --- 编辑器集成 ---
#[cfg(feature = "binding-vim")]
pub mod vim_bindings;

// ============================================================================
//  2. 通用 C ABI - 全局状态管理
// ============================================================================

// 运行时单例
static GLOBAL_RUNTIME: OnceLock<Runtime> = OnceLock::new();
// 节点句柄单例
static GLOBAL_HANDLE: OnceLock<EtpHandle> = OnceLock::new();
// 回调表单例
static GLOBAL_CBS: OnceLock<EtpCallbacks> = OnceLock::new();
// 日志回调
static GLOBAL_LOG_CB: OnceLock<extern "C" fn(level: c_int, msg: *const c_char)> = OnceLock::new();

/// 获取或初始化 Tokio Runtime
fn get_runtime() -> &'static Runtime {
    GLOBAL_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4) // 生产级配置：4 Worker 线程
            .enable_all()
            .build()
            .expect("ETP-FFI: Failed to initialize Tokio Runtime")
    })
}

// ============================================================================
//  3. 通用 C ABI - 数据结构与回调定义
// ============================================================================

/// 跨语言回调函数表 (VTable)
/// 允许宿主语言全面接管 ETP 的核心逻辑
#[repr(C)]
pub struct EtpCallbacks {
    /// 宿主上下文指针 (User Data)，透传给所有回调
    pub user_data: *mut c_void,

    // --- 业务层 (Flavor) ---
    /// 收到流数据: return 1=Handled, 0=Pass
    pub on_stream_data: extern "C" fn(ctx: *mut c_void, stream_id: u32, src_ip: *const c_char, data: *const u8, len: usize) -> c_int,
    /// 连接建立
    pub on_peer_connected: extern "C" fn(ctx: *mut c_void, peer_ip: *const c_char),
    /// 连接断开
    pub on_peer_disconnected: extern "C" fn(ctx: *mut c_void, peer_ip: *const c_char),

    // --- 协议层 (Dialect) ---
    /// 加密/混淆: 原地修改 data，返回新长度。cap 是 buffer 容量。
    pub dialect_seal: extern "C" fn(ctx: *mut c_void, data: *mut u8, len: usize, cap: usize) -> usize,
    /// 解密/去混淆: 从 data 读，写入 out。返回写入长度。
    pub dialect_open: extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize, out: *mut u8, out_cap: usize) -> usize,

    // --- 传输层 (Packet Handler) ---
    /// 原始包拦截: return 1=Drop/Handled, 0=Continue
    pub handler_raw_packet: extern "C" fn(ctx: *mut c_void, src_ip: *const c_char, data: *const u8, len: usize) -> c_int,

    // --- 拥塞控制 (Congestion Control Strategy) ---
    // 宿主语言实现 CC 算法的状态机
    /// 创建算法实例: 返回 instance_ptr
    pub cc_new: extern "C" fn(ctx: *mut c_void) -> *mut c_void,
    /// 销毁算法实例
    pub cc_drop: extern "C" fn(instance: *mut c_void),
    /// 包发送事件
    pub cc_on_sent: extern "C" fn(instance: *mut c_void, amount: usize, bytes: usize),
    /// ACK 事件
    pub cc_on_ack: extern "C" fn(instance: *mut c_void, amount: usize, rtt_micros: c_ulonglong),
    /// 丢包事件
    pub cc_on_loss: extern "C" fn(instance: *mut c_void),
    /// 检查是否允许发送: return 1=Yes, 0=No
    pub cc_can_send: extern "C" fn(instance: *mut c_void, bytes_inflight: c_ulonglong) -> c_int,
    /// 获取 Pacing 延迟 (微秒)
    pub cc_pacing_delay: extern "C" fn(instance: *mut c_void) -> c_ulonglong,
    /// 获取 RTO (微秒)
    pub cc_get_rto: extern "C" fn(instance: *mut c_void) -> c_ulonglong,
    /// 获取 MSS
    pub cc_get_mss: extern "C" fn(instance: *mut c_void) -> c_ulonglong,
}

// ============================================================================
//  4. 通用 C ABI - 导出函数 (Exported Functions)
// ============================================================================

/// 1. 初始化 ETP 库并注册回调
/// 返回: 0=Success, -1=Already Init
#[no_mangle]
pub extern "C" fn etp_init(cbs: EtpCallbacks) -> c_int {
    if GLOBAL_CBS.set(cbs).is_err() {
        return -1;
    }
    // 同时也初始化 Runtime
    let _ = get_runtime();
    0
}

/// 2. 注册日志重定向 (Log Redirection)
/// 将 Rust 内部日志 (Info/Warn/Error) 转发给宿主语言
/// level: 1=Error, 2=Warn, 3=Info, 4=Debug, 5=Trace
#[no_mangle]
pub extern "C" fn etp_init_logger(cb: extern "C" fn(c_int, *const c_char)) -> c_int {
    if GLOBAL_LOG_CB.set(cb).is_err() {
        return -1;
    }
    
    struct FfiLogger;
    impl log::Log for FfiLogger {
        fn enabled(&self, _metadata: &Metadata) -> bool { true }
        fn log(&self, record: &Record) {
            if let Some(cb) = GLOBAL_LOG_CB.get() {
                let lvl = match record.level() {
                    Level::Error => 1,
                    Level::Warn => 2,
                    Level::Info => 3,
                    Level::Debug => 4,
                    Level::Trace => 5,
                };
                let s = CString::new(format!("{}", record.args())).unwrap_or_default();
                cb(lvl, s.as_ptr());
            }
        }
        fn flush(&self) {}
    }

    // 设置全局 Logger
    static LOGGER: FfiLogger = FfiLogger;
    if log::set_logger(&LOGGER).map(|()| log::set_max_level(log::LevelFilter::Trace)).is_err() {
        return -2;
    }
    0
}

/// 3. 启动节点 (阻塞调用，直到 Engine 停止)
/// bind_addr: "0.0.0.0:443"
/// 返回: 0=Success, -1=Error, -2=Panic
#[no_mangle]
pub extern "C" fn etp_start_node(bind_addr: *const c_char) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let rt = get_runtime();
        
        let c_str = unsafe { CStr::from_ptr(bind_addr) };
        let bind_str = c_str.to_string_lossy().to_string();

        rt.block_on(async {
            // 构建配置
            let mut config = NodeConfig::default();
            config.bind_addr = bind_str;
            
            // 默认配置为 FFI 模式
            config.default_flavor = "etp.flavor.ffi.v1".to_string();
            config.default_dialect = "etp.dialect.ffi.v1".to_string();
            config.congestion_algo = "etp.cc.ffi.v1".to_string(); // 使用 FFI 拥塞控制

            // 构建插件
            let registry = Arc::new(PluginRegistry::new());
            
            // 注册 FFI 代理插件
            registry.register_flavor(Arc::new(FfiFlavor));
            registry.register_dialect(Arc::new(FfiDialect));
            
            // 注册 FFI 拥塞控制构造器
            registry.register_congestion_mod("etp.cc.ffi.v1", || {
                Box::new(FfiCongestion::new())
            });

            // 启动引擎
            let (mut engine, handle, _) = match EtpEngine::new(config, registry).await {
                Ok(r) => r,
                Err(e) => {
                    log::error!("ETP Start Failed: {}", e);
                    return -1;
                }
            };

            // 设置句柄
            if GLOBAL_HANDLE.set(handle).is_err() {
                log::warn!("ETP Handle already set (Restarting?)");
            }

            // 设置 Raw Handler
            engine.set_default_handler(Arc::new(FfiHandler));

            log::info!("ETP Node Started via FFI.");
            
            // 运行主循环
            if let Err(e) = engine.run().await {
                log::error!("ETP Engine Crashed: {}", e);
                return -1;
            }
            0
        })
    }));

    match result {
        Ok(code) => code,
        Err(_) => -2,
    }
}

/// 4. 停止节点 (异步触发)
#[no_mangle]
pub extern "C" fn etp_stop_node() {
    if let Some(h) = GLOBAL_HANDLE.get() {
        let h = h.clone();
        get_runtime().spawn(async move {
            let _ = h.shutdown().await;
        });
    }
}

/// 5. 发送应用数据 (标准流, Stream ID = 1)
#[no_mangle]
pub extern "C" fn etp_send(target_ip: *const c_char, data: *const u8, len: usize) -> c_int {
    etp_send_stream(target_ip, 1, data, len)
}

/// 6. 发送多路复用数据 (指定 Stream ID)
#[no_mangle]
pub extern "C" fn etp_send_stream(target_ip: *const c_char, stream_id: u32, data: *const u8, len: usize) -> c_int {
    let handle = match GLOBAL_HANDLE.get() { Some(h) => h, None => return -1 };
    
    // Copy data to Rust heap
    let c_str = unsafe { CStr::from_ptr(target_ip) };
    let addr_str = c_str.to_string_lossy().to_string();
    let data_vec = unsafe { slice::from_raw_parts(data, len).to_vec() };
    
    let h = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            let _ = h.send_stream(addr, stream_id, data_vec).await;
        } else {
            log::error!("Invalid IP: {}", addr_str);
        }
    });
    0
}

/// 7. 发送控制指令 (Side Channel)
/// category: 1=Critical, 2=Heartbeat, 3=Metadata
#[no_mangle]
pub extern "C" fn etp_send_control(target_ip: *const c_char, category: u32, data: *const u8, len: usize) -> c_int {
    let handle = match GLOBAL_HANDLE.get() { Some(h) => h, None => return -1 };
    
    let c_str = unsafe { CStr::from_ptr(target_ip) };
    let addr_str = c_str.to_string_lossy().to_string();
    let data_vec = unsafe { slice::from_raw_parts(data, len).to_vec() };
    
    use crate::plugin::flavors::control::{ControlCategory, CHANNEL_CRITICAL, CHANNEL_HEARTBEAT, CHANNEL_METADATA};
    let cat = match category {
        1 => ControlCategory::Critical,
        2 => ControlCategory::Heartbeat,
        3 => ControlCategory::Metadata,
        _ => ControlCategory::Custom(category),
    };

    let h = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            let _ = h.send_control_cmd(addr, cat, data_vec).await;
        }
    });
    0
}

/// 8. 主动连接对等点 (Manual Connect)
#[no_mangle]
pub extern "C" fn etp_connect(target_ip: *const c_char, pub_key_hex: *const c_char) -> c_int {
    let handle = match GLOBAL_HANDLE.get() { Some(h) => h, None => return -1 };
    
    let ip_str = unsafe { CStr::from_ptr(target_ip).to_string_lossy().to_string() };
    let key_str = unsafe { CStr::from_ptr(pub_key_hex).to_string_lossy().to_string() };
    
    let h = handle.clone();
    get_runtime().spawn(async move {
        if let (Ok(addr), Ok(key)) = (ip_str.parse::<SocketAddr>(), hex::decode(&key_str)) {
            let _ = h.connect(addr, key).await;
        }
    });
    0
}

/// 9. 获取节点统计信息 (JSON 格式)
/// 返回的字符串需要调用 etp_free_string 释放
#[no_mangle]
pub extern "C" fn etp_get_metrics_json() -> *mut c_char {
    let handle = match GLOBAL_HANDLE.get() { Some(h) => h, None => return ptr::null_mut() };
    
    // 同步等待结果
    let res = get_runtime().block_on(async {
        handle.get_stats().await.unwrap_or("{}".into())
    });
    
    // 转换为 JSON 对象 (假设 get_stats 返回的是 raw string，这里包装一下)
    let json_obj = json!({ "raw": res }).to_string();
    
    CString::new(json_obj).unwrap().into_raw()
}

/// 10. 释放 Rust 字符串内存
#[no_mangle]
pub extern "C" fn etp_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

// ============================================================================
//  5. 内部 Proxy 实现 (The Glue)
//  将 Rust Trait 调用转发给 C Callbacks
// ============================================================================

// --- Flavor Proxy ---
#[derive(Debug)]
struct FfiFlavor;
impl CapabilityProvider for FfiFlavor { fn capability_id(&self) -> String { "etp.flavor.ffi.v1".into() } }
impl Flavor for FfiFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let c_src = CString::new(ctx.src_addr.to_string()).unwrap_or_default();
            let res = (cbs.on_stream_data)(
                cbs.user_data,
                ctx.stream_id,
                c_src.as_ptr(),
                data.as_ptr(),
                data.len()
            );
            return res != 0;
        }
        false
    }
    fn on_connection_open(&self, peer: SocketAddr) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let c_peer = CString::new(peer.to_string()).unwrap_or_default();
            (cbs.on_peer_connected)(cbs.user_data, c_peer.as_ptr());
        }
    }
    fn on_connection_close(&self, peer: SocketAddr) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let c_peer = CString::new(peer.to_string()).unwrap_or_default();
            (cbs.on_peer_disconnected)(cbs.user_data, c_peer.as_ptr());
        }
    }
}

// --- Dialect Proxy ---
#[derive(Debug)]
struct FfiDialect;
impl CapabilityProvider for FfiDialect { fn capability_id(&self) -> String { "etp.dialect.ffi.v1".into() } }
impl Dialect for FfiDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            // Reserve extra space for C modification
            payload.reserve(1024);
            let new_len = (cbs.dialect_seal)(
                cbs.user_data,
                payload.as_mut_ptr(),
                payload.len(),
                payload.capacity()
            );
            unsafe { payload.set_len(new_len); }
        }
    }
    fn open(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let mut out = Vec::with_capacity(data.len());
            let new_len = (cbs.dialect_open)(
                cbs.user_data,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.capacity()
            );
            if new_len > 0 {
                unsafe { out.set_len(new_len); }
                return Ok(out);
            }
        }
        Err(anyhow::anyhow!("FFI Dialect Error"))
    }
    fn probe(&self, _data: &[u8]) -> bool { true } // Accept all for FFI
}

// --- Handler Proxy ---
struct FfiHandler;
impl PacketHandler for FfiHandler {
    fn handle<'a>(&'a self, data: &'a [u8], src: SocketAddr, _t: &'a Arc<dyn PacketTransport>) 
        -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> 
    {
        Box::pin(async move {
            if let Some(cbs) = GLOBAL_CBS.get() {
                let c_src = CString::new(src.to_string()).unwrap_or_default();
                let res = (cbs.handler_raw_packet)(
                    cbs.user_data,
                    c_src.as_ptr(),
                    data.as_ptr(),
                    data.len()
                );
                return res != 0;
            }
            false
        })
    }
}

// --- Congestion Control Proxy ---
#[derive(Debug)]
struct FfiCongestion {
    instance: *mut c_void, // C-Side Instance Pointer
}
unsafe impl Send for FfiCongestion {}
unsafe impl Sync for FfiCongestion {}

impl FfiCongestion {
    fn new() -> Self {
        let ptr = if let Some(cbs) = GLOBAL_CBS.get() {
            (cbs.cc_new)(cbs.user_data)
        } else {
            ptr::null_mut()
        };
        Self { instance: ptr }
    }
}

impl Drop for FfiCongestion {
    fn drop(&mut self) {
        if !self.instance.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                (cbs.cc_drop)(self.instance);
            }
        }
    }
}

impl CongestionControlAlgo for FfiCongestion {
    fn on_packet_sent(&mut self, amount: usize, bytes: usize) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            (cbs.cc_on_sent)(self.instance, amount, bytes);
        }
    }
    fn on_ack_received(&mut self, amount: usize, rtt: Option<Duration>) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let us = rtt.map(|d| d.as_micros() as u64).unwrap_or(0);
            (cbs.cc_on_ack)(self.instance, amount, us);
        }
    }
    fn on_packet_lost(&mut self) {
        if let Some(cbs) = GLOBAL_CBS.get() { (cbs.cc_on_loss)(self.instance); }
    }
    fn can_send(&self, inflight: u64) -> bool {
        if let Some(cbs) = GLOBAL_CBS.get() {
            return (cbs.cc_can_send)(self.instance, inflight) != 0;
        }
        true
    }
    fn get_pacing_delay(&self) -> Duration {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let us = (cbs.cc_pacing_delay)(self.instance);
            return Duration::from_micros(us);
        }
        Duration::ZERO
    }
    fn get_rto(&self) -> Duration {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let us = (cbs.cc_get_rto)(self.instance);
            return Duration::from_micros(us);
        }
        Duration::from_millis(300)
    }
    fn get_mss(&self) -> u64 {
        if let Some(cbs) = GLOBAL_CBS.get() {
            return (cbs.cc_get_mss)(self.instance) as u64;
        }
        1350
    }
}
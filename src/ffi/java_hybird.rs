// etp-core/src/ffi/java_hybrid.rs

#![cfg(feature = "binding-java")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int};
use std::slice;
use std::time::Duration;

// --- JNI 依赖 ---
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString, JValue, GlobalRef, JByteBuffer};
use jni::sys::{jint, jlong, jboolean, JNI_VERSION_1_6};
use jni::JavaVM;

// --- ETP 核心依赖 ---
use tokio::runtime::Runtime;
use lazy_static::lazy_static;
use log::{info, error, debug, warn, Level};
use serde::{Deserialize, Serialize};

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};
use crate::transport::shaper::SecurityProfile;
use crate::transport::reliability::MultiplexingMode;

// ============================================================================
//  1. 全局基础设施 (Infrastructure)
// ============================================================================

static mut JVM_PTR: Option<JavaVM> = None;
static TOKIO: OnceLock<Runtime> = OnceLock::new();

#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {
    unsafe { JVM_PTR = Some(vm); }
    // 默认初始化 env_logger，但会被下面的 LogBridge 覆盖
    let _ = env_logger::try_init();
    JNI_VERSION_1_6
}

fn get_jvm() -> Option<&'static JavaVM> {
    unsafe { JVM_PTR.as_ref() }
}

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("Failed to start Tokio Runtime")
    })
}

// ============================================================================
//  2. 统一回调抽象 (Unified Callback Trait)
//  无论是 JNI 对象还是 FFM 函数指针，都适配到此接口
// ============================================================================

trait JavaCallback: Send + Sync {
    fn on_data(&self, stream_id: i32, src: &str, data: &[u8]);
    fn on_event(&self, event_type: i32, msg: &str); // 1=Conn, 0=Disconn, -1=Error
    fn on_log(&self, level: i32, msg: &str); // 1=Error, 2=Warn, 3=Info, 4=Debug
}

// --- 实现 A: JNI 回调 (Android / Legacy Java) ---
struct JniCallbackImpl {
    listener: GlobalRef,
}

impl JniCallbackImpl {
    fn with_env<F>(&self, f: F) 
    where F: FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<()> 
    {
        if let Some(jvm) = get_jvm() {
            match jvm.attach_current_thread() {
                Ok(mut env) => {
                    if let Err(e) = f(&mut env, self.listener.as_obj()) {
                        error!("JNI Callback Failed: {:?}", e);
                        let _ = env.exception_describe(); // 打印 Java 堆栈
                        let _ = env.exception_clear();
                    }
                }
                Err(e) => error!("JVM Attach Failed: {:?}", e),
            }
        }
    }
}

impl JavaCallback for JniCallbackImpl {
    fn on_data(&self, stream_id: i32, src: &str, data: &[u8]) {
        // 数据拷贝不可避免 (JVM GC 机制限制)
        let data_vec = data.to_vec(); 
        let src_str = src.to_string();
        
        self.with_env(move |env, listener| {
            let j_src = env.new_string(&src_str)?;
            let j_bytes = env.byte_array_from_slice(&data_vec)?;
            env.call_method(
                listener, "onStreamData", "(ILjava/lang/String;[B)V",
                &[JValue::Int(stream_id), JValue::Object(&j_src.into()), JValue::Object(&j_bytes.into())]
            )?;
            Ok(())
        });
    }

    fn on_event(&self, event_type: i32, msg: &str) {
        let msg_str = msg.to_string();
        self.with_env(move |env, listener| {
            let j_msg = env.new_string(&msg_str)?;
            env.call_method(
                listener, "onEvent", "(ILjava/lang/String;)V",
                &[JValue::Int(event_type), JValue::Object(&j_msg.into())]
            )?;
            Ok(())
        });
    }

    fn on_log(&self, level: i32, msg: &str) {
        let msg_str = msg.to_string();
        self.with_env(move |env, listener| {
            let j_msg = env.new_string(&msg_str)?;
            env.call_method(
                listener, "onLog", "(ILjava/lang/String;)V",
                &[JValue::Int(level), JValue::Object(&j_msg.into())]
            )?;
            Ok(())
        });
    }
}

// --- 实现 B: FFM 回调 (Java 22+ / Server) ---
type FfmDataFn = extern "C" fn(i32, *const c_char, *const u8, i32);
type FfmEventFn = extern "C" fn(i32, *const c_char);
type FfmLogFn = extern "C" fn(i32, *const c_char);

struct FfmCallbackImpl {
    cb_data: FfmDataFn,
    cb_event: FfmEventFn,
    cb_log: FfmLogFn,
}

// 手动标记 Send/Sync，调用者需保证函数指针在多线程下安全 (Java FFM Upcall Stubs 是安全的)
unsafe impl Send for FfmCallbackImpl {}
unsafe impl Sync for FfmCallbackImpl {}

impl JavaCallback for FfmCallbackImpl {
    fn on_data(&self, stream_id: i32, src: &str, data: &[u8]) {
        let c_src = CString::new(src).unwrap_or_default();
        (self.cb_data)(stream_id, c_src.as_ptr(), data.as_ptr(), data.len() as i32);
    }
    fn on_event(&self, event_type: i32, msg: &str) {
        let c_msg = CString::new(msg).unwrap_or_default();
        (self.cb_event)(event_type, c_msg.as_ptr());
    }
    fn on_log(&self, level: i32, msg: &str) {
        let c_msg = CString::new(msg).unwrap_or_default();
        (self.cb_log)(level, c_msg.as_ptr());
    }
}

// ============================================================================
//  3. 混合 Flavor (Business Logic)
// ============================================================================

struct HybridFlavor {
    callback: Arc<dyn JavaCallback>,
}

impl HybridFlavor {
    fn new(cb: Arc<dyn JavaCallback>) -> Arc<Self> {
        Arc::new(Self { callback: cb })
    }
}

impl CapabilityProvider for HybridFlavor { fn capability_id(&self) -> String { "etp.flavor.java.hybrid.v2".into() } }

impl Flavor for HybridFlavor {
    fn priority(&self) -> u8 { 255 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        self.callback.on_data(ctx.stream_id as i32, &ctx.src_addr.to_string(), data);
        true
    }
    fn on_connection_open(&self, peer: SocketAddr) {
        self.callback.on_event(1, &peer.to_string());
    }
    fn on_connection_close(&self, peer: SocketAddr) {
        self.callback.on_event(0, &peer.to_string());
    }
}

// ============================================================================
//  4. 日志桥接 (Log Bridge)
//  将 Rust Log 转发到 Java，这对 Android 开发至关重要
// ============================================================================

struct JavaLogBridge {
    callback: Arc<dyn JavaCallback>,
}

impl log::Log for JavaLogBridge {
    fn enabled(&self, _metadata: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        let level = match record.level() {
            Level::Error => 1,
            Level::Warn => 2,
            Level::Info => 3,
            Level::Debug => 4,
            Level::Trace => 5,
        };
        let msg = format!("{}", record.args());
        self.callback.on_log(level, &msg);
    }
    fn flush(&self) {}
}

fn init_log_bridge(callback: Arc<dyn JavaCallback>) {
    let logger = Box::new(JavaLogBridge { callback });
    // 设置最大日志级别，并忽略重复初始化的错误
    let _ = log::set_boxed_logger(logger).map(|()| log::set_max_level(log::LevelFilter::Debug));
}

// ============================================================================
//  5. 通用启动流程 (Common Logic)
// ============================================================================

// 简化配置 JSON，支持 Kotlin Data Class 序列化传参
#[derive(Deserialize, Default)]
struct JavaConfigJson {
    bind: Option<String>,
    profile: Option<String>, // "turbo", "balanced", "paranoid"
    multiplexing: Option<String>, // "single", "multi"
    cover_traffic: Option<bool>,
}

fn start_node_common(config_json: String, callback: Arc<dyn JavaCallback>) -> Result<jlong, String> {
    // 1. 初始化日志桥接
    init_log_bridge(callback.clone());

    // 2. 解析 JSON 配置
    let jcfg: JavaConfigJson = serde_json::from_str(&config_json)
        .map_err(|e| format!("JSON Config Error: {}", e))?;

    let mut config = NodeConfig::default();
    if let Some(b) = jcfg.bind { config.bind_addr = b; }
    
    if let Some(p) = jcfg.profile {
        config.profile = match p.as_str() {
            "turbo" => SecurityProfile::Turbo,
            "paranoid" => SecurityProfile::Paranoid { interval_ms: 20, target_size: 1350 },
            _ => SecurityProfile::Balanced,
        };
    }

    if let Some(m) = jcfg.multiplexing {
        config.multiplexing_mode = if m == "single" { MultiplexingMode::StrictSingle } else { MultiplexingMode::ParallelMulti };
    }
    
    if let Some(c) = jcfg.cover_traffic {
        config.anonymity.enable_cover_traffic = c;
    }

    config.default_flavor = "etp.flavor.java.hybrid.v2".to_string();

    // 3. 构建 Registry
    let registry = Arc::new(PluginRegistry::new());
    registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
    registry.register_flavor(HybridFlavor::new(callback));

    // 4. 启动 Engine
    let rt = get_runtime();
    let res = rt.block_on(async {
        EtpEngine::new(config, registry).await
    });

    match res {
        Ok((engine, handle, _)) => {
            rt.spawn(async move {
                if let Err(e) = engine.run().await {
                    error!("ETP Engine Crashed: {}", e);
                }
            });
            let ptr = Box::into_raw(Box::new(handle)) as jlong;
            Ok(ptr)
        },
        Err(e) => Err(e.to_string()),
    }
}

// ============================================================================
//  6. JNI 导出接口 (Android / Legacy)
// ============================================================================

/// JNI 启动: startNode(String jsonConfig, EtpListener listener) -> long handle
#[no_mangle]
pub extern "system" fn Java_com_etp_core_EtpNative_startNode(
    mut env: JNIEnv, _class: JClass, json_config: JString, listener: JObject
) -> jlong {
    let config_str: String = match env.get_string(&json_config) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let global_listener = match env.new_global_ref(listener) {
        Ok(g) => g,
        Err(_) => return 0,
    };

    let callback = Arc::new(JniCallbackImpl { listener: global_listener });

    match start_node_common(config_str, callback) {
        Ok(ptr) => ptr,
        Err(e) => {
            let _ = env.throw_new("java/io/IOException", e);
            0
        }
    }
}

/// JNI 零拷贝发送: sendDataDirect(long handle, String target, ByteBuffer data, int len)
/// 针对 DirectByteBuffer 优化，避免 JNI 层的数组拷贝
#[no_mangle]
pub extern "system" fn Java_com_etp_core_EtpNative_sendDataDirect(
    mut env: JNIEnv, _class: JClass, handle_ptr: jlong, target: JString, data: JByteBuffer, len: jint
) {
    if handle_ptr == 0 { return; }
    
    let target_str: String = env.get_string(&target).unwrap().into();
    
    // 获取 Direct Buffer 内存地址 (Unsafe, efficient)
    let data_ptr = env.get_direct_buffer_address(&data);
    
    let data_vec = if let Ok(ptr) = data_ptr {
        // Safety: 我们必须立即拷贝数据，因为 Rust 异步任务执行时，
        // Java 端的 Buffer 可能已经被回收或修改 (如果 Java 端没做 Pinning)。
        // 尽管是 Direct，为了异步安全，Rust 侧最好还是拥有数据。
        // 但这一步是在 Native 堆上拷贝，比 JNI 的 GetByteArrayRegion 快。
        unsafe { slice::from_raw_parts(ptr, len as usize).to_vec() }
    } else {
        // Fallback or error
        return;
    };

    let handle = unsafe { (*(handle_ptr as *mut EtpHandle)).clone() };
    let rt = get_runtime();

    rt.spawn(async move {
        if let Ok(addr) = target_str.parse::<SocketAddr>() {
            let _ = handle.send_data(addr, data_vec).await;
        }
    });
}

/// JNI 普通发送 (兼容性好)
#[no_mangle]
pub extern "system" fn Java_com_etp_core_EtpNative_sendData(
    mut env: JNIEnv, _class: JClass, handle_ptr: jlong, target: JString, data: jni::objects::JByteArray
) {
    if handle_ptr == 0 { return; }
    let target_str: String = env.get_string(&target).unwrap().into();
    let data_vec = env.convert_byte_array(data).unwrap_or_default();
    
    let handle = unsafe { (*(handle_ptr as *mut EtpHandle)).clone() };
    let rt = get_runtime();
    rt.spawn(async move {
        if let Ok(addr) = target_str.parse::<SocketAddr>() {
            let _ = handle.send_data(addr, data_vec).await;
        }
    });
}

/// JNI 释放
#[no_mangle]
pub extern "system" fn Java_com_etp_core_EtpNative_freeHandle(_env: JNIEnv, _class: JClass, ptr: jlong) {
    if ptr != 0 { unsafe { let _ = Box::from_raw(ptr as *mut EtpHandle); } }
}

// ============================================================================
//  7. FFM 导出接口 (Project Panama / Modern Server)
// ============================================================================

#[no_mangle]
pub extern "C" fn etp_ffm_start_node(
    json_config: *const c_char,
    cb_data: FfmDataFn,
    cb_event: FfmEventFn,
    cb_log: FfmLogFn
) -> jlong {
    let s = unsafe { CStr::from_ptr(json_config).to_string_lossy().to_string() };
    
    let callback = Arc::new(FfmCallbackImpl { cb_data, cb_event, cb_log });
    
    match start_node_common(s, callback) {
        Ok(ptr) => ptr,
        Err(e) => {
            error!("FFM Start Error: {}", e);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn etp_ffm_send_data(
    handle_ptr: jlong,
    target_ip: *const c_char,
    data_ptr: *const u8,
    data_len: i32
) {
    if handle_ptr == 0 { return; }
    let t_str = unsafe { CStr::from_ptr(target_ip).to_string_lossy().to_string() };
    let d_vec = unsafe { slice::from_raw_parts(data_ptr, data_len as usize).to_vec() };
    
    let handle = unsafe { (*(handle_ptr as *mut EtpHandle)).clone() };
    get_runtime().spawn(async move {
        if let Ok(addr) = t_str.parse() {
            let _ = handle.send_data(addr, d_vec).await;
        }
    });
}

#[no_mangle]
pub extern "C" fn etp_ffm_free_handle(ptr: jlong) {
    if ptr != 0 { unsafe { let _ = Box::from_raw(ptr as *mut EtpHandle); } }
}
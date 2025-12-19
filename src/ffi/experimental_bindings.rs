// etp-core/src/ffi/experimental_bindings.rs

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void, c_double};
use std::slice;

use tokio::runtime::Runtime;
use lazy_static::lazy_static;
use log::{error, info};

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, CapabilityProvider};

// ============================================================================
//  0. 全局基础设施 (Shared Runtime)
//  所有语言绑定共享同一个 Tokio 运行时和 ETP 句柄
// ============================================================================

static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("ETP: Failed to init Tokio Runtime")
    })
}

/// 通用启动逻辑：幂等启动，确保单例
fn ensure_etp_started(bind_addr: &str, flavor_id: &str) -> bool {
    // 1. 如果已启动，直接返回成功
    if HANDLE.get().is_some() { return true; }

    let rt = get_runtime();
    let bind_str = bind_addr.to_string();
    let flav_str = flavor_id.to_string();

    // 2. 阻塞初始化 (在主线程/调用线程中完成配置加载)
    let res = rt.block_on(async move {
        let mut cfg = NodeConfig::default();
        cfg.bind_addr = bind_str;
        cfg.default_flavor = flav_str;
        
        let reg = Arc::new(PluginRegistry::new());
        // 注册标准组件
        reg.register_dialect(Arc::new(crate::plugin::StandardDialect));
        reg.register_flavor(Arc::new(crate::plugin::StandardFlavor)); 
        
        EtpEngine::new(cfg, reg).await
    });

    // 3. 处理结果并 Spawn 守护任务
    match res {
        Ok((eng, h, _)) => {
            let _ = HANDLE.set(h);
            rt.spawn(async move {
                if let Err(e) = eng.run().await {
                    eprintln!("ETP Engine Background Error: {}", e);
                }
            });
            true
        },
        Err(e) => {
            eprintln!("ETP Engine Init Failed: {}", e);
            false
        }
    }
}

// ============================================================================
//  1. Nushell 支持 (JSON-RPC Protocol)
//  特性: binding-nushell
// ============================================================================

#[cfg(all(feature = "binding-experimental", feature = "binding-nushell"))]
pub mod nushell_impl {
    use super::*;
    use std::io::{self, BufRead, Write};
    use serde::{Serialize, Deserialize};
    use serde_json::{Value, json};

    // --- Nu Protocol Types ---

    #[derive(Deserialize, Debug)]
    #[serde(tag = "method")]
    enum NuRequest {
        #[serde(rename = "hello")]
        Hello { protocol: String, version: String, features: Vec<Value> },
        #[serde(rename = "quit")]
        Quit,
        #[serde(rename = "signature")]
        Signature,
        #[serde(rename = "run")]
        Run { name: String, call: NuCall, input: Value },
    }

    #[derive(Deserialize, Debug)]
    struct NuCall {
        head: Value, // Span info
        positional: Option<Vec<Value>>, // 位置参数
        named: Option<Vec<(String, Option<Value>)>>, // 命名参数
    }

    #[derive(Serialize)]
    struct NuResponseOk {
        Ok: Value,
    }

    /// Nushell 插件主入口
    #[no_mangle]
    pub extern "C" fn etp_nu_plugin_main() {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut lines = stdin.lock().lines();

        while let Some(Ok(line)) = lines.next() {
            // Nu 发送的每一行都是完整的 JSON 消息
            let req: NuRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    // 发送错误响应给 Nu，而不是崩溃
                    let err_json = json!({"Error": {"label": "JSON Parse Error", "msg": e.to_string()}});
                    writeln!(stdout, "{}", err_json).unwrap();
                    continue;
                }
            };

            match req {
                NuRequest::Hello { .. } => {
                    let resp = json!({
                        "Hello": {
                            "protocol": "nu-plugin", 
                            "version": "0.93.0", // 适配较新版本
                            "features": []
                        }
                    });
                    writeln!(stdout, "{}", resp).unwrap();
                },
                NuRequest::Quit => break,
                NuRequest::Signature => {
                    // 定义命令: etp <target> <data>
                    let sig = json!({
                        "Signature": [{
                            "name": "etp",
                            "usage": "Send data via ETP protocol",
                            "extra_usage": "Example: etp 127.0.0.1:8000 'hello'",
                            "category": "Network",
                            "params": [
                                // 必需的位置参数 target
                                {
                                    "name": "target",
                                    "type": "String",
                                    "optional": false,
                                    "desc": "Target Address (IP:Port)"
                                },
                                // 必需的位置参数 data
                                {
                                    "name": "data",
                                    "type": "String", 
                                    "optional": false,
                                    "desc": "Payload Data"
                                }
                            ],
                            "is_filter": false
                        }]
                    });
                    writeln!(stdout, "{}", sig).unwrap();
                },
                NuRequest::Run { name, call, .. } => {
                    if name == "etp" {
                        handle_run_etp(call, &mut stdout);
                    } else {
                        let err = json!({"Error": {"label": "Unknown Command", "msg": format!("Command {} not found", name)}});
                        writeln!(stdout, "{}", err).unwrap();
                    }
                }
            }
            stdout.flush().unwrap();
        }
    }

    fn handle_run_etp(call: NuCall, stdout: &mut io::Stdout) {
        // 健壮的参数解析：支持位置参数
        let mut target = String::new();
        let mut data = String::new();

        if let Some(pos) = call.positional {
            if pos.len() >= 2 {
                // Nu Value 结构通常是 { "String": { "val": "..." } } 或直接 "..."
                // 我们需要递归解包
                target = extract_nu_string(&pos[0]).unwrap_or_default();
                data = extract_nu_string(&pos[1]).unwrap_or_default();
            }
        }

        if target.is_empty() || data.is_empty() {
            let err = json!({"Error": {"label": "Missing Args", "msg": "Target and Data are required"}});
            writeln!(stdout, "{}", err).unwrap();
            return;
        }

        // 启动逻辑
        if !ensure_etp_started("0.0.0.0:0", "etp.flavor.nu.v1") {
            let err = json!({"Error": {"label": "Init Failed", "msg": "Could not bind port"}});
            writeln!(stdout, "{}", err).unwrap();
            return;
        }

        // 发送逻辑
        if let Some(h) = HANDLE.get() {
            let h = h.clone();
            let d_bytes = data.into_bytes();
            
            get_runtime().spawn(async move {
                if let Ok(addr) = target.parse::<SocketAddr>() {
                    let _ = h.send_data(addr, d_bytes).await;
                }
            });

            // 返回成功 Value
            let resp = json!({
                "Ok": { 
                    "Value": { 
                        "String": { 
                            "val": "Packet Queued", 
                            "span": { "start": 0, "end": 0 } 
                        } 
                    } 
                }
            });
            writeln!(stdout, "{}", resp).unwrap();
        }
    }

    fn extract_nu_string(v: &Value) -> Option<String> {
        // Nu 0.90+ JSON format: { "String": { "val": "content", ... } }
        if let Some(s) = v.get("String").and_then(|x| x.get("val")).and_then(|s| s.as_str()) {
            return Some(s.to_string());
        }
        // Fallback: direct string
        if let Some(s) = v.as_str() {
            return Some(s.to_string());
        }
        None
    }
}

// ============================================================================
//  2. Ring-lang 支持 (VM Extension / C-API Hook)
//  特性: binding-ring
// ============================================================================

#[cfg(all(feature = "binding-experimental", feature = "binding-ring"))]
pub mod ring_impl {
    use super::*;
    use libc::{c_char, c_void, c_int, c_double};

    // Ring VM 状态结构体 (Opaque)
    #[repr(C)]
    pub struct RingState { _private: [u8; 0] }

    // Ring API 外部符号声明 (由 ring 解释器在运行时提供)
    extern "C" {
        // 注册 C 函数到 Ring VM
        fn ring_vm_funcregister(pState: *mut RingState, name: *const c_char, func: extern "C" fn(*mut RingState));
        
        // 获取参数 (Index 从 1 开始)
        fn ring_vm_api_getstring(pState: *mut RingState, index: c_int) -> *const c_char;
        fn ring_vm_api_getnumber(pState: *mut RingState, index: c_int) -> c_double;
        
        // 返回值
        fn ring_vm_api_retnumber(pState: *mut RingState, num: c_double);
        fn ring_vm_api_retstring(pState: *mut RingState, str: *const c_char);
    }

    /// 动态库入口点: ring_loadlib 会调用此函数
    #[no_mangle]
    pub extern "C" fn ringlib_init(pState: *mut RingState) {
        let fn_init = CString::new("etp_init").unwrap();
        let fn_send = CString::new("etp_send").unwrap();
        
        unsafe {
            ring_vm_funcregister(pState, fn_init.as_ptr(), ring_etp_init);
            ring_vm_funcregister(pState, fn_send.as_ptr(), ring_etp_send);
        }
    }

    /// ring: etp_init("0.0.0.0:9000")
    extern "C" fn ring_etp_init(pState: *mut RingState) {
        unsafe {
            let arg1 = ring_vm_api_getstring(pState, 1);
            if arg1.is_null() {
                ring_vm_api_retnumber(pState, -1.0); // Error
                return;
            }
            let bind = CStr::from_ptr(arg1).to_string_lossy();
            
            let success = ensure_etp_started(&bind, "etp.flavor.ring.v1");
            ring_vm_api_retnumber(pState, if success { 1.0 } else { 0.0 });
        }
    }

    /// ring: etp_send("1.2.3.4:80", "hello")
    extern "C" fn ring_etp_send(pState: *mut RingState) {
        unsafe {
            let arg_target = ring_vm_api_getstring(pState, 1);
            let arg_data = ring_vm_api_getstring(pState, 2);
            
            if arg_target.is_null() || arg_data.is_null() {
                return;
            }

            let target = CStr::from_ptr(arg_target).to_string_lossy().to_string();
            let data = CStr::from_ptr(arg_data).to_string_lossy().to_string();

            if let Some(h) = HANDLE.get() {
                let h = h.clone();
                let d_bytes = data.into_bytes();
                
                get_runtime().spawn(async move {
                    if let Ok(addr) = target.parse::<SocketAddr>() {
                        let _ = h.send_data(addr, d_bytes).await;
                    }
                });
                ring_vm_api_retnumber(pState, 1.0);
            } else {
                ring_vm_api_retnumber(pState, 0.0); // Not initialized
            }
        }
    }
}

// ============================================================================
//  3. Haxe / HashLink 支持 (Raw C ABI)
//  特性: binding-haxe
// ============================================================================

#[cfg(all(feature = "binding-experimental", feature = "binding-haxe"))]
pub mod haxe_impl {
    use super::*;
    use libc::{c_char, c_int, c_uchar};

    /// Haxe 的 hl (HashLink) 或 hxcpp 可以直接调用此 C ABI
    #[no_mangle]
    pub extern "C" fn etp_haxe_init(bind_addr: *const c_char) -> c_int {
        if bind_addr.is_null() { return -1; }
        let s = unsafe { CStr::from_ptr(bind_addr).to_string_lossy() };
        
        if ensure_etp_started(&s, "etp.flavor.haxe.v1") { 0 } else { 1 }
    }

    /// 发送字节数组 (Haxe Bytes -> Rust Vec)
    #[no_mangle]
    pub extern "C" fn etp_haxe_send(target: *const c_char, data: *const c_uchar, len: c_int) -> c_int {
        if target.is_null() || data.is_null() || len <= 0 { return -1; }
        
        let t_str = unsafe { CStr::from_ptr(target).to_string_lossy().to_string() };
        // Deep copy data immediately to own it
        let d_vec = unsafe { slice::from_raw_parts(data, len as usize).to_vec() };

        if let Some(h) = HANDLE.get() {
            let h = h.clone();
            get_runtime().spawn(async move {
                if let Ok(addr) = t_str.parse::<SocketAddr>() {
                    let _ = h.send_data(addr, d_vec).await;
                }
            });
            0
        } else {
            -2 // Not init
        }
    }
}

// ============================================================================
//  4. Fusion-lang 支持 (Component Style)
//  特性: binding-fusion
// ============================================================================

#[cfg(all(feature = "binding-experimental", feature = "binding-fusion"))]
pub mod fusion_impl {
    use super::*;
    use libc::{c_char, c_void};

    // Fusion 语言偏好“组件句柄”模式
    
    #[no_mangle]
    pub extern "C" fn etp_fusion_create_context(bind: *const c_char) -> *mut c_void {
        let s = unsafe { CStr::from_ptr(bind).to_string_lossy() };
        if ensure_etp_started(&s, "etp.flavor.fusion.v1") {
            // 返回一个 Magic Number 或 Handle 指针作为成功标志
            // 这里返回 0xETP001 的非空指针
            return 0xETP as *mut c_void; 
        }
        std::ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn etp_fusion_push(_ctx: *mut c_void, target: *const c_char, msg: *const c_char) {
        // Fusion 字符串是 C-Style null terminated
        let t = unsafe { CStr::from_ptr(target).to_string_lossy().to_string() };
        let m = unsafe { CStr::from_ptr(msg).to_string_lossy().to_string() };
        
        if let Some(h) = HANDLE.get() {
            let h = h.clone();
            get_runtime().spawn(async move {
                if let Ok(addr) = t.parse() {
                    let _ = h.send_data(addr, m.into_bytes()).await;
                }
            });
        }
    }
}

// ============================================================================
//  5. Carbon-lang 支持 (Modern C++ Interop)
//  特性: binding-carbon
// ============================================================================

#[cfg(all(feature = "binding-experimental", feature = "binding-carbon"))]
pub mod carbon_impl {
    use super::*;
    use libc::c_char;

    // Carbon 和现代 C++ 倾向于使用 (ptr, size) 对来表示字符串，避免 strlen 开销
    #[repr(C)]
    pub struct CarbonSlice {
        ptr: *const c_char,
        size: usize,
    }

    #[no_mangle]
    pub extern "C" fn etp_carbon_init(bind: CarbonSlice) -> bool {
        let s = unsafe {
            let bytes = slice::from_raw_parts(bind.ptr as *const u8, bind.size);
            String::from_utf8_lossy(bytes).to_string()
        };
        ensure_etp_started(&s, "etp.flavor.carbon.v1")
    }

    #[no_mangle]
    pub extern "C" fn etp_carbon_send(target: CarbonSlice, payload: CarbonSlice) {
        let t_str = unsafe {
            let bytes = slice::from_raw_parts(target.ptr as *const u8, target.size);
            String::from_utf8_lossy(bytes).to_string()
        };
        let d_vec = unsafe {
            slice::from_raw_parts(payload.ptr as *const u8, payload.size).to_vec()
        };

        if let Some(h) = HANDLE.get() {
            let h = h.clone();
            get_runtime().spawn(async move {
                if let Ok(addr) = t_str.parse() {
                    let _ = h.send_data(addr, d_vec).await;
                }
            });
        }
    }
}
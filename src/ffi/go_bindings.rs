// etp-core/src/ffi/go_bindings.rs

#![cfg(feature = "binding-go")]

use std::os::raw::{c_char, c_int, c_void};
use std::slice;
use std::sync::{Arc, OnceLock, Mutex};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::runtime::Runtime;

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::PluginRegistry;

// --- 1. Go 兼容的内存结构 (Zero-Copy) ---

/// 对应 Go 的 string 头结构 (reflect.StringHeader)
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: usize,
}

/// 对应 Go 的 []byte 头结构 (reflect.SliceHeader)
#[repr(C)]
pub struct GoSlice {
    pub p: *const u8,
    pub len: usize,
    pub cap: usize,
}

// --- 2. 全局状态 ---

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static HANDLES: OnceLock<Mutex<HashMap<usize, Arc<EtpHandle>>>> = OnceLock::new();
static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

fn get_handle(id: usize) -> Option<Arc<EtpHandle>> {
    HANDLES.get()?.lock().unwrap().get(&id).cloned()
}

// --- 3. 导出 API ---

/// 初始化运行时 (Go init 调用)
#[no_mangle]
pub extern "C" fn etp_go_init() {
    let _ = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Tokio init failed")
    });
    let _ = HANDLES.get_or_init(|| Mutex::new(HashMap::new()));
}

/// 启动节点
/// 返回 handle_id (负数表示错误)
#[no_mangle]
pub extern "C" fn etp_go_start(bind_addr: GoString) -> c_int {
    let rt = match RUNTIME.get() {
        Some(r) => r,
        None => return -1,
    };

    let s_slice = unsafe { slice::from_raw_parts(bind_addr.p as *const u8, bind_addr.n) };
    let bind_str = String::from_utf8_lossy(s_slice).to_string();

    // 阻塞式启动 (Go 协程会等待)
    let res = rt.block_on(async {
        let mut config = NodeConfig::default();
        config.bind_addr = bind_str;
        let registry = Arc::new(PluginRegistry::new());
        // 注册默认插件
        registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
        
        let (engine, handle, _) = EtpEngine::new(config, registry).await.ok()?;
        
        tokio::spawn(async move {
            let _ = engine.run().await;
        });
        
        Some(handle)
    });

    if let Some(handle) = res {
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        HANDLES.get().unwrap().lock().unwrap().insert(id, Arc::new(handle));
        id as c_int
    } else {
        -2
    }
}

/// 发送数据
/// handle_id: start 返回的 ID
/// target: IP 字符串
/// data: 字节切片
#[no_mangle]
pub extern "C" fn etp_go_send(handle_id: c_int, target: GoString, data: GoSlice) -> c_int {
    let handle = match get_handle(handle_id as usize) {
        Some(h) => h,
        None => return -1, // Invalid Handle
    };
    
    let rt = RUNTIME.get().unwrap();

    // 数据拷贝 (必须，因为 Go 的内存可能会被 GC 或移动，且 Rust async 生命周期长于此函数调用)
    let addr_str = unsafe { 
        let s = slice::from_raw_parts(target.p as *const u8, target.n);
        String::from_utf8_lossy(s).to_string()
    };
    
    let data_vec = unsafe {
        slice::from_raw_parts(data.p, data.len).to_vec()
    };

    rt.spawn(async move {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            let _ = handle.send_data(addr, data_vec).await;
        }
    });

    0 // Success (Async Queued)
}

/// 销毁句柄
#[no_mangle]
pub extern "C" fn etp_go_close(handle_id: c_int) {
    if let Some(map) = HANDLES.get() {
        let mut guard = map.lock().unwrap();
        if let Some(h) = guard.remove(&(handle_id as usize)) {
            let rt = RUNTIME.get().unwrap();
            rt.spawn(async move {
                let _ = h.shutdown().await;
            });
        }
    }
}
// etp-core/src/ffi/scheme_bindings.rs

#![cfg(feature = "binding-scheme")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void, c_ulong};
use std::slice;
use std::collections::VecDeque;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use log::{info, error};

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. 全局状态与邮箱 (The Scheme Mailbox)
// ============================================================================

// Scheme 事件类型
#[repr(C)]
pub enum SchemeEventType {
    StreamData = 1,
    Connected = 2,
    Disconnected = 3,
}

// 传递给 Scheme 的事件结构体 (C Struct 布局)
#[repr(C)]
pub struct SchemeEvent {
    pub event_type: SchemeEventType,
    pub stream_id: u32,
    pub src_ip: *mut c_char,    // 需要 Scheme 端负责 free 或 Rust 管理
    pub data_ptr: *mut u8,      // 原始数据
    pub data_len: usize,
}

// 全局事件队列：Rust 生产 -> Scheme 消费
// 这种模式避免了跨语言线程回调的死锁风险
static SCHEME_MAILBOX: OnceLock<Mutex<VecDeque<SchemeEvent>>> = OnceLock::new();
static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

fn get_mailbox() -> &'static Mutex<VecDeque<SchemeEvent>> {
    SCHEME_MAILBOX.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    })
}

// ============================================================================
//  2. Scheme Proxy Flavor
// ============================================================================

struct SchemeProxyFlavor;

impl SchemeProxyFlavor {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    /// 将事件推入邮箱
    fn push_event(&self, evt: SchemeEvent) {
        let mb = get_mailbox();
        // 这里使用 blocking_lock 是安全的，因为 Tokio 线程池足够大
        // 且 Scheme 取数据很快
        if let Ok(mut queue) = mb.try_lock() {
            queue.push_back(evt);
        } else {
            // 如果锁竞争极其严重，选择丢弃或自旋（这里简化为打印）
            error!("Scheme Mailbox locked, dropping event");
            // 内存清理
            unsafe {
                let _ = CString::from_raw(evt.src_ip);
                let _ = Vec::from_raw_parts(evt.data_ptr, evt.data_len, evt.data_len);
            }
        }
    }
}

impl CapabilityProvider for SchemeProxyFlavor {
    fn capability_id(&self) -> String { "etp.flavor.scheme.v1".into() }
}

impl Flavor for SchemeProxyFlavor {
    fn priority(&self) -> u8 { 255 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // Deep Clone 数据到堆上，所有权移交给 C 结构体
        let data_vec = data.to_vec();
        let (ptr, len, cap) = data_vec.into_raw_parts();
        // 确保 cap == len，避免 free 时出错 (into_raw_parts 并不保证)
        // 实际上 Vec::from_raw_parts 需要正确的 cap。
        // 为简化，我们传递 ptr 和 len，Scheme 端只读，读完通知 Rust 释放，
        // 或者 Scheme copy 一份。
        // 这里采用：**Rust 分配，Scheme 读取后调用 etp_scheme_free_event 归还**。

        let src_c = CString::new(ctx.src_addr.to_string()).unwrap().into_raw();

        let evt = SchemeEvent {
            event_type: SchemeEventType::StreamData,
            stream_id: ctx.stream_id,
            src_ip: src_c,
            data_ptr: ptr,
            data_len: len,
        };

        self.push_event(evt);
        true
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        let src_c = CString::new(peer.to_string()).unwrap().into_raw();
        let evt = SchemeEvent {
            event_type: SchemeEventType::Connected,
            stream_id: 0,
            src_ip: src_c,
            data_ptr: std::ptr::null_mut(),
            data_len: 0,
        };
        self.push_event(evt);
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        let src_c = CString::new(peer.to_string()).unwrap().into_raw();
        let evt = SchemeEvent {
            event_type: SchemeEventType::Disconnected,
            stream_id: 0,
            src_ip: src_c,
            data_ptr: std::ptr::null_mut(),
            data_len: 0,
        };
        self.push_event(evt);
    }
}

// ============================================================================
//  3. C ABI 导出 (供 Scheme C-FFI 调用)
// ============================================================================

/// 启动节点
#[no_mangle]
pub extern "C" fn etp_scheme_start(bind_addr: *const c_char) -> c_int {
    let c_str = unsafe { CStr::from_ptr(bind_addr) };
    let bind_str = c_str.to_string_lossy().to_string();

    let rt = get_runtime();
    let res = rt.block_on(async {
        let mut config = NodeConfig::default();
        config.bind_addr = bind_str;
        config.default_flavor = "etp.flavor.scheme.v1".to_string();

        let registry = Arc::new(PluginRegistry::new());
        registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
        registry.register_flavor(SchemeProxyFlavor::new());

        EtpEngine::new(config, registry).await
    });

    match res {
        Ok((engine, handle, _)) => {
            let _ = HANDLE.set(handle);
            rt.spawn(async move {
                let _ = engine.run().await;
            });
            0 // Success
        },
        Err(_) => -1,
    }
}

/// 发送数据
#[no_mangle]
pub extern "C" fn etp_scheme_send(target: *const c_char, data: *const u8, len: usize) -> c_int {
    let handle = match HANDLE.get() {
        Some(h) => h,
        None => return -1,
    };
    
    let c_str = unsafe { CStr::from_ptr(target) };
    let addr_str = c_str.to_string_lossy().to_string();
    let data_vec = unsafe { slice::from_raw_parts(data, len).to_vec() };
    
    let h_clone = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            let _ = h_clone.send_data(addr, data_vec).await;
        }
    });
    0
}

/// 轮询事件 (非阻塞)
/// out_evt: 指向由 Scheme 分配的 SchemeEvent 内存
/// 返回: 1 有事件, 0 无事件
#[no_mangle]
pub extern "C" fn etp_scheme_poll(out_evt: *mut SchemeEvent) -> c_int {
    let mb = get_mailbox();
    // 使用 try_lock 保证非阻塞
    if let Ok(mut queue) = mb.try_lock() {
        if let Some(evt) = queue.pop_front() {
            unsafe { *out_evt = evt; }
            return 1;
        }
    }
    0
}

/// 释放事件内存 (必须由 Scheme 消费完事件后调用)
/// 这是一个 Rust 回收内存的钩子
#[no_mangle]
pub extern "C" fn etp_scheme_free_event(evt: *mut SchemeEvent) {
    unsafe {
        let e = &*evt;
        if !e.src_ip.is_null() {
            let _ = CString::from_raw(e.src_ip);
        }
        if !e.data_ptr.is_null() && e.data_len > 0 {
            // 重新构建 Vec 并 drop
            let _ = Vec::from_raw_parts(e.data_ptr, e.data_len, e.data_len);
        }
    }
}
// etp-core/src/ffi/perl_bindings.rs

#![cfg(feature = "binding-perl")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::collections::VecDeque;
use std::ptr;
use std::slice;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use lazy_static::lazy_static;

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. Perl 友好的事件结构
// ============================================================================

#[repr(C)]
pub struct PerlEvent {
    pub type_id: c_int, // 1=Data, 2=Conn, 3=Disconn
    pub stream_id: u32,
    pub src_len: usize,
    pub src_ptr: *mut c_char,
    pub data_len: usize,
    pub data_ptr: *mut u8,
}

// 内部队列
static PERL_MAILBOX: OnceLock<Mutex<VecDeque<PerlEvent>>> = OnceLock::new();
static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

fn get_mailbox() -> &'static Mutex<VecDeque<PerlEvent>> {
    PERL_MAILBOX.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap()
    })
}

// ============================================================================
//  2. Proxy Flavor
// ============================================================================

struct PerlProxyFlavor;
impl PerlProxyFlavor {
    fn push(&self, type_id: i32, sid: u32, src: SocketAddr, data: &[u8]) {
        if let Ok(mut q) = get_mailbox().try_lock() {
            let src_str = CString::new(src.to_string()).unwrap();
            let (d_ptr, d_len) = if !data.is_empty() {
                let mut v = data.to_vec();
                let p = v.as_mut_ptr();
                let l = v.len();
                std::mem::forget(v); // Leak to transfer ownership to C struct
                (p, l)
            } else {
                (ptr::null_mut(), 0)
            };

            q.push_back(PerlEvent {
                type_id,
                stream_id: sid,
                src_len: src_str.as_bytes().len(),
                src_ptr: src_str.into_raw(), // Transfer ownership
                data_len: d_len,
                data_ptr: d_ptr,
            });
        }
    }
}

impl CapabilityProvider for PerlProxyFlavor { fn capability_id(&self) -> String { "etp.flavor.perl.v1".into() } }
impl Flavor for PerlProxyFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        self.push(1, ctx.stream_id, ctx.src_addr, data);
        true
    }
    fn on_connection_open(&self, peer: SocketAddr) { self.push(2, 0, peer, &[]); }
    fn on_connection_close(&self, peer: SocketAddr) { self.push(3, 0, peer, &[]); }
}

// ============================================================================
//  3. C ABI 导出
// ============================================================================

#[no_mangle]
pub extern "C" fn etp_perl_start(bind_addr: *const c_char) -> c_int {
    let c_str = unsafe { CStr::from_ptr(bind_addr) };
    let bind_str = c_str.to_string_lossy().to_string();
    
    let rt = get_runtime();
    let res = rt.block_on(async {
        let mut cfg = NodeConfig::default();
        cfg.bind_addr = bind_str;
        cfg.default_flavor = "etp.flavor.perl.v1".into();
        let reg = Arc::new(PluginRegistry::new());
        reg.register_dialect(Arc::new(crate::plugin::StandardDialect));
        reg.register_flavor(Arc::new(PerlProxyFlavor));
        EtpEngine::new(cfg, reg).await
    });

    match res {
        Ok((eng, h, _)) => {
            let _ = HANDLE.set(h);
            rt.spawn(async move { let _ = eng.run().await; });
            0
        },
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn etp_perl_send(target: *const c_char, data: *const u8, len: usize) -> c_int {
    let handle = match HANDLE.get() { Some(h) => h, None => return -1 };
    let t_str = unsafe { CStr::from_ptr(target).to_string_lossy().to_string() };
    let d_vec = unsafe { slice::from_raw_parts(data, len).to_vec() };
    let h = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = t_str.parse() { let _ = h.send_data(addr, d_vec).await; }
    });
    0
}

/// 非阻塞轮询
/// 返回指向 Event 结构体的指针，如果没有事件则返回 NULL
#[no_mangle]
pub extern "C" fn etp_perl_poll() -> *mut PerlEvent {
    let mb = get_mailbox();
    if let Ok(mut q) = mb.try_lock() {
        if let Some(evt) = q.pop_front() {
            return Box::into_raw(Box::new(evt));
        }
    }
    ptr::null_mut()
}

/// 释放事件内存 (Perl 用完必须调这个)
#[no_mangle]
pub extern "C" fn etp_perl_free_event(ptr: *mut PerlEvent) {
    if ptr.is_null() { return; }
    unsafe {
        let evt = Box::from_raw(ptr); // Reconstruct Box to drop
        let _ = CString::from_raw(evt.src_ptr);
        if !evt.data_ptr.is_null() {
            let _ = Vec::from_raw_parts(evt.data_ptr, evt.data_len, evt.data_len);
        }
    }
}
// etp-core/src/ffi/lisp_bindings.rs

#![cfg(any(feature = "binding-lisp", feature = "binding-elisp"))]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::collections::VecDeque;
use std::slice;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use lazy_static::lazy_static;
use log::{info, error};

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. 统一状态管理 (The Lisp Reactor)
//  Lisp 语言通常有自己的 GC 和事件循环，我们采用“邮箱轮询”模式来解耦。
// ============================================================================

// 跨语言传递的事件结构 (C Layout)
#[repr(C)]
pub struct LispEvent {
    pub evt_type: u32,      // 1=Data, 2=Connected, 3=Disconnected
    pub stream_id: u32,
    pub src_ip: *mut c_char,
    pub data_ptr: *mut u8,
    pub data_len: usize,
}

static MAILBOX: OnceLock<Mutex<VecDeque<LispEvent>>> = OnceLock::new();
static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

fn get_mailbox() -> &'static Mutex<VecDeque<LispEvent>> {
    MAILBOX.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Tokio init failed")
    })
}

// --- Lisp Proxy Flavor ---
// 负责将 ETP 事件推入 MAILBOX
struct LispProxyFlavor;
impl LispProxyFlavor {
    fn new() -> Arc<Self> { Arc::new(Self) }
    
    fn push(&self, evt_type: u32, stream: u32, src: SocketAddr, data: &[u8]) {
        if let Ok(mut q) = get_mailbox().try_lock() {
            let c_src = CString::new(src.to_string()).unwrap().into_raw();
            let (ptr, len) = if !data.is_empty() {
                // Copy data to heap, Lisp side must free or copy
                let v = data.to_vec();
                let (p, l, _c) = v.into_raw_parts();
                (p, l)
            } else {
                (std::ptr::null_mut(), 0)
            };

            q.push_back(LispEvent {
                evt_type,
                stream_id: stream,
                src_ip: c_src,
                data_ptr: ptr,
                data_len: len,
            });
        }
    }
}

impl CapabilityProvider for LispProxyFlavor { fn capability_id(&self) -> String { "etp.flavor.lisp.v1".into() } }
impl Flavor for LispProxyFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        self.push(1, ctx.stream_id, ctx.src_addr, data);
        true
    }
    fn on_connection_open(&self, peer: SocketAddr) { self.push(2, 0, peer, &[]); }
    fn on_connection_close(&self, peer: SocketAddr) { self.push(3, 0, peer, &[]); }
}

// 内部启动逻辑 (复用)
fn start_internal(bind: String) -> Result<(), String> {
    if HANDLE.get().is_some() { return Err("Already started".into()); }
    
    let rt = get_runtime();
    let res = rt.block_on(async {
        let mut cfg = NodeConfig::default();
        cfg.bind_addr = bind;
        cfg.default_flavor = "etp.flavor.lisp.v1".into();
        
        let reg = Arc::new(PluginRegistry::new());
        reg.register_dialect(Arc::new(crate::plugin::StandardDialect));
        reg.register_flavor(LispProxyFlavor::new());
        
        EtpEngine::new(cfg, reg).await
    });

    match res {
        Ok((eng, h, _)) => {
            let _ = HANDLE.set(h);
            rt.spawn(async move { let _ = eng.run().await; });
            Ok(())
        },
        Err(e) => Err(e.to_string())
    }
}

// ============================================================================
//  2. 面板 A: 标准 C ABI (For Common Lisp & Racket)
// ============================================================================

#[no_mangle]
pub extern "C" fn etp_lisp_start(bind_addr: *const c_char) -> c_int {
    let s = unsafe { CStr::from_ptr(bind_addr).to_string_lossy().to_string() };
    match start_internal(s) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn etp_lisp_send(target: *const c_char, data: *const u8, len: usize) -> c_int {
    let handle = match HANDLE.get() { Some(h) => h, None => return -1 };
    let t_str = unsafe { CStr::from_ptr(target).to_string_lossy().to_string() };
    let d_vec = unsafe { slice::from_raw_parts(data, len).to_vec() };
    
    let h = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = t_str.parse() {
            let _ = h.send_data(addr, d_vec).await;
        }
    });
    0
}

#[no_mangle]
pub extern "C" fn etp_lisp_poll(out: *mut LispEvent) -> c_int {
    let mb = get_mailbox();
    if let Ok(mut q) = mb.try_lock() {
        if let Some(evt) = q.pop_front() {
            unsafe { *out = evt; }
            return 1;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn etp_lisp_free_event(evt: *mut LispEvent) {
    unsafe {
        let e = &*evt;
        if !e.src_ip.is_null() { let _ = CString::from_raw(e.src_ip); }
        if !e.data_ptr.is_null() { let _ = Vec::from_raw_parts(e.data_ptr, e.data_len, e.data_len); }
    }
}

// ============================================================================
//  3. 面板 B: Emacs Dynamic Module (For Elisp)
//  需要开启 `binding-elisp` 特性
// ============================================================================

#[cfg(feature = "binding-elisp")]
mod elisp_module {
    use super::*;
    use emacs::{Defun, Env, Result as EmacsResult, Value, IntoLisp};

    // 初始化 Emacs 模块
    emacs::plugin_is_GPL_compatible!();

    #[emacs::module(name = "etp-core")]
    fn init(env: &Env) -> EmacsResult<()> {
        env.message("ETP-Core Module Loaded!")?;
        Ok(())
    }

    /// (etp-start "0.0.0.0:8080")
    #[defun]
    fn etp_start(env: &Env, bind_addr: String) -> EmacsResult<bool> {
        match start_internal(bind_addr) {
            Ok(_) => {
                env.message("ETP Node Started")?;
                Ok(true)
            },
            Err(e) => {
                env.message(&format!("ETP Start Failed: {}", e))?;
                Ok(false)
            }
        }
    }

    /// (etp-send "1.2.3.4:9000" "Hello")
    #[defun]
    fn etp_send(env: &Env, target: String, data: String) -> EmacsResult<()> {
        let handle = match HANDLE.get() {
            Some(h) => h,
            None => return Ok(()),
        };
        
        let h = handle.clone();
        let d_vec = data.into_bytes();
        
        // 这里的异步要小心，Emacs 是单线程的。
        // 我们只是把任务扔给 Tokio，不等待结果。
        get_runtime().spawn(async move {
            if let Ok(addr) = target.parse() {
                let _ = h.send_data(addr, d_vec).await;
            }
        });
        Ok(())
    }

    /// (etp-poll) -> nil | (type stream-id src-ip data-string)
    /// 这是一个非阻塞调用，Elisp 可以在 idle-timer 中调用它
    #[defun]
    fn etp_poll(env: &Env) -> EmacsResult<Option<Value<'_>>> {
        let mb = get_mailbox();
        // 尝试获取锁，如果锁被占用（极少见），直接返回 nil
        if let Ok(mut q) = mb.try_lock() {
            if let Some(evt) = q.pop_front() {
                // 转换 Rust 数据到 Emacs Lisp 对象
                // 这次我们需要负责清理 evt 的内存，因为它是从 VecDeque 拿出来的，已经是 Owned
                
                let type_int = evt.evt_type;
                let stream_id = evt.stream_id;
                
                let src_str = unsafe { CStr::from_ptr(evt.src_ip).to_string_lossy().into_owned() };
                // 释放 CString 内存
                unsafe { let _ = CString::from_raw(evt.src_ip); }

                let data_str = if !evt.data_ptr.is_null() {
                    let slice = unsafe { slice::from_raw_parts(evt.data_ptr, evt.data_len) };
                    let s = String::from_utf8_lossy(slice).into_owned();
                    // 释放 Vec 内存
                    unsafe { let _ = Vec::from_raw_parts(evt.data_ptr, evt.data_len, evt.data_len); }
                    s
                } else {
                    "".to_string()
                };

                // 返回 List: (type stream src data)
                let list = env.list(&[
                    type_int.into_lisp(env)?,
                    stream_id.into_lisp(env)?,
                    src_str.into_lisp(env)?,
                    data_str.into_lisp(env)?,
                ])?;
                
                return Ok(Some(list));
            }
        }
        Ok(None)
    }
}
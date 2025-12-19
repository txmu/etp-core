// etp-core/src/ffi/vim_bindings.rs

#![cfg(feature = "binding-vim")]

use std::sync::{Arc, OnceLock, Mutex, Condvar};
use std::net::SocketAddr;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::cell::RefCell;

use tokio::runtime::Runtime;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use serde_json::json;
use log::{error, debug, info};

// EventFD 用于通知 Neovim/Libuv (Linux/macOS)
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(unix)]
use libc::{eventfd, EFD_NONBLOCK, write as c_write};

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. 基础设施：Mailbox 与 通知句柄
// ============================================================================

static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

// 生产级 Mailbox：互斥锁 + 条件变量
// 既支持非阻塞轮询 (Neovim/Vimscript)，也支持阻塞等待 (Python Thread)
struct NotificationQueue {
    queue: Mutex<VecDeque<VimEvent>>,
    cond: Condvar,
}

static MAILBOX: OnceLock<Arc<NotificationQueue>> = OnceLock::new();

// 线程局部缓冲区：用于安全地返回 char* 给宿主语言
// 避免 static mut 带来的数据竞争
thread_local! {
    static RETURN_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(4096));
}

// Neovim 专用 EventFD 句柄
static NOTIFY_FD: OnceLock<NotifyHandle> = OnceLock::new();

struct NotifyHandle {
    #[cfg(unix)]
    fd: RawFd,
}

impl NotifyHandle {
    fn new() -> Self {
        #[cfg(unix)]
        unsafe {
            // EFD_NONBLOCK: 非阻塞写入，防止 Rust 线程卡死
            let fd = eventfd(0, EFD_NONBLOCK);
            if fd < 0 { panic!("Failed to create eventfd for Neovim integration"); }
            Self { fd }
        }
        #[cfg(not(unix))]
        Self {} 
    }

    fn notify(&self) {
        #[cfg(unix)]
        unsafe {
            let val: u64 = 1;
            // 写入 8 字节，唤醒 Neovim 的 libuv loop
            let ret = c_write(self.fd, &val as *const _ as *const c_void, 8);
            if ret < 0 {
                // 忽略 EAGAIN，表示通知已挂起但未被消费，无需重复写入
            }
        }
    }
}

#[derive(Serialize, Clone)]
struct VimEvent {
    #[serde(rename = "type")]
    evt_type: String, // "data", "connect"
    stream: u32,
    src: String,
    payload: String, // Lossy UTF-8 string
}

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to init Tokio Runtime")
    })
}

fn get_mailbox() -> &'static Arc<NotificationQueue> {
    MAILBOX.get_or_init(|| Arc::new(NotificationQueue {
        queue: Mutex::new(VecDeque::new()),
        cond: Condvar::new(),
    }))
}

// ============================================================================
//  2. Vim Proxy Flavor
// ============================================================================

struct VimProxyFlavor;

impl VimProxyFlavor {
    fn push(&self, evt: VimEvent) {
        let mb = get_mailbox();
        
        // 1. 获取锁并推入队列
        if let Ok(mut q) = mb.queue.lock() {
            q.push_back(evt);
        }
        
        // 2. 唤醒所有阻塞等待的线程 (Python Interface)
        mb.cond.notify_all();

        // 3. 唤醒 EventFD (Neovim Interface)
        if let Some(h) = NOTIFY_FD.get() {
            h.notify();
        }
    }
}

impl CapabilityProvider for VimProxyFlavor { fn capability_id(&self) -> String { "etp.flavor.vim.v1".into() } }

impl Flavor for VimProxyFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // Vim 处理二进制并不方便，这里转换为 String (Lossy)
        // 如果需要传输二进制，建议在 Dialect 层启用 Base64 编码
        let payload = String::from_utf8_lossy(data).to_string();
        
        self.push(VimEvent {
            evt_type: "data".into(),
            stream: ctx.stream_id,
            src: ctx.src_addr.to_string(),
            payload,
        });
        true
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        self.push(VimEvent { 
            evt_type: "connect".into(), 
            stream: 0, 
            src: peer.to_string(), 
            payload: "".into() 
        });
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        self.push(VimEvent { 
            evt_type: "disconnect".into(), 
            stream: 0, 
            src: peer.to_string(), 
            payload: "".into() 
        });
    }
}

// ============================================================================
//  3. 启动与辅助逻辑
// ============================================================================

fn ensure_started(bind: &str) -> bool {
    if HANDLE.get().is_some() { return true; }
    
    // 必须先初始化 FD，否则 Flavor 无法通知
    NOTIFY_FD.get_or_init(|| NotifyHandle::new());

    let rt = get_runtime();
    let bind_s = bind.to_string();
    
    let res = rt.block_on(async {
        let mut cfg = NodeConfig::default();
        cfg.bind_addr = bind_s;
        cfg.default_flavor = "etp.flavor.vim.v1".into();
        
        let reg = Arc::new(PluginRegistry::new());
        reg.register_dialect(Arc::new(crate::plugin::StandardDialect));
        reg.register_flavor(Arc::new(VimProxyFlavor));
        
        EtpEngine::new(cfg, reg).await
    });

    match res {
        Ok((eng, h, _)) => {
            let _ = HANDLE.set(h);
            rt.spawn(async move {
                if let Err(e) = eng.run().await {
                    error!("ETP Engine Error: {}", e);
                }
            });
            true
        },
        Err(e) => {
            error!("ETP Start Failed: {}", e);
            false
        },
    }
}

// 辅助：将字符串写入线程局部缓冲区并返回 C 指针
fn write_to_tls_buffer(s: &str) -> *const c_char {
    RETURN_BUFFER.with(|buf_cell| {
        let mut buf = buf_cell.borrow_mut();
        buf.clear();
        buf.extend_from_slice(s.as_bytes());
        buf.push(0); // Null terminator
        buf.as_ptr() as *const c_char
    })
}

// ============================================================================
//  4. Vimscript 支持 (JSON-RPC via libcall)
// ============================================================================

#[derive(Deserialize)]
struct VimRequest {
    cmd: String,
    arg1: Option<String>,
    arg2: Option<String>,
}

#[no_mangle]
pub extern "C" fn etp_vim_rpc(req_str: *const c_char) -> *const c_char {
    if req_str.is_null() { return std::ptr::null(); }
    
    let c_str = unsafe { CStr::from_ptr(req_str) };
    let req_json = c_str.to_string_lossy();
    
    let resp_value = match serde_json::from_str::<VimRequest>(&req_json) {
        Ok(req) => handle_vim_cmd(req),
        Err(e) => json!({"error": format!("JSON Parse Error: {}", e)}),
    };

    write_to_tls_buffer(&resp_value.to_string())
}

fn handle_vim_cmd(req: VimRequest) -> serde_json::Value {
    match req.cmd.as_str() {
        "start" => {
            let bind = req.arg1.unwrap_or("0.0.0.0:0".into());
            let ok = ensure_started(&bind);
            json!({"status": if ok { "ok" } else { "fail" }})
        },
        "send" => {
            if let (Some(target), Some(data)) = (req.arg1, req.arg2) {
                if let Some(h) = HANDLE.get() {
                    let h = h.clone();
                    // Fire and forget send
                    get_runtime().spawn(async move {
                        if let Ok(addr) = target.parse() {
                            let _ = h.send_data(addr, data.into_bytes()).await;
                        }
                    });
                    json!({"status": "queued"})
                } else {
                    json!({"error": "not_started"})
                }
            } else {
                json!({"error": "missing_args"})
            }
        },
        "poll" => {
            // 非阻塞轮询 (Vim Timer Mode)
            let mb = get_mailbox();
            if let Ok(mut q) = mb.queue.try_lock() {
                if let Some(evt) = q.pop_front() {
                    return json!({"event": evt});
                }
            }
            json!({"event": null})
        },
        _ => json!({"error": "unknown_cmd"})
    }
}

// ============================================================================
//  5. Neovim 支持 (EventFD + Raw Struct)
// ============================================================================

#[repr(C)]
pub struct NvimEvent {
    pub type_id: c_int, // 1=Data
    pub src_ptr: *const c_char,
    pub data_ptr: *const u8,
    pub data_len: usize,
}

// 静态缓冲区用于 LuaJIT FFI 直接读取，避免频繁 malloc/free
// 注意：这在单线程访问下是安全的 (Neovim 主循环是单线程)
static mut NVIM_EVT_BUF: NvimEvent = NvimEvent { type_id: 0, src_ptr: std::ptr::null(), data_ptr: std::ptr::null(), data_len: 0 };
static mut NVIM_SRC_BUF: [u8; 64] = [0; 64];
static mut NVIM_DATA_BUF: [u8; 8192] = [0; 8192];

#[no_mangle]
pub extern "C" fn etp_nvim_get_fd() -> c_int {
    if let Some(h) = NOTIFY_FD.get() {
        #[cfg(unix)]
        return h.fd as c_int;
    }
    -1
}

#[no_mangle]
pub extern "C" fn etp_nvim_consume_fd() {
    #[cfg(unix)]
    if let Some(h) = NOTIFY_FD.get() {
        unsafe {
            let mut buf = [0u8; 8];
            libc::read(h.fd, buf.as_mut_ptr() as *mut c_void, 8);
        }
    }
}

#[no_mangle]
pub extern "C" fn etp_nvim_poll_fast() -> *const NvimEvent {
    let mb = get_mailbox();
    // 使用 try_lock 避免阻塞 Neovim 主线程
    if let Ok(mut q) = mb.queue.try_lock() {
        if let Some(evt) = q.pop_front() {
            unsafe {
                // 1. Copy Source IP
                let src_bytes = evt.src.as_bytes();
                let src_len = src_bytes.len().min(63);
                std::ptr::copy_nonoverlapping(src_bytes.as_ptr(), NVIM_SRC_BUF.as_mut_ptr(), src_len);
                NVIM_SRC_BUF[src_len] = 0; // Null terminate

                // 2. Copy Payload
                let data_bytes = evt.payload.as_bytes();
                let data_len = data_bytes.len().min(8192);
                std::ptr::copy_nonoverlapping(data_bytes.as_ptr(), NVIM_DATA_BUF.as_mut_ptr(), data_len);

                // 3. Fill Struct
                NVIM_EVT_BUF.type_id = 1;
                NVIM_EVT_BUF.src_ptr = NVIM_SRC_BUF.as_ptr() as *const c_char;
                NVIM_EVT_BUF.data_ptr = NVIM_DATA_BUF.as_ptr();
                NVIM_EVT_BUF.data_len = data_len;
                
                return &NVIM_EVT_BUF;
            }
        }
    }
    std::ptr::null()
}

// ============================================================================
//  6. Vim-Python 支持 (Blocking Poll with Condvar)
// ============================================================================

/// 阻塞式拉取 (生产级实现)
/// timeout_ms: 等待超时时间
/// 返回: JSON 字符串指针 (有数据) 或 NULL (超时)
#[no_mangle]
pub extern "C" fn etp_py_poll_blocking(timeout_ms: u32) -> *const c_char {
    let mb = get_mailbox();
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms as u64);

    // 1. 获取锁
    let mut guard = match mb.queue.lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null(), // Poisoned lock
    };

    loop {
        // 2. 检查队列是否有数据
        if let Some(evt) = guard.pop_front() {
            // 有数据 -> 序列化 -> 写入 TLS Buffer -> 返回
            let json_str = json!({"event": evt}).to_string();
            return write_to_tls_buffer(&json_str);
        }

        // 3. 检查剩余时间
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return std::ptr::null(); // 超时返回 NULL
        }
        let remaining = timeout - elapsed;

        // 4. 等待 Condition Variable (释放锁并挂起线程)
        // wait_timeout 返回 (guard, wait_result)
        let (new_guard, _result) = mb.cond.wait_timeout(guard, remaining).unwrap();
        guard = new_guard;
    }
}
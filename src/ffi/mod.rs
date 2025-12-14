// etp-core/src/ffi/mod.rs

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_longlong, c_uchar, c_uint, c_ulonglong, c_void};
use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::slice;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use tokio::runtime::Runtime;

// 引入 ETP Core 内部模块
use crate::plugin::{
    Flavor, Dialect, FlavorContext, CapabilityProvider, PluginRegistry,
};
use crate::network::node::{EtpEngine, NodeConfig, PacketHandler, PacketTransport, EtpHandle};
use crate::transport::congestion::CongestionControlAlgo;

// ============================================================================
// 1. 全局状态管理 (Global State)
// ============================================================================

// 用于在 FFI 边界之外保持 Tokio 运行时和 ETP 句柄
static GLOBAL_RUNTIME: OnceLock<Runtime> = OnceLock::new();
static GLOBAL_HANDLE: OnceLock<EtpHandle> = OnceLock::new();
static GLOBAL_CBS: OnceLock<EtpCallbacks> = OnceLock::new();

// ============================================================================
// 2. C ABI 回调定义 (VTable)
// ============================================================================

/// 跨语言回调函数表
/// 所有的外部语言（Go, Python, C++）都需要填充这个结构体并传给 Rust
#[repr(C)]
pub struct EtpCallbacks {
    // --- Flavor Hooks ---
    /// 当收到流数据时调用。返回 1 表示已处理，0 表示忽略。
    pub flavor_on_stream_data: extern "C" fn(stream_id: u32, src_ip: *const c_char, data: *const u8, len: usize) -> c_int,
    
    // --- Dialect Hooks ---
    /// 加密/封包前调用。允许修改 data 内容（原地扩容）。返回新的长度。
    pub dialect_seal: extern "C" fn(data: *mut u8, len: usize, cap: usize) -> usize,
    /// 解密/解包前调用。将解包结果写入 out。返回写入的长度。
    pub dialect_open: extern "C" fn(data: *const u8, len: usize, out: *mut u8, out_cap: usize) -> usize,
    
    // --- Handler Hooks ---
    /// 原始数据包拦截。返回 1 表示拦截，0 表示放行。
    pub handler_handle: extern "C" fn(src_ip: *const c_char, data: *const u8, len: usize) -> c_int,

    // --- Congestion Control Hooks (自定义拥塞控制) ---
    // 注意：拥塞控制需要维护状态，因此我们需要传回一个上下文指针 (ctx)
    
    /// 创建一个新的拥塞控制实例。返回 void* 指针作为 context。
    pub cc_new: extern "C" fn() -> *mut c_void,
    /// 销毁拥塞控制实例
    pub cc_drop: extern "C" fn(ctx: *mut c_void),
    /// 当数据包发送时调用
    pub cc_on_sent: extern "C" fn(ctx: *mut c_void, amount: usize, bytes: usize),
    /// 当收到 ACK 时调用
    pub cc_on_ack: extern "C" fn(ctx: *mut c_void, amount: usize, rtt_micros: c_ulonglong),
    /// 当检测到丢包时调用
    pub cc_on_loss: extern "C" fn(ctx: *mut c_void),
    /// 询问是否允许发送 (拥塞窗口判断)。返回 1 允许，0 拒绝。
    pub cc_can_send: extern "C" fn(ctx: *mut c_void, bytes_inflight: c_ulonglong) -> c_int,
    /// 获取 Pacing 延迟 (微秒)
    pub cc_pacing_delay: extern "C" fn(ctx: *mut c_void) -> c_ulonglong,
    /// 获取 RTO (微秒)
    pub cc_get_rto: extern "C" fn(ctx: *mut c_void) -> c_ulonglong,
    /// 获取 MSS
    pub cc_get_mss: extern "C" fn(ctx: *mut c_void) -> c_ulonglong,
}

// ============================================================================
// 3. FFI 导出函数 (Exported API)
// ============================================================================

/// 1. 初始化回调表
#[no_mangle]
pub extern "C" fn etp_init(cbs: EtpCallbacks) -> c_int {
    // 防止重复初始化
    if GLOBAL_CBS.set(cbs).is_err() {
        return -1; // Already initialized
    }
    0
}

/// 2. 启动 ETP 节点 (阻塞调用)
/// bind_addr: "0.0.0.0:4000"
/// cc_algo_id: "etp.cc.ffi" (如果想用 FFI 拥塞控制)
#[no_mangle]
pub extern "C" fn etp_start_node(bind_addr: *const c_char) -> c_int {
    // 捕获 Panic，防止 Rust 崩溃导致宿主程序（如 Python/Node）崩溃
    let result = catch_unwind(AssertUnwindSafe(|| {
        let c_str = unsafe { CStr::from_ptr(bind_addr) };
        let bind_str = c_str.to_string_lossy().to_string();

        // 初始化 Tokio Runtime
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio Runtime");

        // 注册到全局，以便 send_data 使用
        if GLOBAL_RUNTIME.set(rt).is_err() {
            eprintln!("[ETP-FFI] Runtime already initialized");
            return -1;
        }
        let rt = GLOBAL_RUNTIME.get().unwrap();

        rt.block_on(async {
            let registry = Arc::new(PluginRegistry::new());

            // --- A. 注册 FFI 代理插件 ---
            registry.register_flavor(Arc::new(FfiFlavor));
            registry.register_dialect(Arc::new(FfiDialect));

            // --- B. 注册 FFI 拥塞控制构造器 ---
            // 当 Config 指定 "etp.cc.ffi" 时，会调用此闭包创建 FfiCongestion
            registry.register_congestion_mod("etp.cc.ffi", || {
                Box::new(FfiCongestion::new())
            });

            // --- C. 配置节点 ---
            let mut config = NodeConfig::default();
            config.bind_addr = bind_str;
            // 强制使用 FFI 定义的 Flavor/Dialect/CC
            config.default_flavor = "etp.flavor.ffi".to_string();
            config.default_dialect = "etp.dialect.ffi".to_string();
            config.congestion_algo = "etp.cc.ffi".to_string(); // 使用外部定义的拥塞控制

            let (mut engine, handle, _) = EtpEngine::new(config, registry).await.expect("Engine init failed");
            
            // 保存 Handle
            if GLOBAL_HANDLE.set(handle).is_err() {
                 eprintln!("[ETP-FFI] Handle already set");
            }

            // 设置 FFI Handler
            engine.set_default_handler(Arc::new(FfiHandler));

            println!("[ETP-FFI] Node running via FFI bridge...");
            // 运行引擎 (无限循环)
            if let Err(e) = engine.run().await {
                eprintln!("[ETP-FFI] Engine error: {}", e);
            }
        });
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -2, // Panic occurred
    }
}

/// 3. 发送数据 (非阻塞/异步 Fire-and-Forget)
/// 支持所有语言调用，无需手动管理线程
#[no_mangle]
pub extern "C" fn etp_send(target_ip: *const c_char, data: *const u8, len: usize) -> c_int {
    let handle = match GLOBAL_HANDLE.get() {
        Some(h) => h,
        None => return -1, // Node not started
    };
    let rt = match GLOBAL_RUNTIME.get() {
        Some(r) => r,
        None => return -1,
    };

    // 数据拷贝：从 C 内存空间复制到 Rust Vec，因为异步任务的生命周期不确定
    let c_str = unsafe { CStr::from_ptr(target_ip) };
    let addr_str = c_str.to_string_lossy().to_string();
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let vec_data = slice.to_vec();
    let handle_clone = handle.clone();

    // 在 Tokio Runtime 中 Spawn 任务
    rt.spawn(async move {
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            if let Err(e) = handle_clone.send_data(addr, vec_data).await {
                eprintln!("[ETP-FFI] Send failed: {}", e);
            }
        } else {
            eprintln!("[ETP-FFI] Invalid IP: {}", addr_str);
        }
    });

    0 // Success (queued)
}

/// 4. 辅助函数：释放 Rust 分配的内存
/// 某些语言（如 C#）如果通过 dialect_open 接收了 Rust 的 Vec，需要 Rust 来释放
#[no_mangle]
pub extern "C" fn etp_free_bytes(ptr: *mut u8, len: usize, cap: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, cap);
        }
    }
}

// ============================================================================
// 4. 代理实现 (Proxies)
// ============================================================================

// --- FFI Flavor ---
#[derive(Debug)]
struct FfiFlavor;
impl CapabilityProvider for FfiFlavor {
    fn capability_id(&self) -> String { "etp.flavor.ffi".into() }
}
impl Flavor for FfiFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if let Some(cbs) = GLOBAL_CBS.get() {
            let addr = CString::new(ctx.src_addr.to_string()).unwrap_or_default();
            let res = (cbs.flavor_on_stream_data)(
                ctx.stream_id,
                addr.as_ptr(),
                data.as_ptr(),
                data.len()
            );
            return res != 0;
        }
        false
    }
    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}

// --- FFI Dialect ---
#[derive(Debug)]
struct FfiDialect;
impl CapabilityProvider for FfiDialect {
    fn capability_id(&self) -> String { "etp.dialect.ffi".into() }
}
impl Dialect for FfiDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        if let Some(cbs) = GLOBAL_CBS.get() {
            // 给外部语言预留空间 (假设最大扩展 1KB，可调整)
            payload.reserve(1024);
            let new_len = (cbs.dialect_seal)(
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
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                out.capacity()
            );
            if new_len == 0 {
                return Err(anyhow::anyhow!("FFI dialect open returned 0"));
            }
            unsafe { out.set_len(new_len); }
            return Ok(out);
        }
        Err(anyhow::anyhow!("No callbacks registered"))
    }
    fn probe(&self, _data: &[u8]) -> bool { true }
}

// --- FFI Handler ---
struct FfiHandler;
impl PacketHandler for FfiHandler {
    fn handle<'a>(
        &'a self,
        data: &'a [u8],
        src: SocketAddr,
        _transport: &'a Arc<dyn PacketTransport>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            if let Some(cbs) = GLOBAL_CBS.get() {
                let addr = CString::new(src.to_string()).unwrap_or_default();
                let res = (cbs.handler_handle)(
                    addr.as_ptr(),
                    data.as_ptr(),
                    data.len()
                );
                return res != 0;
            }
            false
        })
    }
}

// --- FFI Congestion Control (核心难点实现) ---
#[derive(Debug)]
struct FfiCongestion {
    // 外部语言维护的状态指针 (void*)
    ctx: *mut c_void,
}

// 必须手动标记 Send + Sync，因为 void* 指针本身不是。
// 调用方需保证其上下文是线程安全的，或者 ETP Core 保证同一 Connection 不会并发调用 CC。
unsafe impl Send for FfiCongestion {}
unsafe impl Sync for FfiCongestion {}

impl FfiCongestion {
    fn new() -> Self {
        let ctx = if let Some(cbs) = GLOBAL_CBS.get() {
            (cbs.cc_new)()
        } else {
            std::ptr::null_mut()
        };
        Self { ctx }
    }
}

impl Drop for FfiCongestion {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                (cbs.cc_drop)(self.ctx);
            }
        }
    }
}

impl CongestionControlAlgo for FfiCongestion {
    fn on_packet_sent(&mut self, amount: usize, bytes: usize) {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                (cbs.cc_on_sent)(self.ctx, amount, bytes);
            }
        }
    }

    fn on_ack_received(&mut self, amount: usize, rtt_sample: Option<Duration>) {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                let micros = rtt_sample.map(|d| d.as_micros() as u64).unwrap_or(0);
                (cbs.cc_on_ack)(self.ctx, amount, micros);
            }
        }
    }

    fn on_packet_lost(&mut self) {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                (cbs.cc_on_loss)(self.ctx);
            }
        }
    }

    fn can_send(&self, bytes_in_flight: u64) -> bool {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                return (cbs.cc_can_send)(self.ctx, bytes_in_flight) != 0;
            }
        }
        true // 默认允许，防止死锁
    }

    fn get_pacing_delay(&self) -> Duration {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                let micros = (cbs.cc_pacing_delay)(self.ctx);
                return Duration::from_micros(micros);
            }
        }
        Duration::ZERO
    }

    fn get_rto(&self) -> Duration {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                let micros = (cbs.cc_get_rto)(self.ctx);
                return Duration::from_micros(micros);
            }
        }
        Duration::from_millis(300) // 默认值
    }

    fn get_mss(&self) -> u64 {
        if !self.ctx.is_null() {
            if let Some(cbs) = GLOBAL_CBS.get() {
                return (cbs.cc_get_mss)(self.ctx) as u64;
            }
        }
        1350
    }
}

// 多语言接入指南 (Polyglot Integration)

//由于我们导出的是标准 C ABI，以下语言的集成方式如下：

// 1.  C / C++ / Zig / Carbon:
//    *   直接 `#include "etp_core.h"` (你需要根据上面的 `repr(C)` 结构体手写或使用 `cbindgen` 生成头文件)。
//    *   链接 `libetp_core.so`。
//    *   C++ 可以实现 `cc_new` 来创建 C++ 类实例，并将 `this` 指针作为 `void* ctx` 传回。

// 2.  Golang (cgo):
//    *   在 Go 代码中定义 `//export` 的函数。
//    *   使用 `C.etp_init` 注册 Go 函数指针。
//    *   使用 `C.etp_send` 发送数据。

// 3.  Python (ctypes):
//    *   定义 `ctypes.Structure` 映射 `EtpCallbacks`。
//    *   使用 `CFUNCTYPE` 创建 Python 回调函数装饰器。
//    *   `cdll.LoadLibrary("libetp_core.so")` 加载库。
//    *   注意：Python 的 GC 和 GIL 可能会影响拥塞控制的回调性能。

// 4.  Node.js (ffi-napi):
//    *   使用 `ffi-napi` 定义函数签名。
//    *   将 JS 函数传给 rust。注意保持 JS 回调的引用防止被 GC。

// 5.  Lua (LuaJIT):
//    *   `ffi.cdef[[ ... ]]` 定义结构体。
//    *   `ffi.load("etp_core")`。
//    *   非常适合实现拥塞控制算法，因为 LuaJIT FFI 性能极高。

//6.  Shell (Bash/Zsh/PowerShell等):
//    *   不支持直接回调。Shell 本身无法提供 C 函数指针供 Rust 回调。
//    *   解决方案: 编写一个极小的 C 或 Go 编写的 CLI Wrapper (etp-cli)。
//    *   `etp-cli` 接收命令行参数作为配置，将标准输入 (Stdin) 作为数据源发送 (`etp_send`)，将接收到的数据 (`flavor_on_stream_data`) 打印到标准输出 (Stdout)。
//    *   这样 Shell 就可以通过管道操作： `cat data.bin | etp-cli --target 1.2.3.4 | processed_output_tool`。

// etp-core/src/ffi/zig_bindings.rs

#![cfg(feature = "binding-zig")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::slice;
use std::ffi::{c_void, CStr};
use std::os::raw::c_char;

use tokio::runtime::Runtime;
use lazy_static::lazy_static;

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. Zig-Compatible Layouts (The "Super" Part)
//  Zig 的 slice 本质是 struct { ptr: [*]T, len: usize }。
//  我们在 Rust 端显式定义这种布局，使得 Zig 可以直接传递 slice，无需手动拆包。
// ============================================================================

#[repr(C)]
pub struct ZigSlice<T> {
    pub ptr: *mut T,
    pub len: usize,
}

impl<T> ZigSlice<T> {
    pub fn as_slice(&self) -> &[T] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// 对应 Zig 的 `[]const u8`
pub type ZigStr = ZigSlice<u8>;
/// 对应 Zig 的 `[]u8`
pub type ZigBytes = ZigSlice<u8>;

// ============================================================================
//  2. 全局运行时
// ============================================================================

static TOKIO: OnceLock<Runtime> = OnceLock::new();
static HANDLE: OnceLock<EtpHandle> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("Tokio init failed")
    })
}

// ============================================================================
//  3. Zig Proxy Flavor
// ============================================================================

// 定义 Zig 回调函数类型
// fn(stream_id: u32, src_ptr: [*]u8, src_len: usize, data_ptr: [*]u8, data_len: usize) callconv(.C) void
type ZigOnDataFn = extern "C" fn(u32, *const u8, usize, *const u8, usize);

static ZIG_CALLBACK: OnceLock<ZigOnDataFn> = OnceLock::new();

struct ZigFlavor;
impl CapabilityProvider for ZigFlavor { fn capability_id(&self) -> String { "etp.flavor.zig.v1".into() } }
impl Flavor for ZigFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if let Some(cb) = ZIG_CALLBACK.get() {
            let src_str = ctx.src_addr.to_string();
            let src_bytes = src_str.as_bytes();
            
            // 直接传递指针和长度，Zig 端可以直接将其视为 slice
            (cb)(
                ctx.stream_id,
                src_bytes.as_ptr(), src_bytes.len(),
                data.as_ptr(), data.len()
            );
        }
        true
    }
    fn on_connection_open(&self, _: SocketAddr) {}
    fn on_connection_close(&self, _: SocketAddr) {}
}

// ============================================================================
//  4. Zig API Exports
// ============================================================================

/// 初始化回调
#[no_mangle]
pub extern "C" fn etp_zig_init(cb: ZigOnDataFn) {
    let _ = ZIG_CALLBACK.set(cb);
}

/// 启动节点
/// 注意：参数直接接收 ZigStr 结构体，而不是分开的 ptr/len
#[no_mangle]
pub extern "C" fn etp_zig_start(bind_addr: ZigStr) -> i32 {
    let slice = bind_addr.as_slice();
    let bind_str = String::from_utf8_lossy(slice).to_string();

    let rt = get_runtime();
    let res = rt.block_on(async {
        let mut cfg = NodeConfig::default();
        cfg.bind_addr = bind_str;
        cfg.default_flavor = "etp.flavor.zig.v1".into();
        
        let reg = Arc::new(PluginRegistry::new());
        reg.register_dialect(Arc::new(crate::plugin::StandardDialect));
        reg.register_flavor(Arc::new(ZigFlavor));
        
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

/// 发送数据
#[no_mangle]
pub extern "C" fn etp_zig_send(target: ZigStr, data: ZigBytes) -> i32 {
    let handle = match HANDLE.get() { Some(h) => h, None => return -1 };
    
    // 必须拷贝数据，因为 Zig 栈上的 slice 可能会消失
    let t_str = String::from_utf8_lossy(target.as_slice()).to_string();
    let d_vec = data.as_slice().to_vec();
    
    let h = handle.clone();
    get_runtime().spawn(async move {
        if let Ok(addr) = t_str.parse() {
            let _ = h.send_data(addr, d_vec).await;
        }
    });
    0
}
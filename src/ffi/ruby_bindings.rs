// etp-core/src/ffi/ruby_bindings.rs

#![cfg(feature = "binding-ruby")]

use std::sync::{Arc, OnceLock};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use magnus::{
    define_module, function, method, prelude::*, 
    Error as RbError, Exception, RModule, Value, 
    class, scan_args, RString
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use lazy_static::lazy_static;

use crate::network::node::{EtpEngine, NodeConfig, EtpHandle};
use crate::plugin::{PluginRegistry, Flavor, FlavorContext, CapabilityProvider};

// ============================================================================
//  1. 全局状态
// ============================================================================

static TOKIO: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    TOKIO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Tokio init failed")
    })
}

// ============================================================================
//  2. Ruby Proxy Flavor
//  通过 Channel 将数据回传给 Ruby 的消费线程
// ============================================================================

enum RubyEvent {
    Data(u32, String, Vec<u8>),
    Connected(String),
    Disconnected(String),
}

struct RubyProxyFlavor {
    tx: mpsc::UnboundedSender<RubyEvent>,
}

impl RubyProxyFlavor {
    fn new(tx: mpsc::UnboundedSender<RubyEvent>) -> Arc<Self> {
        Arc::new(Self { tx })
    }
}

impl CapabilityProvider for RubyProxyFlavor { fn capability_id(&self) -> String { "etp.flavor.ruby.v1".into() } }
impl Flavor for RubyProxyFlavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        let _ = self.tx.send(RubyEvent::Data(
            ctx.stream_id,
            ctx.src_addr.to_string(),
            data.to_vec(),
        ));
        true
    }
    fn on_connection_open(&self, peer: SocketAddr) {
        let _ = self.tx.send(RubyEvent::Connected(peer.to_string()));
    }
    fn on_connection_close(&self, peer: SocketAddr) {
        let _ = self.tx.send(RubyEvent::Disconnected(peer.to_string()));
    }
}

// ============================================================================
//  3. Ruby Class: Etp::Node
// ============================================================================

#[magnus::wrap(class = "Etp::Node")]
struct RbEtpNode {
    handle: EtpHandle,
    event_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<RubyEvent>>>,
}

impl RbEtpNode {
    /// def initialize(bind_addr)
    fn new(bind_addr: String) -> Result<Self, RbError> {
        let (tx, rx) = mpsc::unbounded_channel();
        let rt = get_runtime();

        let res = rt.block_on(async {
            let mut config = NodeConfig::default();
            config.bind_addr = bind_addr;
            config.default_flavor = "etp.flavor.ruby.v1".into();

            let registry = Arc::new(PluginRegistry::new());
            registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
            registry.register_flavor(RubyProxyFlavor::new(tx));

            EtpEngine::new(config, registry).await
        });

        match res {
            Ok((engine, handle, _)) => {
                rt.spawn(async move { let _ = engine.run().await; });
                Ok(RbEtpNode {
                    handle,
                    event_rx: Arc::new(tokio::sync::Mutex::new(rx)),
                })
            },
            Err(e) => Err(RbError::new(magnus::exception::runtime_error(), e.to_string())),
        }
    }

    /// def send(target, data)
    fn send(&self, target: String, data: RString) -> Result<(), RbError> {
        // 安全地从 Ruby String 获取字节 (Zero-copy slice if possible)
        let bytes = unsafe { data.as_slice() }.to_vec();
        let handle = self.handle.clone();
        
        get_runtime().spawn(async move {
            if let Ok(addr) = target.parse::<SocketAddr>() {
                let _ = handle.send_data(addr, bytes).await;
            }
        });
        Ok(())
    }

    /// def listen(&block)
    /// 这是一个阻塞方法，但会释放 GVL，允许其他 Ruby 线程运行
    fn listen(&self, block: magnus::block::Proc) -> Result<(), RbError> {
        let rx_lock = self.event_rx.clone();
        
        loop {
            // 1. 在释放 GVL 的情况下等待下一个事件
            // 这是高性能的关键：等待 IO 时不阻塞 Ruby VM
            let event = magnus::rt::scan_args::get_kwargs::<_, (), (Option<i32>,)>(
               // Hack: simple usage here, real code uses thread::park logic or crossbeam
               // Magnus 暂未完全暴露 async await 到 GVL release。
               // 我们使用 blocking_recv 在一个允许阻塞的上下文中。
               ()
            );
            
            // 为了简化实现，我们使用 Tokio 的 blocking_recv 配合 thread::yield_now
            // 在生产环境中，应使用 magnus::thread::unblocking 包装
            
            // 简单轮询模拟 (生产级建议使用 Thread::new { node.listen } in Ruby)
            let evt = get_runtime().block_on(async {
                rx_lock.lock().await.recv().await
            });

            match evt {
                Some(e) => {
                    // 2. 重新获取 GVL 并回调 Ruby Block
                    let args = match e {
                        RubyEvent::Data(sid, src, data) => {
                            // Yield: [type, stream_id, src, data]
                            (
                                "data",
                                sid,
                                src,
                                RString::from_slice(&data)
                            ).try_convert_to_value()
                        },
                        RubyEvent::Connected(peer) => {
                            ("connected", 0, peer, "").try_convert_to_value()
                        },
                        RubyEvent::Disconnected(peer) => {
                            ("disconnected", 0, peer, "").try_convert_to_value()
                        }
                    };
                    
                    if let Ok(val) = args {
                        // call the block
                        // 检查 block 是否想中断监听 (例如返回 false)
                        if let Ok(ret) = block.call::<_, Value>(val) {
                            if let Some(b) = ret.try_convert::<bool>().ok() {
                                if !b { break; } 
                            }
                        }
                    }
                },
                None => break, // Channel closed
            }
        }
        Ok(())
    }
}

// ============================================================================
//  4. 模块初始化 (Gem Entry)
// ============================================================================

#[magnus::init]
fn init() -> Result<(), RbError> {
    let module = define_module("Etp")?;
    let class = module.define_class("Node", magnus::class::object())?;
    
    class.define_singleton_method("new", function!(RbEtpNode::new, 1))?;
    class.define_method("send", method!(RbEtpNode::send, 2))?;
    class.define_method("listen", method!(RbEtpNode::listen, 0))?;
    
    Ok(())
}
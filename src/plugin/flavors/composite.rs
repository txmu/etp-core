// etp-core/src/plugin/flavors/composite.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use log::{debug, info, trace};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

/// CompositeFlavor: 基于 Stream ID 的多路复用器
///
/// 允许单个 ETP 连接承载并行、隔离的业务流。
/// 例如: Stream 1 -> Control, Stream 2 -> VPN, Stream 3-10 -> FileShare。
///
/// 该模块负责将底层的 Stream ID 映射到具体的 Flavor 实例。
/// 关键特性是“去重通知”：如果同一个 Flavor 实例处理多个 Stream，
/// 连接建立/断开/轮询等全局事件只会被通知一次。
pub struct CompositeFlavor {
    /// 静态流映射: StreamID -> Flavor
    static_mapping: Arc<RwLock<HashMap<u32, Arc<dyn Flavor>>>>,
    /// 默认 Flavor: 处理未命中的 Stream ID
    default_flavor: Arc<dyn Flavor>,
}

impl CompositeFlavor {
    /// 创建一个新的 CompositeFlavor，指定默认的回落处理逻辑
    pub fn new(default_flavor: Arc<dyn Flavor>) -> Self {
        Self {
            static_mapping: Arc::new(RwLock::new(HashMap::new())),
            default_flavor,
        }
    }

    /// 绑定特定的 Stream ID 到特定的 Flavor
    ///
    /// 注意：多个 Stream ID 可以绑定到同一个 Flavor 实例。
    pub fn bind_stream(&self, stream_id: u32, flavor: Arc<dyn Flavor>) {
        self.static_mapping.write().insert(stream_id, flavor);
    }

    /// 移除绑定
    pub fn unbind_stream(&self, stream_id: u32) {
        self.static_mapping.write().remove(&stream_id);
    }

    /// 内部辅助函数：收集所有唯一的 Flavor 实例
    ///
    /// 通过比较 Arc 指针的数据地址（Data Pointer）来实现去重。
    /// 这对于 dyn Trait 对象是必须的，因为我们要确保同一个实例只被调用一次。
    fn collect_unique_flavors(&self) -> Vec<Arc<dyn Flavor>> {
        let map = self.static_mapping.read();
        
        // 使用 usize 存储指针地址，以此作为去重依据
        let mut seen_ptrs: HashSet<usize> = HashSet::new();
        let mut unique_flavors = Vec::new();

        // 1. 处理默认 Flavor
        let default_ptr = Arc::as_ptr(&self.default_flavor) as *const () as usize;
        seen_ptrs.insert(default_ptr);
        unique_flavors.push(self.default_flavor.clone());

        // 2. 遍历映射表
        for flavor in map.values() {
            // 获取 Arc 内部数据的裸指针，转为 usize 用于哈希集合比较
            // 注意：对于胖指针 (Fat Pointer)，as *const () 会丢弃 vtable 部分，
            // 仅保留数据地址，这正是我们判断“是否为同一实例”所需要的。
            let ptr = Arc::as_ptr(flavor) as *const () as usize;
            
            if seen_ptrs.insert(ptr) {
                unique_flavors.push(flavor.clone());
            }
        }

        unique_flavors
    }
}

impl CapabilityProvider for CompositeFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.composite.v1".into()
    }
}

impl Flavor for CompositeFlavor {
    fn priority(&self) -> u8 {
        255 // 最高优先级，作为入口分发器
    }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        let stream_id = ctx.stream_id;
        
        // 1. 查找静态映射
        // 使用读锁进行快速查找
        {
            let map = self.static_mapping.read();
            if let Some(flavor) = map.get(&stream_id) {
                trace!("Composite: Dispatching Stream {} to {}", stream_id, flavor.capability_id());
                // 直接转发 Context，无需修改数据 (Zero-Copy Dispatch)
                return flavor.on_stream_data(ctx, data);
            }
        }

        // 2. 默认处理
        // 未命中特定 Stream ID 的流量交给默认 Flavor (如 VPN)
        trace!("Composite: Dispatching Stream {} to DEFAULT {}", stream_id, self.default_flavor.capability_id());
        self.default_flavor.on_stream_data(ctx, data)
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        info!("Composite: Connection opened to {}, initializing sub-flavors...", peer);
        
        // 获取去重后的 Flavor 列表，避免重复初始化
        let flavors = self.collect_unique_flavors();
        
        for flavor in flavors {
            debug!("Composite: Notifying ON_OPEN to sub-flavor: {}", flavor.capability_id());
            flavor.on_connection_open(peer);
        }
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        info!("Composite: Connection closed to {}, cleaning up sub-flavors...", peer);
        
        // 获取去重后的 Flavor 列表，避免重复清理
        let flavors = self.collect_unique_flavors();
        
        for flavor in flavors {
            debug!("Composite: Notifying ON_CLOSE to sub-flavor: {}", flavor.capability_id());
            flavor.on_connection_close(peer);
        }
    }

    fn poll(&self) {
        // 轮询逻辑也需要去重，防止同一个 Flavor 被频繁 Poll
        let flavors = self.collect_unique_flavors();
        
        for flavor in flavors {
            flavor.poll();
        }
    }
}
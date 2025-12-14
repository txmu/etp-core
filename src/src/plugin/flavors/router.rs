// etp-core/src/plugin/flavors/router.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::HashMap;
use parking_lot::RwLock;
use log::{debug, warn, trace};
use anyhow::{Result, anyhow};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};

/// 路由头部定义
/// [RouteID (1 byte)] [Payload...]
const ROUTE_HEADER_LEN: usize = 1;

/// RouterFlavor: 协议内分流器
/// 将单一数据流根据首字节分发给不同的子 Flavor
pub struct RouterFlavor {
    /// 路由表: RouteID -> SubFlavor
    routes: Arc<RwLock<HashMap<u8, Arc<dyn Flavor>>>>,
    /// 默认 Flavor (当 RouteID 未命中时使用，可选)
    default_route: Option<Arc<dyn Flavor>>,
}

impl RouterFlavor {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            default_route: None,
        }
    }

    /// 注册子 Flavor
    /// id: 协议标识符 (0-255)，例如 0x01=VPN, 0x02=Chat
    pub fn register_route(&self, id: u8, flavor: Arc<dyn Flavor>) {
        self.routes.write().insert(id, flavor);
    }

    /// 设置默认回落 Flavor (用于处理不带头的遗留流量或未知流量)
    pub fn set_default_route(&mut self, flavor: Arc<dyn Flavor>) {
        self.default_route = Some(flavor);
    }
}

impl CapabilityProvider for RouterFlavor {
    fn capability_id(&self) -> String {
        "etp.flavor.router.v1".into()
    }
}

impl Flavor for RouterFlavor {
    fn priority(&self) -> u8 {
        255 // 最高优先级，作为入口控制器
    }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < ROUTE_HEADER_LEN {
            return false;
        }

        let route_id = data[0];
        let payload = &data[ROUTE_HEADER_LEN..];

        let routes = self.routes.read();
        
        if let Some(flavor) = routes.get(&route_id) {
            // 构造新的上下文 (透传)
            // 注意：这里我们剥离了 Route Header，子 Flavor 看到的是纯净数据
            let sub_ctx = FlavorContext {
                src_addr: ctx.src_addr,
                stream_id: ctx.stream_id,
                data_len: payload.len(),
                system: ctx.system,
            };
            
            trace!("Router: Dispatching packet ({} bytes) to RouteID {}", payload.len(), route_id);
            return flavor.on_stream_data(sub_ctx, payload);
        }

        // Fallback 逻辑
        if let Some(default) = &self.default_route {
            // 默认路由通常处理原始数据 (包含 Header)，因为它可能根本不知道有 Header
            return default.on_stream_data(ctx, data);
        }

        warn!("Router: No route found for ID {}, dropping packet.", route_id);
        true // 已处理（丢弃），阻止向后传递
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // 广播连接事件给所有子 Flavor
        // 这样 VPN 可以初始化 TUN，Chat 可以发送 Sync
        let routes = self.routes.read();
        for flavor in routes.values() {
            flavor.on_connection_open(peer);
        }
        if let Some(default) = &self.default_route {
            default.on_connection_open(peer);
        }
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        let routes = self.routes.read();
        for flavor in routes.values() {
            flavor.on_connection_close(peer);
        }
        if let Some(default) = &self.default_route {
            default.on_connection_close(peer);
        }
    }

    fn poll(&self) {
        // 轮询所有子 Flavor 的后台任务
        let routes = self.routes.read();
        for flavor in routes.values() {
            flavor.poll();
        }
        if let Some(default) = &self.default_route {
            default.poll();
        }
    }
}
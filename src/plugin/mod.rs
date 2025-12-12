// etp-core/src/plugin/mod.rs

use std::sync::Arc;
use std::collections::HashMap;
use std::any::Any;
use std::net::SocketAddr;
use anyhow::Result;
use parking_lot::RwLock;
use std::fmt::Debug;

// 引入 ZKP 模块
use crate::security::zkp_negotiation::{ZkpNegotiator, CapabilityId};

/// 上下文：传递给 Flavor 的运行时信息
pub struct FlavorContext<'a> {
    pub src_addr: SocketAddr,
    pub stream_id: u32,
    pub data_len: usize,
    /// 允许 Flavor 访问一些共享状态（如 DHT），此处使用 Any 占位，实际应为 Context 结构
    pub state: Option<&'a dyn Any>,
}

/// 基础能力接口
pub trait CapabilityProvider: Send + Sync + Debug {
    /// 返回能力的唯一 ID (用于 ZKP 协商)
    /// 格式建议: "etp.<category>.<name>.v<version>"
    fn capability_id(&self) -> CapabilityId;
}

// -----------------------------------------------------------------------------
// Dialect (方言): 定义 "怎么说" (How to speak)
// 负责物理层的编码、混淆、伪装。
// -----------------------------------------------------------------------------
pub trait Dialect: CapabilityProvider {
    /// 封装: 将加密后的 ETP 帧数据包装成特定格式 (如添加 TLS Header)
    fn seal(&self, payload: &mut Vec<u8>);

    /// 解封: 尝试解析格式并还原 ETP 数据。
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// 探针: 快速检查数据包是否看起来属于该方言 (无状态检查)
    /// 用于自适应学习: 当 Session 未建立时，Node 会遍历所有 Dialect 的 probe()
    fn probe(&self, data: &[u8]) -> bool;
}

// -----------------------------------------------------------------------------
// Flavor (风味): 定义 "说什么" (What to say)
// 负责逻辑层的业务处理 (VPN, Chat, Fileshare)。
// -----------------------------------------------------------------------------
pub trait Flavor: CapabilityProvider {
    /// 优先级 (0-255)，数字越大优先级越高
    /// 当多个 Flavor 都想处理同一个包时，优先级高的先得
    fn priority(&self) -> u8 { 100 }

    /// 当收到数据流时触发
    /// 返回 true 表示该 Flavor 已全权处理该数据，后续 Flavor 不再接收
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool;
    
    /// 当连接建立时触发 (用于初始化)
    fn on_connection_open(&self, peer: SocketAddr);

    /// 当连接关闭时触发
    fn on_connection_close(&self, peer: SocketAddr);

    /// 后台轮询 (可选)
    /// 用于执行定时任务，如 DHT 发布、P2P 只有列表刷新
    fn poll(&self) {}
}

// -----------------------------------------------------------------------------
// Plugin Registry (插件注册中心)
// -----------------------------------------------------------------------------
#[derive(Clone)]
pub struct PluginRegistry {
    dialects: Arc<RwLock<HashMap<String, Arc<dyn Dialect>>>>,
    flavors: Arc<RwLock<HashMap<String, Arc<dyn Flavor>>>>,
    
    /// 内置的安全协商器
    pub negotiator: Arc<ZkpNegotiator>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            dialects: Arc::new(RwLock::new(HashMap::new())),
            flavors: Arc::new(RwLock::new(HashMap::new())),
            negotiator: Arc::new(ZkpNegotiator::new()),
        }
    }

    pub fn register_dialect(&self, dialect: Arc<dyn Dialect>) {
        let id = dialect.capability_id();
        self.negotiator.register_capability(id.clone());
        self.dialects.write().insert(id, dialect);
    }

    pub fn register_flavor(&self, flavor: Arc<dyn Flavor>) {
        let id = flavor.capability_id();
        self.negotiator.register_capability(id.clone());
        self.flavors.write().insert(id, flavor);
    }

    pub fn get_dialect(&self, id: &str) -> Option<Arc<dyn Dialect>> {
        self.dialects.read().get(id).cloned()
    }
    
    pub fn get_flavor(&self, id: &str) -> Option<Arc<dyn Flavor>> {
        self.flavors.read().get(id).cloned()
    }

    /// 获取所有注册的方言 (用于遍历探测)
    pub fn all_dialects(&self) -> Vec<Arc<dyn Dialect>> {
        self.dialects.read().values().cloned().collect()
    }

    /// 根据协商结果 (Common Capabilities) 激活对应的 Flavor 列表
    pub fn get_active_flavors(&self, capability_ids: &[String]) -> Vec<Arc<dyn Flavor>> {
        let map = self.flavors.read();
        let mut active = Vec::new();
        for id in capability_ids {
            if let Some(f) = map.get(id) {
                active.push(f.clone());
            }
        }
        // 按优先级排序 (高优先级在前)
        active.sort_by(|a, b| b.priority().cmp(&a.priority()));
        active
    }
}

// -----------------------------------------------------------------------------
// 默认实现 (Standards)
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub struct StandardDialect; 
impl CapabilityProvider for StandardDialect {
    fn capability_id(&self) -> String { "etp.dialect.noise.std".into() }
}
impl Dialect for StandardDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        // 简单的随机前缀
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut prefix = [0u8; 16];
        rng.fill_bytes(&mut prefix);
        let mut new = Vec::with_capacity(16 + payload.len());
        new.extend_from_slice(&prefix);
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 16 { return Err(anyhow::anyhow!("Too short")); }
        Ok(data[16..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 16 // 随机噪声很难探测，这也是它的目的
    }
}

#[derive(Debug)]
pub struct StandardFlavor;
impl CapabilityProvider for StandardFlavor {
    fn capability_id(&self) -> String { "etp.flavor.core".into() }
}
impl Flavor for StandardFlavor {
    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool {
        false // 不拦截，让核心处理
    }
    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}
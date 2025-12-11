// etp-core/src/plugin/mod.rs

use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use std::fmt::Debug;
use parking_lot::RwLock;

// ----------------------
// Concept 1: Dialect (方言)
// 负责物理层的“伪装”。它决定了数据在 UDP 线缆上长什么样。
// ----------------------

pub trait Dialect: Send + Sync + Debug {
    /// 方言 ID (如 "tls_1.3", "random_noise", "http_3")
    fn id(&self) -> &'static str;

    /// 封装: 将加密后的 ETP 帧数据包装成特定格式 (如添加 TLS Header)
    fn seal(&self, payload: &mut Vec<u8>);

    /// 解封: 尝试解析格式并还原 ETP 数据。如果不符合该方言格式，返回 Error
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;
}

// ----------------------
// Concept 2: Flavor (风味)
// 负责逻辑层的“业务偏好”。它决定了节点如何处理特定类型的数据流。
// ----------------------

/// 风味上下文，传递给 Flavor 处理函数
pub struct FlavorContext<'a> {
    pub src_addr: std::net::SocketAddr,
    pub stream_id: u32,
    pub data_len: usize,
    // 可扩展更多上下文...
    _phantom: &'a (),
}

pub trait Flavor: Send + Sync + Debug {
    fn id(&self) -> &'static str;

    /// 当收到数据流时触发。返回 true 表示该 Flavor 已处理该数据，
    /// 核心逻辑不需要再将其发给默认通道；返回 false 表示仅做审计/Hook，继续默认流程。
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool;
    
    /// 当连接建立时触发
    fn on_connection_open(&self, peer: std::net::SocketAddr);
}

// ----------------------
// Plugin Registry
// ----------------------

#[derive(Clone)]
pub struct PluginRegistry {
    dialects: Arc<RwLock<HashMap<String, Arc<dyn Dialect>>>>,
    flavors: Arc<RwLock<HashMap<String, Arc<dyn Flavor>>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            dialects: Arc::new(RwLock::new(HashMap::new())),
            flavors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_dialect(&self, dialect: Arc<dyn Dialect>) {
        self.dialects.write().insert(dialect.id().to_string(), dialect);
    }

    pub fn register_flavor(&self, flavor: Arc<dyn Flavor>) {
        self.flavors.write().insert(flavor.id().to_string(), flavor);
    }

    pub fn get_dialect(&self, id: &str) -> Option<Arc<dyn Dialect>> {
        self.dialects.read().get(id).cloned()
    }
    
    pub fn get_flavor(&self, id: &str) -> Option<Arc<dyn Flavor>> {
        self.flavors.read().get(id).cloned()
    }
}

// ----------------------
// 默认实现 (Default Plugins)
// ----------------------

#[derive(Debug)]
pub struct StandardDialect; // 纯随机噪声
impl Dialect for StandardDialect {
    fn id(&self) -> &'static str { "standard_noise" }
    fn seal(&self, payload: &mut Vec<u8>) {
        // 简单的随机前缀混淆
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
}

#[derive(Debug)]
pub struct StandardFlavor; // 标准透传
impl Flavor for StandardFlavor {
    fn id(&self) -> &'static str { "std_passthrough" }
    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool {
        false // 不拦截，继续交给核心逻辑
    }
    fn on_connection_open(&self, _peer: std::net::SocketAddr) {}
}

// ----------------------
// Unit Tests
// ----------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_registry() {
        let registry = PluginRegistry::new();
        registry.register_dialect(Arc::new(StandardDialect));
        
        let d = registry.get_dialect("standard_noise").unwrap();
        let mut data = vec![1, 2, 3];
        d.seal(&mut data);
        assert_eq!(data.len(), 19); // 16 + 3
        
        let restored = d.open(&data).unwrap();
        assert_eq!(restored, vec![1, 2, 3]);
    }
}
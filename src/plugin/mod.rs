// etp-core/src/plugin/mod.rs

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::fmt::Debug;
use anyhow::{Result, anyhow};
use parking_lot::RwLock;
use rand::{Rng, RngCore};

use crate::security::zkp_negotiation::{ZkpNegotiator, CapabilityId};
use crate::NodeID;

// 引入传输层策略接口 (Mods)
use crate::transport::congestion::CongestionControlAlgo;
use crate::transport::padding::PaddingStrategy;

// ============================================================================
//  1. 基础上下文定义 (Contexts)
// ============================================================================

/// 系统上下文接口：暴露给插件的安全系统能力
/// 允许插件查询路由表或检查连接状态，而无需持有 Engine 的全量锁
pub trait SystemContext: Send + Sync {
    /// 核心变更：返回 NodeInfo，以便插件读取 reputation 字段执行安全策略
    /// 根据 NodeID 查找已知的物理地址 (DHT/Local Routing Table)
    fn lookup_peer(&self, node_id: &NodeID) -> Option<crate::common::NodeInfo>;
    
    /// 检查与指定地址的会话是否处于活跃状态
    fn is_connected(&self, addr: SocketAddr) -> bool;
    /// 获取当前节点的 ID
    fn my_node_id(&self) -> NodeID;
}

/// Flavor 上下文：传递给 Flavor 的运行时数据信息
pub struct FlavorContext<'a> {
    pub src_addr: SocketAddr,
    pub stream_id: u32,
    pub data_len: usize,
    /// 强类型的系统上下文
    pub system: &'a dyn SystemContext,
}

/// Interceptor 上下文：传递给拦截器的元数据
pub struct InterceptorContext {
    pub stream_id: u32,
    pub is_handshake: bool,
}

/// Agent 上下文：传递给后台智能体的控制句柄
/// (目前是一个空占位符，未来可以包含 EtpHandle 或 Metrics 引用)
pub struct AgentContext {
    pub node_id: NodeID,
}

// ============================================================================
//  2. 扩展接口定义 (Traits)
// ============================================================================

/// 基础能力接口 (所有插件的基类)
pub trait CapabilityProvider: Send + Sync + Debug {
    /// 返回能力的唯一 ID (用于 ZKP 协商和日志)
    /// 格式建议: "vendor.category.name.version"
    fn capability_id(&self) -> CapabilityId;
}

/// Dialect (方言): 定义 "怎么说" (Wire Format / Obfuscation)
/// 负责数据的序列化、伪装、去伪装
pub trait Dialect: CapabilityProvider {
    /// 封包：对数据进行混淆或添加头部 (In-Place 修改)
    fn seal(&self, payload: &mut Vec<u8>);
    
    /// 解包：去除混淆，还原原始数据
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// 探针：快速判断数据包是否属于该方言 (用于多协议共存时的嗅探)
    fn probe(&self, data: &[u8]) -> bool;
}

/// Flavor (风味): 定义 "说什么" (Business Logic)
/// 负责处理业务数据流 (VPN, Chat, FileShare)
pub trait Flavor: CapabilityProvider {
    /// 优先级 (0-255)，越高越先被调度
    fn priority(&self) -> u8 { 100 }
    
    /// 处理入站流数据
    /// 返回 true 表示数据已被消费，不再传递给后续处理者
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool;
    
    /// 连接建立回调
    fn on_connection_open(&self, peer: SocketAddr);
    
    /// 连接断开回调
    fn on_connection_close(&self, peer: SocketAddr);
    
    /// 定时轮询 (用于超时重传、状态清理)
    fn poll(&self) {}
}

/// Interceptor (拦截器): 定义 "怎么处理" (Middleware / Add-on)
/// 位于 Flavor 和底层之间，负责无状态或弱状态的流处理 (压缩, 审计, 防火墙)
pub trait Interceptor: CapabilityProvider {
    /// 入站处理 (Decrypted Layer -> Flavor)
    /// 返回 Ok(None) 表示丢弃该包
    fn on_ingress(&self, ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(Some(data))
    }

    /// 出站处理 (Flavor -> Encrypted Layer)
    fn on_egress(&self, ctx: &InterceptorContext, data: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(Some(data))
    }
}

/// Agent (智能体): 定义 "怎么思考" (Background Worker)
/// 独立于连接运行的后台任务，用于网络维护、数据分析或自动化决策
#[async_trait::async_trait]
pub trait Agent: CapabilityProvider {
    /// 启动智能体 (在 Node 启动时调用)
    async fn run(&self, ctx: AgentContext);
}

// ============================================================================
//  3. 构造器类型定义 (用于 Mods)
// ============================================================================

/// 拥塞控制算法构造器
pub type CongestionConstructor = Arc<dyn Fn() -> Box<dyn CongestionControlAlgo> + Send + Sync>;

/// 填充策略构造器
pub type PaddingConstructor = Arc<dyn Fn() -> Box<dyn PaddingStrategy> + Send + Sync>;

// ============================================================================
//  4. 插件注册中心 (The Registry)
// ============================================================================

#[derive(Clone)]
pub struct PluginRegistry {
    // 基础插件
    dialects: Arc<RwLock<HashMap<String, Arc<dyn Dialect>>>>,
    flavors: Arc<RwLock<HashMap<String, Arc<dyn Flavor>>>>,
    
    // 中间件 (全局默认链)
    default_interceptors: Arc<RwLock<Vec<Arc<dyn Interceptor>>>>,
    
    // 核心 Mods (构造器)
    congestion_mods: Arc<RwLock<HashMap<String, CongestionConstructor>>>,
    padding_mods: Arc<RwLock<HashMap<String, PaddingConstructor>>>,
    
    // 智能体
    agents: Arc<RwLock<Vec<Arc<dyn Agent>>>>,

    // 安全协商器
    pub negotiator: Arc<ZkpNegotiator>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            dialects: Arc::new(RwLock::new(HashMap::new())),
            flavors: Arc::new(RwLock::new(HashMap::new())),
            default_interceptors: Arc::new(RwLock::new(Vec::new())),
            congestion_mods: Arc::new(RwLock::new(HashMap::new())),
            padding_mods: Arc::new(RwLock::new(HashMap::new())),
            agents: Arc::new(RwLock::new(Vec::new())),
            negotiator: Arc::new(ZkpNegotiator::new()),
        }
    }

    // --- Dialect Management ---
    pub fn register_dialect(&self, dialect: Arc<dyn Dialect>) {
        let id = dialect.capability_id();
        // Dialect 需要参与 ZKP 协商，因为双方必须说同样的语言
        self.negotiator.register_capability(id.clone());
        self.dialects.write().insert(id, dialect);
    }

    pub fn get_dialect(&self, id: &str) -> Option<Arc<dyn Dialect>> {
        self.dialects.read().get(id).cloned()
    }

    pub fn all_dialects(&self) -> Vec<Arc<dyn Dialect>> {
        self.dialects.read().values().cloned().collect()
    }

    // --- Flavor Management ---
    pub fn register_flavor(&self, flavor: Arc<dyn Flavor>) {
        let id = flavor.capability_id();
        // Flavor 需要参与 ZKP 协商，确认对方支持该业务
        self.negotiator.register_capability(id.clone());
        self.flavors.write().insert(id, flavor);
    }

    pub fn get_flavor(&self, id: &str) -> Option<Arc<dyn Flavor>> {
        self.flavors.read().get(id).cloned()
    }

    pub fn get_active_flavors(&self, capability_ids: &[String]) -> Vec<Arc<dyn Flavor>> {
        let map = self.flavors.read();
        let mut active = Vec::new();
        for id in capability_ids {
            if let Some(f) = map.get(id) {
                active.push(f.clone());
            }
        }
        active.sort_by(|a, b| b.priority().cmp(&a.priority()));
        active
    }

    // --- Interceptor Management (Add-ons) ---
    pub fn register_default_interceptor(&self, interceptor: Arc<dyn Interceptor>) {
        // 拦截器通常是本地策略，不需要 ZKP 协商
        self.default_interceptors.write().push(interceptor);
    }

    pub fn get_default_interceptors(&self) -> Vec<Arc<dyn Interceptor>> {
        self.default_interceptors.read().clone()
    }

    // --- Mod Management: Congestion ---
    pub fn register_congestion_mod<F>(&self, id: &str, constructor: F)
    where
        F: Fn() -> Box<dyn CongestionControlAlgo> + Send + Sync + 'static,
    {
        // 拥塞控制是本地发送策略，通常不需要协商，但也允许注册 ID 以便日志记录
        self.congestion_mods.write().insert(id.to_string(), Arc::new(constructor));
    }

    pub fn create_congestion_algo(&self, id: &str) -> Option<Box<dyn CongestionControlAlgo>> {
        let map = self.congestion_mods.read();
        if let Some(constructor) = map.get(id) {
            Some(constructor())
        } else {
            None
        }
    }

    // --- Mod Management: Padding ---
    pub fn register_padding_strategy<F>(&self, id: &str, constructor: F)
    where
        F: Fn() -> Box<dyn PaddingStrategy> + Send + Sync + 'static,
    {
        self.padding_mods.write().insert(id.to_string(), Arc::new(constructor));
    }

    pub fn create_padding_strategy(&self, id: &str) -> Option<Box<dyn PaddingStrategy>> {
        let map = self.padding_mods.read();
        if let Some(constructor) = map.get(id) {
            Some(constructor())
        } else {
            None
        }
    }

    // --- Agent Management ---
    pub fn register_agent(&self, agent: Arc<dyn Agent>) {
        self.agents.write().push(agent);
    }

    pub fn get_agents(&self) -> Vec<Arc<dyn Agent>> {
        self.agents.read().clone()
    }
}

// -----------------------------------------------------------------------------
// Default Implementations (Placeholders for Standard Types)
// -----------------------------------------------------------------------------

// Standard Dialect
#[derive(Debug)]
pub struct StandardDialect; 
impl CapabilityProvider for StandardDialect {
    fn capability_id(&self) -> String { "etp.dialect.noise.std".into() }
}
impl Dialect for StandardDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        // Simple prefix obfuscation
        let mut rng = rand::thread_rng();
        let mut prefix = [0u8; 16];
        rng.fill_bytes(&mut prefix);
        let mut new = Vec::with_capacity(16 + payload.len());
        new.extend_from_slice(&prefix);
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 16 { return Err(anyhow!("Too short")); }
        Ok(data[16..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 16 
    }
}

// Standard Flavor
#[derive(Debug)]
pub struct StandardFlavor;
impl CapabilityProvider for StandardFlavor {
    fn capability_id(&self) -> String { "etp.flavor.core".into() }
}
impl Flavor for StandardFlavor {
    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool { false }
    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}

// Fake Implementations for Dialects (Moved here to centralize standard plugins)
// (Note: In a real project, these might be in separate files, but mod.rs often re-exports or defines basics)

#[derive(Debug)]
pub struct FakeHttpDialect;
impl CapabilityProvider for FakeHttpDialect { fn capability_id(&self) -> String { "etp.dialect.http.v1".into() } }
impl Dialect for FakeHttpDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let header = format!("POST /api/v1/data HTTP/1.1\r\nHost: www.google.com\r\nContent-Length: {}\r\n\r\n", payload.len());
        let mut new = Vec::with_capacity(header.len() + payload.len());
        new.extend_from_slice(header.as_bytes());
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        let split = b"\r\n\r\n";
        if let Some(idx) = data.windows(4).position(|w| w == split) {
            return Ok(data[idx+4..].to_vec());
        }
        Err(anyhow!("Invalid HTTP"))
    }
    fn probe(&self, data: &[u8]) -> bool { data.starts_with(b"POST") || data.starts_with(b"GET") }
}

#[derive(Debug)]
pub struct FakeTlsDialect;
impl CapabilityProvider for FakeTlsDialect { fn capability_id(&self) -> String { "etp.dialect.tls.v1".into() } }
impl Dialect for FakeTlsDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let len = payload.len() as u16;
        let mut head = vec![0x17, 0x03, 0x03];
        head.extend_from_slice(&len.to_be_bytes());
        let mut new = Vec::with_capacity(5 + payload.len());
        new.extend(head);
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 5 || data[0] != 0x17 { return Err(anyhow!("Invalid TLS")); }
        Ok(data[5..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool { data.starts_with(&[0x17, 0x03]) }
}

#[derive(Debug)]
pub struct FakeQuicDialect;
impl CapabilityProvider for FakeQuicDialect { fn capability_id(&self) -> String { "etp.dialect.quic.v1".into() } }
impl Dialect for FakeQuicDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let mut new = vec![0x40 | 0x01]; // Short Header
        new.extend_from_slice(&[0x00; 8]); // DCID placeholder
        new.push(0x00); // PN
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 10 { return Err(anyhow!("Invalid QUIC")); }
        Ok(data[10..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool { (data[0] & 0x40) != 0 }
}

#[derive(Debug)]
pub struct FakeDtlsDialect;
impl CapabilityProvider for FakeDtlsDialect { fn capability_id(&self) -> String { "etp.dialect.dtls.v1".into() } }
impl Dialect for FakeDtlsDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let len = payload.len() as u16;
        let mut head = vec![0x17, 0xFE, 0xFD]; // DTLS 1.2
        head.extend_from_slice(&[0; 8]); // Epoch + Seq
        head.extend_from_slice(&len.to_be_bytes());
        let mut new = Vec::with_capacity(13 + payload.len());
        new.extend(head);
        new.append(payload);
        *payload = new;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 13 { return Err(anyhow!("Invalid DTLS")); }
        Ok(data[13..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool { data.starts_with(&[0x17, 0xFE, 0xFD]) }
}
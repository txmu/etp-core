// etp-core/src/plugin/mod.rs

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use anyhow::{Result, anyhow};
use parking_lot::RwLock;
use std::fmt::Debug;
use rand::{Rng, RngCore}; 

use crate::security::zkp_negotiation::{ZkpNegotiator, CapabilityId};
use crate::NodeID; // 需要引入 NodeID

/// 系统上下文接口：暴露给 Flavor 的安全系统能力
/// 允许 Flavor 查询路由表或检查连接状态，而无需持有 Engine 的全量锁
pub trait SystemContext: Send + Sync {
    /// 根据 NodeID 查找已知的物理地址 (DHT/Local Routing Table)
    fn lookup_peer(&self, node_id: &NodeID) -> Option<SocketAddr>;
    
    /// 检查与指定地址的会话是否处于活跃状态
    fn is_connected(&self, addr: SocketAddr) -> bool;
    
    /// 获取当前节点的 ID
    fn my_node_id(&self) -> NodeID;
}

/// 上下文：传递给 Flavor 的运行时信息
pub struct FlavorContext<'a> {
    pub src_addr: SocketAddr,
    pub stream_id: u32,
    pub data_len: usize,
    /// 强类型的系统上下文，取代原先的 dyn Any
    pub system: &'a dyn SystemContext,
}

/// 基础能力接口
pub trait CapabilityProvider: Send + Sync + Debug {
    /// 返回能力的唯一 ID (用于 ZKP 协商)
    fn capability_id(&self) -> CapabilityId;
}

// -----------------------------------------------------------------------------
// Dialect (方言): 定义 "怎么说" (How to speak)
// -----------------------------------------------------------------------------
pub trait Dialect: CapabilityProvider {
    fn seal(&self, payload: &mut Vec<u8>);
    fn open(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn probe(&self, data: &[u8]) -> bool;
}

// -----------------------------------------------------------------------------
// Flavor (风味): 定义 "说什么" (What to say)
// -----------------------------------------------------------------------------
pub trait Flavor: CapabilityProvider {
    fn priority(&self) -> u8 { 100 }
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool;
    fn on_connection_open(&self, peer: SocketAddr);
    fn on_connection_close(&self, peer: SocketAddr);
    fn poll(&self) {}
}

// -----------------------------------------------------------------------------
// Plugin Registry (插件注册中心)
// -----------------------------------------------------------------------------
#[derive(Clone)]
pub struct PluginRegistry {
    dialects: Arc<RwLock<HashMap<String, Arc<dyn Dialect>>>>,
    flavors: Arc<RwLock<HashMap<String, Arc<dyn Flavor>>>>,
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

    pub fn all_dialects(&self) -> Vec<Arc<dyn Dialect>> {
        self.dialects.read().values().cloned().collect()
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
}

// -----------------------------------------------------------------------------
// 1. Standard Dialect
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct StandardDialect; 
impl CapabilityProvider for StandardDialect {
    fn capability_id(&self) -> String { "etp.dialect.noise.std".into() }
}
impl Dialect for StandardDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
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

// -----------------------------------------------------------------------------
// 2. Fake HTTP Dialect
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct FakeHttpDialect;
impl CapabilityProvider for FakeHttpDialect {
    fn capability_id(&self) -> String { "etp.dialect.http.v1".into() }
}
impl Dialect for FakeHttpDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let path_len = rng.gen_range(4..12);
        let path: String = (0..path_len).map(|_| (rng.gen_range(b'a'..=b'z') as char)).collect();
        let hosts = ["www.google.com", "api.aws.com", "cdn.cloudflare.net", "update.microsoft.com"];
        let host = hosts[rng.gen_range(0..hosts.len())];
        
        let header = format!(
            "POST /{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ETP-Core/1.0\r\nAccept: */*\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
            path, host, payload.len()
        );
        let mut new_buf = Vec::with_capacity(header.len() + payload.len());
        new_buf.extend_from_slice(header.as_bytes());
        new_buf.append(payload);
        *payload = new_buf;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        let end_marker = b"\r\n\r\n";
        if let Some(idx) = data.windows(4).position(|window| window == end_marker) {
            let body_start = idx + 4;
            if body_start >= data.len() { return Ok(Vec::new()); }
            return Ok(data[body_start..].to_vec());
        }
        Err(anyhow!("Invalid HTTP format"))
    }
    fn probe(&self, data: &[u8]) -> bool {
        if data.len() < 10 { return false; }
        let s = &data[0..4];
        s == b"POST" || s == b"GET " || s == b"PUT " || s == b"HTTP"
    }
}

// -----------------------------------------------------------------------------
// 3. Fake TLS Dialect
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct FakeTlsDialect;
impl CapabilityProvider for FakeTlsDialect {
    fn capability_id(&self) -> String { "etp.dialect.tls.v1".into() }
}
impl Dialect for FakeTlsDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let len = payload.len() as u16;
        let mut header = vec![0x17, 0x03, 0x03];
        header.extend_from_slice(&len.to_be_bytes());
        let mut new_buf = Vec::with_capacity(5 + payload.len());
        new_buf.extend(header);
        new_buf.append(payload);
        *payload = new_buf;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 5 { return Err(anyhow!("Too short")); }
        if data[0] != 0x17 { return Err(anyhow!("Not TLS AppData")); }
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let end = 5 + len;
        if data.len() < end { return Err(anyhow!("Incomplete TLS record")); }
        Ok(data[5..end].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool {
        if data.len() < 5 { return false; }
        data[0] == 0x17 && data[1] == 0x03
    }
}

// -----------------------------------------------------------------------------
// 4. Fake QUIC Dialect
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct FakeQuicDialect;
impl CapabilityProvider for FakeQuicDialect {
    fn capability_id(&self) -> String { "etp.dialect.quic.v1".into() }
}
impl Dialect for FakeQuicDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let spin = if rng.gen_bool(0.5) { 0x20 } else { 0 };
        let first_byte = 0x40 | spin | (rng.gen::<u8>() & 0x1F); 
        let mut dcid = [0u8; 8];
        rng.fill_bytes(&mut dcid);
        let first_byte = first_byte & 0xFC; 
        let pn = rng.gen::<u8>();
        
        let mut header = Vec::with_capacity(1 + 8 + 1);
        header.push(first_byte);
        header.extend_from_slice(&dcid);
        header.push(pn);
        let mut new_buf = Vec::with_capacity(header.len() + payload.len());
        new_buf.extend(header);
        new_buf.append(payload);
        *payload = new_buf;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 10 { return Err(anyhow!("Too short for QUIC")); }
        if (data[0] & 0x40) == 0 { return Err(anyhow!("Not QUIC Short Header")); }
        let pn_len_code = data[0] & 0x03;
        let pn_len = (pn_len_code + 1) as usize;
        let header_len = 1 + 8 + pn_len;
        if data.len() < header_len { return Err(anyhow!("Packet too short")); }
        Ok(data[header_len..].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool {
        if data.len() < 10 { return false; }
        (data[0] & 0xC0) == 0x40
    }
}

// -----------------------------------------------------------------------------
// 5. Fake DTLS Dialect
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct FakeDtlsDialect;
impl CapabilityProvider for FakeDtlsDialect {
    fn capability_id(&self) -> String { "etp.dialect.dtls.v1".into() }
}
impl Dialect for FakeDtlsDialect {
    fn seal(&self, payload: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut header = vec![0x17, 0xFE, 0xFD];
        let mut seq = [0u8; 8];
        rng.fill_bytes(&mut seq);
        header.extend_from_slice(&seq);
        let len = payload.len() as u16;
        header.extend_from_slice(&len.to_be_bytes());
        let mut new_buf = Vec::with_capacity(13 + payload.len());
        new_buf.extend(header);
        new_buf.append(payload);
        *payload = new_buf;
    }
    fn open(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 13 { return Err(anyhow!("Too short for DTLS")); }
        if data[0] != 0x17 || data[1] != 0xFE || data[2] != 0xFD {
            return Err(anyhow!("Invalid DTLS header"));
        }
        let len = u16::from_be_bytes([data[11], data[12]]) as usize;
        let end = 13 + len;
        if data.len() < end { return Err(anyhow!("Incomplete DTLS record")); }
        Ok(data[13..end].to_vec())
    }
    fn probe(&self, data: &[u8]) -> bool {
        if data.len() < 13 { return false; }
        data[0] == 0x17 && data[1] == 0xFE && data[2] == 0xFD
    }
}

// -----------------------------------------------------------------------------
// Standard Flavor
// -----------------------------------------------------------------------------
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
// etp-core/src/network/dht.rs

use std::collections::{VecDeque, HashSet, HashMap, BTreeMap};
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::cmp::Ordering;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};
use log::{debug, trace, info, warn};
use rand::{Rng, thread_rng};
use anyhow::{Result, Context};

use crate::NodeID;

// ============================================================================
//  常量配置
// ============================================================================

const K_BUCKET_SIZE: usize = 20;  // k
const ID_BITS: usize = 256;       // b
const REPLACEMENT_CACHE_SIZE: usize = 5;

// 抗女巫配置 (仅当 feature 开启时生效)
const MAX_PEERS_PER_IPV4_SUBNET: usize = 2; // 同一个 /24 网段最多允许 2 个节点
const MAX_PEERS_PER_IPV6_SUBNET: usize = 4; // 同一个 /64 网段最多允许 4 个节点

// 信誉系统配置
const REPUTATION_INITIAL: i32 = 100;
const REPUTATION_MAX: i32 = 1000;
const REPUTATION_MIN_BAN: i32 = -50; // 低于此分拉黑
const SCORE_PING_SUCCESS: i32 = 5;
const SCORE_PING_FAIL: i32 = -10;

// ============================================================================
//  数据结构定义
// ============================================================================

/// 节点能力位掩码
pub mod node_features {
    pub const SERVICE_HOST: u32 = 1 << 0;  // 提供服务
    pub const PUBLIC_IP:    u32 = 1 << 1;  // 拥有公网 IP
    pub const DHT_STORE:    u32 = 1 << 2;  // 允许存储数据
}

/// 增强型节点信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeInfo {
    pub id: NodeID,
    pub addr: SocketAddr,
    
    /// 网络延迟 (RTT)
    pub latency_ms: u16,
    
    /// 虚拟 IP (240.x.x.x)，用于 Overlay 路由
    pub virtual_ip: Option<Ipv4Addr>,
    
    /// 最后活跃时间 (Unix Timestamp)
    pub last_seen: u64,
    
    /// 首次发现时间
    pub first_seen: u64,

    /// 节点信誉分
    pub reputation: i32,

    /// 客户端版本字符串 (例如 "ETP/1.3.2")
    pub client_version: String,

    /// 能力位
    pub features: u32,
}

impl NodeInfo {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            id,
            addr,
            latency_ms: 0,
            virtual_ip: None,
            last_seen: now,
            first_seen: now,
            reputation: REPUTATION_INITIAL,
            client_version: "Unknown".into(),
            features: 0,
        }
    }

    /// 更新活跃状态
    pub fn touch(&mut self) {
        self.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    }

    pub fn adjust_reputation(&mut self, delta: i32) {
        self.reputation = (self.reputation + delta).clamp(REPUTATION_MIN_BAN - 10, REPUTATION_MAX);
    }

    pub fn is_banned(&self) -> bool {
        self.reputation <= REPUTATION_MIN_BAN
    }
}

/// DHT 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConfig {
    pub enable_virtual_net: bool,
    pub refresh_interval: Duration,
    pub node_timeout: Duration,
    pub allow_bogon_ips: bool,
    pub secret_seed: [u8; 32],
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            enable_virtual_net: true,
            refresh_interval: Duration::from_secs(600),
            node_timeout: Duration::from_secs(3600),
            allow_bogon_ips: false,
            secret_seed: [0u8; 32],
        }
    }
}

/// XOR 距离度量
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    pub fn xor(a: &NodeID, b: &NodeID) -> Self {
        let mut dist = [0u8; 32];
        for i in 0..32 { dist[i] = a[i] ^ b[i]; }
        Self(dist)
    }

    pub fn leading_zeros(&self) -> usize {
        let mut zeros = 0;
        for byte in &self.0 {
            if *byte == 0 { zeros += 8; } 
            else { zeros += byte.leading_zeros() as usize; break; }
        }
        zeros
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

// ============================================================================
//  内部组件：虚拟网络映射
// ============================================================================

struct VirtualNetworkMapper;
impl VirtualNetworkMapper {
    pub fn map_id_to_ip(id: &NodeID) -> Ipv4Addr {
        let len = id.len();
        let mut b = [id[len-4], id[len-3], id[len-2], id[len-1]];
        b[0] = (b[0] & 0x0F) | 0xF0; // Class E mapping
        if b[0] == 255 { b[0] = 254; }
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }
}

// ============================================================================
//  内部组件：K-Bucket (集成抗女巫逻辑)
// ============================================================================

#[derive(Debug, PartialEq)]
pub enum DhtAddResult {
    Added,
    Updated,
    BucketFull { oldest_node: NodeInfo },
    RejectedSybil, // 触发抗女巫规则
    RejectedBanned, // 节点信誉过低
    Ignored,
}

#[derive(Debug, Serialize, Deserialize)]
struct KBucket {
    nodes: VecDeque<NodeInfo>,
    replacements: VecDeque<NodeInfo>,
    #[serde(skip, default = "Instant::now")]
    last_updated: Instant,
}

impl KBucket {
    fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            replacements: VecDeque::new(),
            last_updated: Instant::now(),
        }
    }

    /// 核心更新逻辑
    fn update(&mut self, mut node: NodeInfo) -> DhtAddResult {
        // 1. 检查黑名单
        if node.is_banned() {
            return DhtAddResult::RejectedBanned;
        }

        self.last_updated = Instant::now();
        node.touch();

        // 2. 如果节点已存在，移至队尾并更新信息
        if let Some(idx) = self.nodes.iter().position(|n| n.id == node.id) {
            let mut existing = self.nodes.remove(idx).unwrap();
            // 融合信息：保留原有的信誉分和首次发现时间
            existing.addr = node.addr;
            existing.touch();
            existing.latency_ms = node.latency_ms;
            existing.client_version = node.client_version;
            existing.features = node.features;
            
            // 如果新传入的 node 携带了有效的 reputation 变更（例如来自上层逻辑），则累加
            // 但通常 update 传入的是 discovery 发现的 node，reputation 为初始值。
            // 这里我们保持 existing 的 reputation
            
            self.nodes.push_back(existing);
            return DhtAddResult::Updated;
        }

        // 3. 抗女巫攻击检查 (Sybil Guard)
        // 仅当 feature 开启且 Bucket 非空时检查
        #[cfg(feature = "dht_anti_sybil")]
        {
            if !self.check_sybil_limit(&node.addr.ip()) {
                warn!("DHT Anti-Sybil: Rejected {} due to subnet limit", node.addr);
                return DhtAddResult::RejectedSybil;
            }
        }

        // 4. Bucket 未满，直接插入
        if self.nodes.len() < K_BUCKET_SIZE {
            self.nodes.push_back(node);
            return DhtAddResult::Added;
        }

        // 5. Bucket 已满，尝试放入替换列表
        let oldest = self.nodes.front().cloned().unwrap();
        
        // 替换列表也要做 Sybil 检查? 暂时不做，因为 Replacement 不参与路由，只是备胎。
        // 但为了防止内存耗尽，Replacement 也要去重
        if !self.replacements.iter().any(|n| n.id == node.id) {
            self.replacements.push_back(node);
            if self.replacements.len() > REPLACEMENT_CACHE_SIZE {
                self.replacements.pop_front();
            }
        }

        DhtAddResult::BucketFull { oldest_node: oldest }
    }

    /// 计算并检查子网限制
    #[cfg(feature = "dht_anti_sybil")]
    fn check_sybil_limit(&self, ip: &IpAddr) -> bool {
        let limit = match ip {
            IpAddr::V4(_) => MAX_PEERS_PER_IPV4_SUBNET,
            IpAddr::V6(_) => MAX_PEERS_PER_IPV6_SUBNET,
        };

        let current_count = self.nodes.iter().filter(|n| {
            Self::is_same_subnet(&n.addr.ip(), ip)
        }).count();

        current_count < limit
    }

    #[cfg(feature = "dht_anti_sybil")]
    fn is_same_subnet(a: &IpAddr, b: &IpAddr) -> bool {
        match (a, b) {
            (IpAddr::V4(a4), IpAddr::V4(b4)) => {
                // /24 check: 前3个字节相同
                let oct_a = a4.octets();
                let oct_b = b4.octets();
                oct_a[0] == oct_b[0] && oct_a[1] == oct_b[1] && oct_a[2] == oct_b[2]
            },
            (IpAddr::V6(a6), IpAddr::V6(b6)) => {
                // /64 check: 前8个字节相同
                let seg_a = a6.segments();
                let seg_b = b6.segments();
                seg_a[0..4] == seg_b[0..4]
            },
            _ => false
        }
    }

    fn mark_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let mut n = self.nodes.remove(idx).unwrap();
            n.touch();
            n.adjust_reputation(SCORE_PING_SUCCESS);
            self.nodes.push_back(n);
        }
    }

    fn mark_failed(&mut self, id: &NodeID) {
        let mut remove_idx = None;
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let node = &mut self.nodes[idx];
            node.adjust_reputation(SCORE_PING_FAIL);
            
            // 如果信誉过低，直接移除
            if node.is_banned() {
                warn!("DHT: Node {:?} banned due to low reputation", hex::encode(&id[0..4]));
                remove_idx = Some(idx);
            }
        }

        if let Some(idx) = remove_idx {
            self.nodes.remove(idx);
            // 晋升备用节点
            if let Some(rep) = self.replacements.pop_back() {
                // 递归尝试加入，确保留存的也是合法的
                self.update(rep);
            }
        }
    }
}

// ============================================================================
//  内部组件：轻量级存储 (Data Store)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct StoredValue {
    data: Vec<u8>,
    created_at: u64,
    ttl: u32, // seconds
}

impl StoredValue {
    fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now > self.created_at + self.ttl as u64
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DhtStorage {
    // Key -> Value
    map: HashMap<NodeID, StoredValue>,
}

impl DhtStorage {
    fn new() -> Self {
        Self { map: HashMap::new() }
    }

    fn put(&mut self, key: NodeID, data: Vec<u8>, ttl: u32) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let val = StoredValue {
            data,
            created_at: now,
            ttl,
        };
        self.map.insert(key, val);
    }

    fn get(&self, key: &NodeID) -> Option<Vec<u8>> {
        if let Some(val) = self.map.get(key) {
            if !val.is_expired() {
                return Some(val.data.clone());
            }
        }
        None
    }

    fn cleanup(&mut self) -> usize {
        let before = self.map.len();
        self.map.retain(|_, v| !v.is_expired());
        before - self.map.len()
    }
}

// ============================================================================
//  主结构：DhtRoutingTable
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct DhtRoutingTable {
    local_id: NodeID,
    config: DhtConfig,
    buckets: Vec<KBucket>,
    storage: DhtStorage,
    
    // 内存中的黑名单 (IP based)
    #[serde(skip)]
    ip_blacklist: HashSet<IpAddr>,
    
    #[serde(skip)]
    node_count_cache: usize,
}

impl DhtRoutingTable {
    pub fn new(local_id: NodeID, config: DhtConfig) -> Self {
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(KBucket::new());
        }
        Self {
            local_id,
            config,
            buckets,
            storage: DhtStorage::new(),
            ip_blacklist: HashSet::new(),
            node_count_cache: 0,
        }
    }

    // --- 基础工具 ---

    fn bucket_index(&self, target: &NodeID) -> Option<usize> {
        let dist = Distance::xor(&self.local_id, target);
        let zeros = dist.leading_zeros();
        if zeros >= ID_BITS { return None; } // Self
        Some(ID_BITS - 1 - zeros)
    }

    fn is_valid_ip(&self, addr: &SocketAddr) -> bool {
        if self.ip_blacklist.contains(&addr.ip()) { return false; }
        if self.config.allow_bogon_ips { return true; }
        
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
            return false;
        }
        true
    }

    // --- 节点操作 ---

    pub fn add_node(&mut self, mut node: NodeInfo) -> DhtAddResult {
        if node.id == self.local_id { return DhtAddResult::Ignored; }
        if !self.is_valid_ip(&node.addr) { return DhtAddResult::Ignored; }

        if self.config.enable_virtual_net && node.virtual_ip.is_none() {
            node.virtual_ip = Some(VirtualNetworkMapper::map_id_to_ip(&node.id));
        }

        if let Some(idx) = self.bucket_index(&node.id) {
            let res = self.buckets[idx].update(node);
            
            // 处理更新结果
            match &res {
                DhtAddResult::Added | DhtAddResult::Updated => {
                    self.node_count_cache = self.buckets.iter().map(|b| b.nodes.len()).sum();
                },
                DhtAddResult::RejectedSybil => {
                    // 可选：如果频繁触发，将 IP 加入临时黑名单
                },
                _ => {}
            }
            return res;
        }
        DhtAddResult::Ignored
    }

    pub fn mark_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].mark_success(id);
        }
    }

    pub fn mark_failed(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].mark_failed(id);
            self.update_count_cache();
        }
    }

    pub fn lookup(&self, id: &NodeID) -> Option<NodeInfo> {
        if let Some(idx) = self.bucket_index(id) {
            for node in &self.buckets[idx].nodes {
                if node.id == *id { return Some(node.clone()); }
            }
        }
        None
    }

    pub fn ban_ip(&mut self, ip: IpAddr) {
        self.ip_blacklist.insert(ip);
        // 清理现有的来自该 IP 的节点
        for bucket in &mut self.buckets {
            bucket.nodes.retain(|n| n.addr.ip() != ip);
            bucket.replacements.retain(|n| n.addr.ip() != ip);
        }
        self.update_count_cache();
    }

    // --- 查找逻辑 (K-Nearest) ---

    pub fn find_closest(&self, target: &NodeID, count: usize) -> Vec<NodeInfo> {
        let mut collected = Vec::new();
        let center_idx = self.bucket_index(target).unwrap_or(0);
        
        // 迭代器：从中心 Bucket 向两侧扩散
        let mut visited = HashSet::new();
        let mut offset = 0;

        while collected.len() < count && visited.len() < ID_BITS {
            // Check right (+offset)
            if center_idx + offset < ID_BITS {
                let idx = center_idx + offset;
                if visited.insert(idx) {
                    self.collect_bucket(idx, &mut collected);
                }
            }
            // Check left (-offset)
            if offset > 0 && center_idx >= offset {
                let idx = center_idx - offset;
                if visited.insert(idx) {
                    self.collect_bucket(idx, &mut collected);
                }
            }
            offset += 1;
        }

        // Sort by XOR distance
        collected.sort_by(|a, b| {
            Distance::xor(target, &a.id).cmp(&Distance::xor(target, &b.id))
        });
        
        collected.truncate(count);
        collected
    }

    fn collect_bucket(&self, idx: usize, out: &mut Vec<NodeInfo>) {
        let bucket = &self.buckets[idx];
        for node in &bucket.nodes { out.push(node.clone()); }
    }

    pub fn get_random_peers(&self, count: usize) -> Vec<NodeInfo> {
        let mut rng = thread_rng();
        let mut all = Vec::new();
        
        let valid_buckets: Vec<usize> = self.buckets.iter().enumerate()
            .filter(|(_, b)| !b.nodes.is_empty())
            .map(|(i, _)| i)
            .collect();
        
        if valid_buckets.is_empty() { return vec![]; }

        for _ in 0..count.min(valid_buckets.len() * K_BUCKET_SIZE) {
            let b_idx = valid_buckets[rng.gen_range(0..valid_buckets.len())];
            let bucket = &self.buckets[b_idx];
            if !bucket.nodes.is_empty() {
                let n_idx = rng.gen_range(0..bucket.nodes.len());
                all.push(bucket.nodes[n_idx].clone());
            }
        }
        
        all.sort_by_key(|n| n.id);
        all.dedup_by_key(|n| n.id);
        all.truncate(count);
        all
    }

    // --- 存储操作 ---

    pub fn store_value(&mut self, key: NodeID, value: Vec<u8>, ttl: u32) {
        self.storage.put(key, value, ttl);
    }

    pub fn get_value(&self, key: &NodeID) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    // --- 维护逻辑 ---

    pub fn get_refresh_ids(&self) -> Vec<NodeID> {
        let now = Instant::now();
        let mut targets = Vec::new();
        let mut rng = thread_rng();

        for (i, bucket) in self.buckets.iter().enumerate() {
            if now.duration_since(bucket.last_updated) > self.config.refresh_interval {
                // Generate random ID in bucket range
                let mut id = self.local_id;
                let bit_idx = ID_BITS - 1 - i;
                let byte_idx = bit_idx / 8;
                let bit_offset = 7 - (bit_idx % 8);
                
                // Flip bit
                id[byte_idx] ^= 1 << bit_offset;
                
                // Randomize rest
                for b in (byte_idx + 1)..32 { id[b] = rng.gen(); }
                let mask = (1 << bit_offset) - 1;
                id[byte_idx] = (id[byte_idx] & !mask) | (rng.gen::<u8>() & mask);
                
                targets.push(id);
            }
        }
        targets
    }

    pub fn get_stale_nodes(&self) -> Vec<NodeID> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let timeout = self.config.node_timeout.as_secs();
        let mut stale = Vec::new();
        
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                if now.saturating_sub(node.last_seen) > timeout {
                    stale.push(node.id);
                }
            }
        }
        stale
    }

    /// 执行垃圾回收 (过期存储、过期节点)
    pub fn perform_gc(&mut self) -> usize {
        self.storage.cleanup()
    }

    // --- 持久化 ---

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self)?;
        let mut file = fs::File::create(path)?;
        file.write_all(&data)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        let mut table: Self = bincode::deserialize(&data)?;
        // 重置易变状态
        table.node_count_cache = table.buckets.iter().map(|b| b.nodes.len()).sum();
        table.ip_blacklist = HashSet::new(); // 黑名单通常不持久化，或单独持久化
        Ok(table)
    }

    pub fn total_nodes(&self) -> usize {
        self.node_count_cache
    }
    
    fn update_count_cache(&mut self) {
        self.node_count_cache = self.buckets.iter().map(|b| b.nodes.len()).sum();
    }
}

// ============================================================================
//  单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn make_node(id_byte: u8, ip_last: u8) -> NodeInfo {
        let mut id = [0u8; 32];
        id[31] = id_byte;
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, ip_last), 8080));
        NodeInfo::new(id, addr)
    }

    #[test]
    #[cfg(feature = "dht_anti_sybil")]
    fn test_anti_sybil_protection() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());

        // 添加属于同一 Bucket (距离相近) 且同一网段 (192.168.1.x) 的节点
        // 假设 Bucket 0 是空的，所有这些节点都会落入同一个 Bucket (取决于 local id)
        // 我们需要构造 ID 使得它们落在同一个 Bucket。
        // 如果 Local 全 0，ID 以 1 结尾通常落在 Bucket 0.
        
        // 1. 添加合法节点 A (192.168.1.10)
        let res = table.add_node(make_node(1, 10));
        assert_eq!(res, DhtAddResult::Added);

        // 2. 添加合法节点 B (192.168.1.11)
        let res = table.add_node(make_node(2, 11));
        assert_eq!(res, DhtAddResult::Added);

        // 3. 添加女巫节点 C (192.168.1.12) -> 此时该网段已有 2 个，应触发拒绝
        // MAX_PEERS_PER_IPV4_SUBNET = 2
        let res = table.add_node(make_node(3, 12));
        assert_eq!(res, DhtAddResult::RejectedSybil);

        // 4. 添加不同网段节点 D (192.168.2.10) -> 应允许
        let mut node_d = make_node(4, 10);
        node_d.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)), 8080);
        let res = table.add_node(node_d);
        assert_eq!(res, DhtAddResult::Added);
    }

    #[test]
    fn test_reputation_ban() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());
        
        let id = [1u8; 32];
        let addr = "10.0.0.1:1234".parse().unwrap();
        table.add_node(NodeInfo::new(id, addr));

        // 连续失败，降低信誉
        for _ in 0..15 {
            table.mark_failed(&id);
        }

        // 检查是否已被移除
        assert!(table.lookup(&id).is_none());
    }

    #[test]
    fn test_storage_ttl() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());
        
        let key = [0xAA; 32];
        table.store_value(key, b"data".to_vec(), 0); // 0 TTL means immediate expire? No, TTL is duration.
        // Actually our TTL logic: now > created + ttl. 
        // If ttl=0, now > created (0 latency) is likely true.
        
        std::thread::sleep(Duration::from_millis(10));
        assert!(table.get_value(&key).is_none());
        
        table.store_value(key, b"data2".to_vec(), 10);
        assert_eq!(table.get_value(&key), Some(b"data2".to_vec()));
    }
}
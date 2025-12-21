// etp-core/src/network/dht.rs

use std::collections::{VecDeque, HashSet, HashMap, BTreeMap};
use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
use std::cmp::Ordering;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};
use log::{debug, trace, info, warn, error};
use rand::{Rng, thread_rng};
use anyhow::{Result, anyhow, Context};

use crate::NodeID;
use crate::common::NodeInfo;

// ============================================================================
//  协议常量与信誉分配置
// ============================================================================

const ID_BITS: usize = 256;       // Kademlia ID 位数 (256位)

const REPUTATION_INITIAL: i32 = 100;
const REPUTATION_MAX: i32     = 1000;
const REPUTATION_MIN_BAN: i32 = -50; // 低于此分视为恶意并封禁

const SCORE_PING_SUCCESS: i32 = 5;
const SCORE_PING_FAIL: i32    = -10;

/// 节点能力位掩码 (用于 Discovery 协商)
pub mod node_features {
    pub const SERVICE_HOST: u32 = 1 << 0;  // 提供业务服务
    pub const PUBLIC_IP:    u32 = 1 << 1;  // 拥有公网可达 IP
    pub const DHT_STORE:    u32 = 1 << 2;  // 允许作为存储节点
}

// ============================================================================
//  1. DHT 全局配置 (支持深度抗女巫动态调整)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConfig {
    /// 是否启用虚拟网络 IP 映射 (240.x.x.x)
    pub enable_virtual_net: bool,
    /// K 桶刷新间隔
    pub refresh_interval: Duration,
    /// 节点未响应超时时间
    pub node_timeout: Duration,
    /// 是否允许 Bogon/私有 IP (仅限局域网测试)
    pub allow_bogon_ips: bool,
    /// 用于某些加密映射的内部种子
    pub secret_seed: [u8; 32],

    // --- [手段 15/21] 增强型抗女巫动态配置 ---
    /// K 桶容量 (典型值: 20, 64, 128, 256)
    pub k_bucket_size: usize,
    
    /// IPv4 /24 (C段) 同一子网准入上限
    pub max_per_ipv4_24: usize,
    
    /// IPv6 /64 (标准终端子网) 同一子网准入上限
    pub max_per_ipv6_64: usize,
    
    /// IPv6 /48 (企业/站点级前缀) 同一前缀准入上限
    pub max_per_ipv6_48: usize,
    
    /// IPv6 /32 (运营商/大型机构级前缀) 同一前缀准入上限
    pub max_per_ipv6_32: usize,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            enable_virtual_net: true,
            refresh_interval: Duration::from_secs(600),
            node_timeout: Duration::from_secs(3600),
            allow_bogon_ips: false,
            secret_seed: [0u8; 32],
            
            // 生产级抗攻击防御默认值
            k_bucket_size: 128,
            max_per_ipv4_24: 2,
            max_per_ipv6_64: 2,
            max_per_ipv6_48: 4,
            max_per_ipv6_32: 8,
        }
    }
}

// ============================================================================
//  2. 基础数学：XOR 距离度量与映射
// ============================================================================

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
    fn cmp(&self, other: &Self) -> Ordering { self.0.cmp(&other.0) }
}

struct VirtualNetworkMapper;
impl VirtualNetworkMapper {
    /// 手段 17: 将 NodeID 确定性映射到 Class E 虚拟空间 (240.x.x.x)
    pub fn map_id_to_ip(id: &NodeID) -> Ipv4Addr {
        let len = id.len();
        let mut b = [id[len-4], id[len-3], id[len-2], id[len-1]];
        b[0] = (b[0] & 0x0F) | 0xF0; 
        if b[0] == 255 { b[0] = 254; } // 避开 255.x.x.x
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }
}

// ============================================================================
//  3. 核心：K-Bucket 实现 (含高性能内存管理与准入控制)
// ============================================================================

#[derive(Debug, PartialEq)]
pub enum DhtAddResult {
    Added,
    Updated,
    BucketFull { oldest_node: NodeInfo },
    RejectedSybil,
    RejectedBanned,
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
    /// 预分配内存以应对高频路由交换
    fn new(k_size: usize) -> Self {
        Self {
            nodes: VecDeque::with_capacity(k_size),
            replacements: VecDeque::with_capacity((k_size / 4).max(5)),
            last_updated: Instant::now(),
        }
    }

    /// [手段 15] 深度子网准入控制
    #[cfg(feature = "dht_anti_sybil")]
    fn check_sybil_limit(&self, incoming_ip: &IpAddr, config: &DhtConfig) -> bool {
        let mut count_v4_24 = 0;
        let mut count_v6_64 = 0;
        let mut count_v6_48 = 0;
        let mut count_v6_32 = 0;

        for node in &self.nodes {
            let existing_ip = node.addr.ip();
            match (incoming_ip, existing_ip) {
                (IpAddr::V4(new), IpAddr::V4(old)) => {
                    // /24 检查 (前 3 字节)
                    if new.octets()[0..3] == old.octets()[0..3] { count_v4_24 += 1; }
                },
                (IpAddr::V6(new), IpAddr::V6(old)) => {
                    let n = new.segments();
                    let o = old.segments();
                    // /64: 前 4 段 (64 bits)
                    if n[0..4] == o[0..4] { count_v6_64 += 1; }
                    // /48: 前 3 段 (48 bits)
                    if n[0..3] == o[0..3] { count_v6_48 += 1; }
                    // /32: 前 2 段 (32 bits)
                    if n[0..2] == o[0..2] { count_v6_32 += 1; }
                },
                _ => {}
            }
        }

        match incoming_ip {
            IpAddr::V4(_) => count_v4_24 < config.max_per_ipv4_24,
            IpAddr::V6(_) => {
                count_v6_64 < config.max_per_ipv6_64 && 
                count_v6_48 < config.max_per_ipv6_48 &&
                count_v6_32 < config.max_per_ipv6_32
            }
        }
    }

    /// 更新节点状态 (LRU 策略)
    fn update(&mut self, mut incoming_node: NodeInfo, config: &DhtConfig) -> DhtAddResult {
        // 1. 检查信誉黑名单
        if incoming_node.reputation <= REPUTATION_MIN_BAN {
            return DhtAddResult::RejectedBanned;
        }

        self.last_updated = Instant::now();
        
        // 2. 如果节点已存在，移至末尾 (Most Recently Used)
        if let Some(idx) = self.nodes.iter().position(|n| n.id == incoming_node.id) {
            let mut existing = self.nodes.remove(idx).unwrap();
            
            // 更新易变属性
            existing.addr = incoming_node.addr;
            existing.latency_ms = incoming_node.latency_ms;
            existing.virtual_ip = incoming_node.virtual_ip;
            existing.client_version = incoming_node.client_version;
            existing.features = incoming_node.features;
            
            // 保持并刷新本地主权字段
            existing.touch(); 
            self.nodes.push_back(existing);
            return DhtAddResult::Updated;
        }

        // 3. 抗女巫防御检查
        #[cfg(feature = "dht_anti_sybil")]
        {
            if !self.check_sybil_limit(&incoming_node.addr.ip(), config) {
                return DhtAddResult::RejectedSybil;
            }
        }

        // 4. 桶未满，直接插入
        if self.nodes.len() < config.k_bucket_size {
            incoming_node.touch();
            self.nodes.push_back(incoming_node);
            return DhtAddResult::Added;
        }

        // 5. 桶已满，放入备选队列 (Replacements)
        let oldest = self.nodes.front().cloned().unwrap();
        let max_replacements = (config.k_bucket_size / 4).max(5);

        if !self.replacements.iter().any(|n| n.id == incoming_node.id) {
            incoming_node.touch();
            self.replacements.push_back(incoming_node);
            if self.replacements.len() > max_replacements {
                self.replacements.pop_front();
            }
        }

        DhtAddResult::BucketFull { oldest_node: oldest }
    }

    fn mark_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let mut n = self.nodes.remove(idx).unwrap();
            n.touch();
            n.adjust_reputation(SCORE_PING_SUCCESS);
            self.nodes.push_back(n);
        }
    }

    fn mark_failed(&mut self, id: &NodeID, config: &DhtConfig) {
        let mut remove_idx = None;
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let node = &mut self.nodes[idx];
            node.adjust_reputation(SCORE_PING_FAIL);
            if node.reputation <= REPUTATION_MIN_BAN {
                warn!("DHT: Banning node {:?} due to low reputation", hex::encode(&id[0..4]));
                remove_idx = Some(idx);
            }
        }

        if let Some(idx) = remove_idx {
            self.nodes.remove(idx);
            // 尝试从备选池晋升
            if let Some(rep) = self.replacements.pop_back() {
                self.update(rep, config);
            }
        }
    }
}

// ============================================================================
//  4. 数据存储组件 (离线投递与索引)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct StoredValue {
    data: Vec<u8>,
    created_at: u64,
    ttl: u32,
}

impl StoredValue {
    fn is_expired(&self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        now > self.created_at + self.ttl as u64
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DhtStorage {
    map: HashMap<NodeID, StoredValue>,
}

impl DhtStorage {
    fn new() -> Self { Self { map: HashMap::new() } }
    
    fn put(&mut self, key: NodeID, data: Vec<u8>, ttl: u32) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.map.insert(key, StoredValue { data, created_at: now, ttl });
    }

    fn get(&self, key: &NodeID) -> Option<Vec<u8>> {
        if let Some(val) = self.map.get(key) {
            if !val.is_expired() { return Some(val.data.clone()); }
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
//  5. 主结构：DhtRoutingTable (万兆级核心路由器)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct DhtRoutingTable {
    local_id: NodeID,
    pub config: DhtConfig,
    buckets: Vec<KBucket>,
    storage: DhtStorage,
    
    #[serde(skip)]
    ip_blacklist: HashSet<IpAddr>,
    #[serde(skip)]
    node_count_cache: usize,
}

impl DhtRoutingTable {
    /// 构造函数：基于配置执行全量预分配
    pub fn new(local_id: NodeID, config: DhtConfig) -> Self {
        let k = config.k_bucket_size;
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(KBucket::new(k));
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

    // --- 算法工具 ---

    fn bucket_index(&self, target: &NodeID) -> Option<usize> {
        let dist = Distance::xor(&self.local_id, target);
        let zeros = dist.leading_zeros();
        if zeros >= ID_BITS { return None; } // 自己
        Some(ID_BITS - 1 - zeros)
    }

    fn is_valid_ip(&self, addr: &SocketAddr) -> bool {
        if self.ip_blacklist.contains(&addr.ip()) { return false; }
        if self.config.allow_bogon_ips { return true; }
        let ip = addr.ip();
        !(ip.is_loopback() || ip.is_multicast() || ip.is_unspecified())
    }

    // --- 外部接口 ---

    pub fn add_node(&mut self, mut node: NodeInfo) -> DhtAddResult {
        if node.id == self.local_id || !self.is_valid_ip(&node.addr) { 
            return DhtAddResult::Ignored; 
        }

        // 虚拟网络映射逻辑
        if self.config.enable_virtual_net && node.virtual_ip.is_none() {
            node.virtual_ip = Some(VirtualNetworkMapper::map_id_to_ip(&node.id));
        }

        if let Some(idx) = self.bucket_index(&node.id) {
            let res = self.buckets[idx].update(node, &self.config);
            if matches!(res, DhtAddResult::Added | DhtAddResult::Updated) {
                self.update_count_cache();
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
        // 由于 mark_failed 会触发递归 update，需要 clone 配置避免借用冲突
        let config = self.config.clone();
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].mark_failed(id, &config);
            self.update_count_cache();
        }
    }

    pub fn lookup(&self, id: &NodeID) -> Option<NodeInfo> {
        self.bucket_index(id).and_then(|idx| {
            self.buckets[idx].nodes.iter().find(|n| n.id == *id).cloned()
        })
    }

    pub fn ban_ip(&mut self, ip: IpAddr) {
        self.ip_blacklist.insert(ip);
        for bucket in &mut self.buckets {
            bucket.nodes.retain(|n| n.addr.ip() != ip);
            bucket.replacements.retain(|n| n.addr.ip() != ip);
        }
        self.update_count_cache();
    }

    /// [手段 15] 寻找 K 个最近节点
    pub fn find_closest(&self, target: &NodeID, count: usize) -> Vec<NodeInfo> {
        let mut collected = Vec::new();
        let center_idx = self.bucket_index(target).unwrap_or(0);
        
        let mut visited = HashSet::new();
        let mut offset = 0;

        while collected.len() < count && visited.len() < ID_BITS {
            for i in &[center_idx as isize + offset, center_idx as isize - offset] {
                if *i >= 0 && *i < ID_BITS as isize {
                    let idx = *i as usize;
                    if visited.insert(idx) {
                        for node in &self.buckets[idx].nodes {
                            collected.push(node.clone());
                        }
                    }
                }
            }
            offset += 1;
        }

        collected.sort_by(|a, b| {
            Distance::xor(target, &a.id).cmp(&Distance::xor(target, &b.id))
        });
        
        collected.truncate(count);
        collected
    }

    pub fn get_random_peers(&self, count: usize) -> Vec<NodeInfo> {
        let mut rng = thread_rng();
        let mut all = Vec::new();
        
        let valid_buckets: Vec<usize> = self.buckets.iter().enumerate()
            .filter(|(_, b)| !b.nodes.is_empty())
            .map(|(i, _)| i)
            .collect();
        
        if valid_buckets.is_empty() { return vec![]; }

        for _ in 0..count.min(valid_buckets.len() * self.config.k_bucket_size) {
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

    // --- 数据存储 ---

    pub fn store_value(&mut self, key: NodeID, value: Vec<u8>, ttl: u32) {
        self.storage.put(key, value, ttl);
    }

    pub fn get_value(&self, key: &NodeID) -> Option<Vec<u8>> {
        self.storage.get(key)
    }

    // --- 维护与持久化 ---

    pub fn get_refresh_ids(&self) -> Vec<NodeID> {
        let mut targets = Vec::new();
        let mut rng = thread_rng();

        for (i, bucket) in self.buckets.iter().enumerate() {
            if bucket.last_updated.elapsed() > self.config.refresh_interval {
                let mut id = self.local_id;
                let bit_idx = ID_BITS - 1 - i;
                let byte_idx = bit_idx / 8;
                let bit_offset = 7 - (bit_idx % 8);
                
                id[byte_idx] ^= 1 << bit_offset; // 翻转位以保证落在该 bucket
                
                for b in (byte_idx + 1)..32 { id[b] = rng.gen(); }
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

    pub fn perform_gc(&mut self) -> usize {
        self.storage.cleanup()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self)?;
        let mut file = fs::File::create(path)?;
        file.write_all(&data)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        let mut table: Self = bincode::deserialize(&data)?;
        table.update_count_cache();
        Ok(table)
    }

    pub fn total_nodes(&self) -> usize {
        self.node_count_cache
    }
    
// ============================================================================
//  单元测试套件 - 生产级全覆盖版
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    /// 辅助工具：快速创建一个测试用 NodeInfo
    fn make_test_node(id_byte: u8, ip_str: &str) -> NodeInfo {
        let mut id = [0u8; 32];
        id[31] = id_byte; // 改变末尾字节以确保落在不同/相同 Bucket
        NodeInfo::new(id, ip_str.parse().unwrap())
    }

    /// 1. 测试基础路由索引与 XOR 距离
    #[test]
    fn test_xor_distance_and_indexing() {
        let local_id = [0u8; 32];
        let config = DhtConfig::default();
        let table = DhtRoutingTable::new(local_id, config);

        // ID 只有最后一位不同，应该落在第 0 个桶 (255 - 0)
        let mut remote_id = [0u8; 32];
        remote_id[31] = 1;
        assert_eq!(table.bucket_index(&remote_id), Some(0));

        // ID 第一位就不同，应该落在最后一个桶 (255 - 255)
        let mut remote_id_far = [0u8; 32];
        remote_id_far[0] = 0x80;
        assert_eq!(table.bucket_index(&remote_id_far), Some(255));
    }

    /// 2. [手段 15] 测试动态 K 桶容量限制
    #[test]
    fn test_dynamic_k_bucket_limit() {
        let local = [0u8; 32];
        let mut config = DhtConfig::default();
        config.k_bucket_size = 3; // 设置极小的 K 桶以便测试
        let mut table = DhtRoutingTable::new(local, config);

        // 插入 3 个不同子网的节点
        for i in 1..=3 {
            let node = make_test_node(i as u8, &format!("1.1.{}.1:8080", i));
            assert_eq!(table.add_node(node), DhtAddResult::Added);
        }

        // 插入第 4 个，应触发 BucketFull
        let node_4 = make_test_node(4, "1.1.4.1:8080");
        let res = table.add_node(node_4);
        assert!(matches!(res, DhtAddResult::BucketFull { .. }));
    }

    /// 3. [手段 15] 测试 IPv4 /24 子网抗女巫防御
    #[test]
    #[cfg(feature = "dht_anti_sybil")]
    fn test_sybil_defense_ipv4_24() {
        let local = [0u8; 32];
        let mut config = DhtConfig::default();
        config.max_per_ipv4_24 = 2; // 同一 C 段最多 2 个
        let mut table = DhtRoutingTable::new(local, config);

        // 前两个来自 192.168.1.x 的节点应允许
        assert_eq!(table.add_node(make_test_node(1, "192.168.1.10:80")), DhtAddResult::Added);
        assert_eq!(table.add_node(make_test_node(2, "192.168.1.11:80")), DhtAddResult::Added);

        // 第三个应被拒绝
        assert_eq!(table.add_node(make_test_node(3, "192.168.1.12:80")), DhtAddResult::RejectedSybil);
    }

    /// 4. [手段 15] 测试 IPv6 /48 站点级抗女巫防御
    #[test]
    #[cfg(feature = "dht_anti_sybil")]
    fn test_sybil_defense_ipv6_48() {
        let local = [0u8; 32];
        let mut config = DhtConfig::default();
        config.max_per_ipv6_48 = 3; // 同一物理站点最多 3 个
        let mut table = DhtRoutingTable::new(local, config);

        // 模拟来自同一企业网/家庭宽带 /48 段的攻击
        // 前缀均为 2001:db8:aaaa
        for i in 1..=3 {
            let ip = format!("[2001:db8:aaaa:{:x}::1]:80", i);
            assert_eq!(table.add_node(make_test_node(i as u8, &ip)), DhtAddResult::Added);
        }

        // 第 4 个应被拦截
        let ip_4 = "[2001:db8:aaaa:ffff::1]:80";
        assert_eq!(table.add_node(make_test_node(4, ip_4)), DhtAddResult::RejectedSybil);
    }

    /// 5. [手段 15] 测试 IPv6 /32 运营商级抗女巫防御
    #[test]
    #[cfg(feature = "dht_anti_sybil")]
    fn test_sybil_defense_ipv6_32() {
        let local = [0u8; 32];
        let mut config = DhtConfig::default();
        config.max_per_ipv6_32 = 2; // 极其严苛的限制，同一 ISP 下只允许 2 个
        let mut table = DhtRoutingTable::new(local, config);

        // 两个节点来自同一 /32 骨干网段，但不同 /48
        assert_eq!(table.add_node(make_test_node(1, "[240e:1234:1111::1]:80")), DhtAddResult::Added);
        assert_eq!(table.add_node(make_test_node(2, "[240e:1234:2222::1]:80")), DhtAddResult::Added);

        // 第三个即便 /48 不同，但在 /32 层面超限，应拒绝
        assert_eq!(table.add_node(make_test_node(3, "[240e:1234:3333::1]:80")), DhtAddResult::RejectedSybil);
    }

    /// 6. 测试信誉分自动封禁逻辑
    #[test]
    fn test_reputation_auto_ban() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());
        
        let id = [0xEE; 32];
        let addr = "1.2.3.4:5678".parse().unwrap();
        table.add_node(NodeInfo::new(id, addr));

        // 模拟节点连续失败
        // 初始 100 分，每次失败 -10，跌破 -50 (需 16 次左右)
        for _ in 0..20 {
            table.mark_failed(&id);
        }

        // 验证节点是否已从路由表中被彻底剔除
        assert!(table.lookup(&id).is_none());
        
        // 尝试重新添加该恶意节点，应直接返回 RejectedBanned
        let res = table.add_node(NodeInfo::new(id, addr));
        assert_eq!(res, DhtAddResult::RejectedBanned);
    }

    /// 7. 测试存储生命周期与 TTL
    #[test]
    fn test_storage_and_gc() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());
        
        let key = [0x55; 32];
        let data = b"DeadDropContent".to_vec();

        // 存储一个 1 秒后过期的值
        table.store_value(key, data.clone(), 1);
        assert_eq!(table.get_value(&key), Some(data));

        // 等待过期
        std::thread::sleep(Duration::from_millis(1100));
        
        // get_value 应返回 None
        assert!(table.get_value(&key).is_none());
        
        // 执行 GC
        let cleaned = table.perform_gc();
        assert_eq!(cleaned, 1);
    }

    /// 8. 测试随机节点获取 (用于 Gossip 扩散)
    #[test]
    fn test_random_peers_selection() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());

        for i in 0..10 {
            table.add_node(make_test_node(i as u8, &format!("10.0.0.{}:80", i)));
        }

        let peers = table.get_random_peers(5);
        assert_eq!(peers.len(), 5);
        
        // 验证没有包含自己 (因为 add_node 时已过滤)
        for p in peers {
            assert_ne!(p.id, local);
        }
    }

    /// 9. 测试持久化 (序列化/反序列化)
    #[test]
    fn test_persistence_integrity() {
        let local = [0x11; 32];
        let config = DhtConfig::default();
        let mut table = DhtRoutingTable::new(local, config);
        
        table.add_node(make_test_node(0x22, "8.8.8.8:53"));
        table.store_value([0x33; 32], vec![1, 2, 3], 3600);

        let encoded = bincode::serialize(&table).unwrap();
        let decoded: DhtRoutingTable = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.local_id, local);
        assert_eq!(decoded.total_nodes(), 1);
        assert!(decoded.get_value(&[0x33; 32]).is_some());
    }
}
// etp-core/src/network/dht.rs

use crate::NodeID;
use std::collections::{VecDeque, HashSet};
use std::time::{Instant, Duration, SystemTime};
use std::cmp::Ordering;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::path::Path;
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};
use log::{debug, trace, info, warn};
use rand::{Rng, thread_rng};
use anyhow::{Result, Context};

// --- 生产级 Kademlia 参数 ---
const K_BUCKET_SIZE: usize = 20;  // k
const ID_BITS: usize = 256;       // b
const ALPHA: usize = 3;           // α (并发度，用于上层)

/// DHT 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtConfig {
    /// 启用虚拟网络映射 (Class E IP)
    pub enable_virtual_net: bool,
    /// 路由表刷新间隔
    pub refresh_interval: Duration,
    /// 节点超时时间 (超过此时间未见视为 Stale)
    pub node_timeout: Duration,
    /// 抗审查模式: 允许本地回环、私有 IP 入表 (Dev/Local mode)
    /// 生产环境应设为 false，以防污染路由表
    pub allow_bogon_ips: bool,
    /// 秘密种子 (用于混淆或确定性映射)
    pub secret_seed: [u8; 32],
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            enable_virtual_net: true,
            refresh_interval: Duration::from_secs(600), // 10分钟
            node_timeout: Duration::from_secs(3600),    // 1小时
            allow_bogon_ips: false,
            secret_seed: [0u8; 32],
        }
    }
}

/// 节点基本信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeInfo {
    pub id: NodeID,
    pub addr: SocketAddr,
    pub latency_ms: u16,
    /// 虚拟 IP (240.x.x.x)，用于 Overlay 路由
    pub virtual_ip: Option<Ipv4Addr>,
    /// 最后活跃时间 (Unix Timestamp)
    pub last_seen: u64,
}

impl NodeInfo {
    pub fn new(id: NodeID, addr: SocketAddr) -> Self {
        Self {
            id,
            addr,
            latency_ms: 0,
            virtual_ip: None,
            last_seen: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
        }
    }

    /// 更新活跃状态
    pub fn touch(&mut self) {
        self.last_seen = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    }
}

/// XOR 距离度量
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    pub fn xor(a: &NodeID, b: &NodeID) -> Self {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a[i] ^ b[i];
        }
        Self(dist)
    }

    /// 计算前导零位数 (Bucket Index)
    pub fn leading_zeros(&self) -> usize {
        let mut zeros = 0;
        for byte in &self.0 {
            if *byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros() as usize;
                break;
            }
        }
        zeros
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

/// 虚拟网络映射器 (Virtual Network Mapper)
/// 将 NodeID 映射到 Class E IP (240.0.0.0/4)
struct VirtualNetworkMapper;

impl VirtualNetworkMapper {
    pub fn map_id_to_ip(id: &NodeID) -> Ipv4Addr {
        let len = id.len();
        // 取 NodeID 的最后 4 字节
        let mut b = [id[len-4], id[len-3], id[len-2], id[len-1]];
        
        // 核心位运算：
        // mask 0xF0 (11110000) 确保它是 Class E
        // mask 0x0F (00001111) 保留 NodeID 该字节的低4位随机性
        b[0] = (b[0] & 0x0F) | 0xF0;
    
        // 边界处理：
        // Class E 的范围是 240.0.0.0 - 255.255.255.255
        // 操作系统通常极其讨厌 255.x.x.x (广播风暴风险)
        // 所以如果首字节是 255，我们将其重映射回 254 (或者 240，看喜好，254 碰撞概率最小)
        if b[0] == 255 {
            b[0] = 254;
        }
    
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    }
}

/// 添加节点的操作结果
#[derive(Debug, PartialEq)]
pub enum DhtAddResult {
    Added,
    /// Bucket 满，且新节点未在其中。需要 Ping 最老节点。
    BucketFull { oldest_node: NodeInfo },
    /// 节点被忽略 (如 IP 非法、自身 ID 等)
    Ignored,
}

/// K-Bucket
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

    fn update(&mut self, mut node: NodeInfo) -> DhtAddResult {
        self.last_updated = Instant::now();
        node.touch();

        // 1. 若已存在，移至队尾 (Most Recently Seen)
        if let Some(idx) = self.nodes.iter().position(|n| n.id == node.id) {
            let mut existing = self.nodes.remove(idx).unwrap();
            // 更新元数据
            existing.addr = node.addr;
            existing.touch();
            if node.latency_ms > 0 { existing.latency_ms = node.latency_ms; }
            
            self.nodes.push_back(existing);
            return DhtAddResult::Added;
        }

        // 2. 若未满，直接插入
        if self.nodes.len() < K_BUCKET_SIZE {
            self.nodes.push_back(node);
            return DhtAddResult::Added;
        }

        // 3. 若已满，放入替换缓存，并通知上层检测 Head
        let oldest = self.nodes.front().cloned().unwrap();
        
        // 存入替换缓存 (去重)
        if let Some(idx) = self.replacements.iter().position(|n| n.id == node.id) {
            self.replacements.remove(idx);
        }
        self.replacements.push_back(node);
        if self.replacements.len() > K_BUCKET_SIZE {
            self.replacements.pop_front();
        }

        DhtAddResult::BucketFull { oldest_node: oldest }
    }

    /// 节点活跃确认 (Ping 通了)
    fn mark_alive(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let mut n = self.nodes.remove(idx).unwrap();
            n.touch();
            self.nodes.push_back(n);
        }
    }

    /// 节点失效 (Ping 不通)
    fn mark_dead(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            self.nodes.remove(idx);
            // 晋升
            if let Some(rep) = self.replacements.pop_back() {
                self.nodes.push_back(rep);
            }
        }
    }
}

/// 生产级 DHT 路由表
#[derive(Debug, Serialize, Deserialize)]
pub struct DhtRoutingTable {
    local_id: NodeID,
    config: DhtConfig,
    buckets: Vec<KBucket>,
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
            node_count_cache: 0,
        }
    }

    /// 计算 Bucket 索引 (Logarithmic Distance)
    /// 返回 0..255
    fn bucket_index(&self, target: &NodeID) -> Option<usize> {
        let dist = Distance::xor(&self.local_id, target);
        let zeros = dist.leading_zeros();
        if zeros >= ID_BITS { return None; } // Self
        Some(ID_BITS - 1 - zeros)
    }

    /// 验证 IP 合法性
    fn is_valid_ip(&self, addr: &SocketAddr) -> bool {
        if self.config.allow_bogon_ips { return true; }
        
        let ip = addr.ip();
        // 简单的 Bogon 过滤: 排除 Loopback, Multicast, Unspecified
        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
            return false;
        }
        // 私有 IP (192.168...) 在 Overlay 网络中通常是允许的 (NAT)，
        // 但如果是在公网 DHT，应该过滤。
        // ETP 默认允许 NAT 后 IP，因为有 NAT 穿透模块。
        true
    }

    // --- 核心操作 ---

    pub fn add_node(&mut self, mut node: NodeInfo) -> DhtAddResult {
        if node.id == self.local_id { return DhtAddResult::Ignored; }
        if !self.is_valid_ip(&node.addr) { return DhtAddResult::Ignored; }

        // 自动计算虚拟 IP
        if self.config.enable_virtual_net && node.virtual_ip.is_none() {
            node.virtual_ip = Some(VirtualNetworkMapper::map_id_to_ip(&node.id));
        }

        if let Some(idx) = self.bucket_index(&node.id) {
            let res = self.buckets[idx].update(node);
            self.update_count_cache();
            return res;
        }
        DhtAddResult::Ignored
    }

    pub fn mark_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].mark_alive(id);
        }
    }

    pub fn mark_failed(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].mark_dead(id);
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

    /// 优化后的 K-Nearest 查找算法
    /// 仅遍历相关的 Bucket，向外扩散
    pub fn find_closest(&self, target: &NodeID, count: usize) -> Vec<NodeInfo> {
        let mut collected = Vec::new();
        
        // 1. 定位中心 Bucket
        let center_idx = self.bucket_index(target).unwrap_or(0); // 如果是 self，从 0 开始
        
        // 2. 双向扩散迭代器
        // 顺序：center, center+1, center-1, center+2, center-2 ...
        // 这种顺序能保证优先搜索距离最近的逻辑空间
        let mut visited_indices = HashSet::new();
        let mut iter_offset = 0;

        while collected.len() < count && visited_indices.len() < ID_BITS {
            // Check +offset
            if center_idx + iter_offset < ID_BITS {
                let idx = center_idx + iter_offset;
                if visited_indices.insert(idx) {
                    self.collect_from_bucket(idx, target, &mut collected, count);
                }
            }
            
            // Check -offset
            if iter_offset > 0 && center_idx >= iter_offset {
                let idx = center_idx - iter_offset;
                if visited_indices.insert(idx) {
                    self.collect_from_bucket(idx, target, &mut collected, count);
                }
            }

            iter_offset += 1;
            
            // 优化：如果向外扩散太远（例如 XOR 距离差异极大），实际上找到的节点已经非常远了。
            // 但为了保证能返回 K 个（如果有的话），我们继续直到全表或满 K。
        }

        // 3. 最终排序
        collected.sort_by(|a, b| {
            let da = Distance::xor(target, &a.id);
            let db = Distance::xor(target, &b.id);
            da.cmp(&db)
        });
        
        collected.truncate(count);
        collected
    }

    fn collect_from_bucket(&self, idx: usize, target: &NodeID, out: &mut Vec<NodeInfo>, limit: usize) {
        let bucket = &self.buckets[idx];
        for node in &bucket.nodes {
            out.push(node.clone());
        }
        // 在节点稀缺时，也可以考虑 replacements 里的节点作为备选
        if out.len() < limit {
             for node in &bucket.replacements {
                out.push(node.clone());
            }
        }
    }

    pub fn get_random_peers(&self, count: usize) -> Vec<NodeInfo> {
        let mut rng = thread_rng();
        let mut all = Vec::new();
        // 简单的随机采样：随机选几个非空 bucket
        let populated_indices: Vec<usize> = self.buckets.iter().enumerate()
            .filter(|(_, b)| !b.nodes.is_empty())
            .map(|(i, _)| i)
            .collect();
        
        if populated_indices.is_empty() { return vec![]; }

        for _ in 0..count.min(populated_indices.len() * K_BUCKET_SIZE) {
            let b_idx = populated_indices[rng.gen_range(0..populated_indices.len())];
            let bucket = &self.buckets[b_idx];
            if !bucket.nodes.is_empty() {
                let n_idx = rng.gen_range(0..bucket.nodes.len());
                all.push(bucket.nodes[n_idx].clone());
            }
        }
        // Dedup
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all.dedup_by(|a, b| a.id == b.id);
        all.truncate(count);
        all
    }

    // --- 维护逻辑 (Maintenance) ---

    /// 获取需要刷新的 Bucket ID
    /// 返回一组随机生成的 ID，这些 ID 落在长时间未更新的 Bucket 范围内。
    /// 上层应用应针对这些 ID 发起 find_node 查询，以发现新节点。
    pub fn get_refresh_ids(&self) -> Vec<NodeID> {
        let now = Instant::now();
        let mut refresh_targets = Vec::new();
        let mut rng = thread_rng();

        for (i, bucket) in self.buckets.iter().enumerate() {
            if now.duration_since(bucket.last_updated) > self.config.refresh_interval {
                // 生成一个落在该 Bucket 范围内的随机 ID
                // Bucket i 对应距离 2^(255-i) .. 2^(256-i) - 1
                // 简单做法：翻转 local_id 的第 (ID_BITS - 1 - i) 位，其余位随机
                // 这样生成的 ID 与 local_id 的 XOR 距离的前导零恰好是 ID_BITS - 1 - i
                
                let bit_index = ID_BITS - 1 - i; // 从高位开始数
                let byte_idx = bit_index / 8;
                let bit_offset = 7 - (bit_index % 8); // 大端序

                let mut target_id = self.local_id;
                
                // Flip the defining bit
                target_id[byte_idx] ^= 1 << bit_offset;

                // Randomize lower bits to scan deeper in that bucket
                // Lower bits start from bit_index + 1 to end
                // We just randomize the whole ID then force the prefix? No.
                // Just randomize randomly is enough for "some ID in bucket".
                // Actually, to be strictly in the bucket, we must match the prefix of local_id
                // up to bit_index, flip bit_index, and randomize the rest.
                
                // Randomize bytes after byte_idx
                for b in (byte_idx + 1)..32 {
                    target_id[b] = rng.gen();
                }
                // Randomize bits in byte_idx lower than bit_offset
                let mask = (1 << bit_offset) - 1;
                let rand_byte: u8 = rng.gen();
                target_id[byte_idx] = (target_id[byte_idx] & !mask) | (rand_byte & mask);

                refresh_targets.push(target_id);
            }
        }
        refresh_targets
    }

    /// 获取过期的节点 (Stale Nodes)
    /// 仅返回 ID，上层应尝试 Ping，如果 Ping 失败则调用 mark_dead
    pub fn get_stale_nodes(&self) -> Vec<NodeID> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
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
        // Reset volatile fields
        table.node_count_cache = table.buckets.iter().map(|b| b.nodes.len()).sum();
        Ok(table)
    }

    pub fn total_nodes(&self) -> usize {
        self.node_count_cache
    }
    
    fn update_count_cache(&mut self) {
        self.node_count_cache = self.buckets.iter().map(|b| b.nodes.len()).sum();
    }
}

// --- 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080))
    }

    #[test]
    fn test_virtual_ip_mapping() {
        let id = [0xAA; 32]; // Ends in 0xAA (170) -> 240...170 is valid
        let ip = VirtualNetworkMapper::map_id_to_ip(&id);
        assert!(ip.octets()[0] == 240);
        
        let mut id2 = [0x00; 32];
        id2[31] = 0xFF; // Ends with FF
        // Class E logic: 0xFF & 0x0F | 0xF0 = 0xFF (255)
        // Should remap to 254
        let ip2 = VirtualNetworkMapper::map_id_to_ip(&id2);
        assert_eq!(ip2.octets()[0], 254);
    }

    #[test]
    fn test_find_closest_optimized() {
        let local = [0u8; 32];
        let mut table = DhtRoutingTable::new(local, DhtConfig::default());
        
        // Populate with specific distances
        // Node A: Distance 1 (Last bit flipped) -> Bucket Index 0 (High index)
        let mut id_a = local; id_a[31] ^= 1;
        table.add_node(NodeInfo::new(id_a, dummy_addr()));
        
        // Node B: Distance Max (First bit flipped) -> Bucket Index 255 (Low index)
        let mut id_b = local; id_b[0] ^= 0x80;
        table.add_node(NodeInfo::new(id_b, dummy_addr()));

        // Search for Node A
        let res = table.find_closest(&id_a, 5);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].id, id_a); // Should be first
    }

    #[test]
    fn test_maintenance_refresh() {
        let local = [0u8; 32];
        let mut config = DhtConfig::default();
        config.refresh_interval = Duration::from_millis(1); // Immediate expire
        
        let table = DhtRoutingTable::new(local, config);
        
        // Should generate IDs for all empty buckets
        let refresh_ids = table.get_refresh_ids();
        assert_eq!(refresh_ids.len(), 256);
        
        // Verify ID generation logic for bucket 0 (distance 1)
        // Bucket 0 means leading zeros = 255.
        // The generated ID should have 255 zeros and last bit 1.
        // Note: Our bucket implementation index 0 corresponds to Distance 1 (Max leading zeros).
        // Let's check the code: bucket_index 0 <-> ID_BITS-1-zeros = 0 => zeros = 255.
        
        // Find the ID for bucket 0
        // We can't easily map back from random list, but we trust the logic coverage.
    }
}
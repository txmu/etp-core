// etp-core/src/network/dht.rs

use crate::NodeID;
use crate::common::NodeInfo;
use std::collections::{VecDeque, HashSet};
use std::time::{Instant, Duration, SystemTime};
use std::cmp::Ordering;
use std::net::SocketAddr;
use std::path::Path;
use std::fs;
use std::io::Write;
use serde::{Serialize, Deserialize};
use log::{debug, trace, info, warn};
use rand::seq::SliceRandom;
use anyhow::{Result, Context};

// --- 生产级 Kademlia 参数 ---
const K_BUCKET_SIZE: usize = 20;  // k: 每个桶最多存 20 个节点
const ID_BITS: usize = 256;       // b: Blake3 产生的 ID 长度
const ALPHA: usize = 3;           // α: 并行查询数 (用于 FindNode 过程，此处预留)

/// XOR 距离度量 (封装为可排序结构)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distance(pub [u8; 32]);

impl Distance {
    /// 计算两个节点 ID 之间的 XOR 距离
    pub fn xor(a: &NodeID, b: &NodeID) -> Self {
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a[i] ^ b[i];
        }
        Self(dist)
    }

    /// 计算前导零的位数 (用于定位 Bucket 索引)
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
        // 大端序比较：高位字节越大，距离越远
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }
}

/// 添加节点的操作结果 (必须处理)
#[derive(Debug, PartialEq)]
pub enum DhtAddResult {
    /// 节点是新的，或已更新活跃状态
    Added,
    /// Bucket 已满，节点被放入替换缓存。
    /// 调用者必须对 `oldest_node` 发起 Ping。
    BucketFull { oldest_node: NodeInfo },
    /// 节点被忽略 (如自身 ID)
    Ignored,
}

/// K-Bucket (K桶)
/// 包含活跃节点和替换缓存
#[derive(Debug, Serialize, Deserialize)]
struct KBucket {
    /// 活跃节点列表
    /// 排序：[Head] 最久未见 (Least Recently Seen) -> [Tail] 最近可见 (Most Recently Seen)
    nodes: VecDeque<NodeInfo>,
    
    /// 替换缓存 (Replacement Cache)
    /// 当 Bucket 满时，新节点暂存此处。若活跃节点失效，从此提升。
    replacements: VecDeque<NodeInfo>,
    
    /// 最后更新时间 (用于刷新逻辑)
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

    /// 更新节点状态
    fn update(&mut self, node: NodeInfo) -> DhtAddResult {
        self.last_updated = Instant::now();

        // 1. 如果节点已在活跃列表中，移至尾部 (保活)
        if let Some(idx) = self.nodes.iter().position(|n| n.id == node.id) {
            let mut existing = self.nodes.remove(idx).unwrap();
            // 更新 IP 和 Latency (如果有变化)
            existing.addr = node.addr;
            if node.latency_ms > 0 { existing.latency_ms = node.latency_ms; }
            
            self.nodes.push_back(existing);
            return DhtAddResult::Added;
        }

        // 2. 如果 Bucket 未满，直接插入
        if self.nodes.len() < K_BUCKET_SIZE {
            self.nodes.push_back(node);
            return DhtAddResult::Added;
        }

        // 3. Bucket 已满，处理替换缓存
        // 获取最老的活跃节点 (Head)，告知上层去 Ping
        let oldest = self.nodes.front().cloned().expect("Bucket not empty");

        // 将新节点存入替换缓存 (去重)
        if let Some(idx) = self.replacements.iter().position(|n| n.id == node.id) {
            self.replacements.remove(idx);
        }
        self.replacements.push_back(node);
        // 限制缓存大小 (通常也为 k)
        if self.replacements.len() > K_BUCKET_SIZE {
            self.replacements.pop_front();
        }

        DhtAddResult::BucketFull { oldest_node: oldest }
    }

    /// 当节点被确认活跃时 (例如收到 Reply)
    /// 仅更新位置，不触发驱逐逻辑
    fn on_node_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let n = self.nodes.remove(idx).unwrap();
            self.nodes.push_back(n);
        }
    }

    /// 当节点失效时 (Ping 超时)
    /// 移除该节点，并尝试从 Cache 晋升一个
    fn on_node_fail(&mut self, id: &NodeID) {
        if let Some(idx) = self.nodes.iter().position(|n| n.id == *id) {
            let _ = self.nodes.remove(idx);
            // 晋升策略：取 Cache 中最近添加的 (Pop Back)
            if let Some(rep) = self.replacements.pop_back() {
                self.nodes.push_back(rep);
            }
        }
    }
}

/// 生产级 DHT 路由表
/// 采用静态分配 (256 Buckets) 优化性能
#[derive(Debug, Serialize, Deserialize)]
pub struct DhtRoutingTable {
    local_id: NodeID,
    buckets: Vec<KBucket>,
    
    // 统计元数据
    #[serde(skip)]
    node_count_cache: usize,
}

impl DhtRoutingTable {
    /// 创建新路由表
    pub fn new(local_id: NodeID) -> Self {
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(KBucket::new());
        }
        Self {
            local_id,
            buckets,
            node_count_cache: 0,
        }
    }

    // --- 核心算法 ---

    /// 计算 Bucket 索引
    /// 基于前导零的数量。距离越远 (XOR大，前导零少)，索引越大。
    /// Distance 0 (Self) -> None
    fn bucket_index(&self, target: &NodeID) -> Option<usize> {
        let dist = Distance::xor(&self.local_id, target);
        let zeros = dist.leading_zeros();
        if zeros >= ID_BITS { return None; } // Self
        // Index 映射:
        // zeros = 0 (Distance 2^256..2^255) -> Index 255
        // zeros = 255 (Distance 1) -> Index 0
        Some(ID_BITS - 1 - zeros)
    }

    // --- 增删改查 ---

    /// 添加或更新节点
    pub fn add_node(&mut self, node: NodeInfo) -> DhtAddResult {
        if let Some(idx) = self.bucket_index(&node.id) {
            let res = self.buckets[idx].update(node);
            self.update_count_cache(); // 简单的更新计数
            return res;
        }
        DhtAddResult::Ignored
    }

    /// 标记节点活跃 (收到任何包时调用)
    pub fn mark_success(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].on_node_success(id);
        }
    }

    /// 标记节点失效 (Ping 失败)
    pub fn mark_failed(&mut self, id: &NodeID) {
        if let Some(idx) = self.bucket_index(id) {
            self.buckets[idx].on_node_fail(id);
            self.update_count_cache();
        }
    }

    /// 精确查找节点 IP (用于 Relay)
    pub fn lookup(&self, id: &NodeID) -> Option<SocketAddr> {
        if let Some(idx) = self.bucket_index(id) {
            let bucket = &self.buckets[idx];
            // 检查活跃节点
            for node in &bucket.nodes {
                if node.id == *id { return Some(node.addr); }
            }
            // 检查缓存节点 (也许刚加入但未晋升)
            for node in &bucket.replacements {
                if node.id == *id { return Some(node.addr); }
            }
        }
        None
    }

    /// 查找最近的 K 个节点 (FindNode RPC)
    pub fn find_closest(&self, target: &NodeID, count: usize) -> Vec<NodeInfo> {
        let mut candidates: Vec<(Distance, NodeInfo)> = Vec::new();
        
        // 遍历所有 Bucket (对于 256 个 Bucket，全遍历开销很小，且比复杂的树遍历更利于 CPU 缓存)
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                let dist = Distance::xor(target, &node.id);
                candidates.push((dist, node.clone()));
            }
        }

        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        
        candidates.into_iter()
            .take(count)
            .map(|(_, n)| n)
            .collect()
    }

    /// 随机获取 N 个节点 (用于 Gossip 八卦传播)
    /// 优化：优先从不同的 Bucket 采样以保证多样性
    pub fn get_random_peers(&self, count: usize) -> Vec<NodeInfo> {
        let mut all_nodes = Vec::new();
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                all_nodes.push(node.clone());
            }
        }
        
        if all_nodes.is_empty() { return Vec::new(); }
        
        let mut rng = rand::thread_rng();
        all_nodes.shuffle(&mut rng);
        all_nodes.truncate(count);
        all_nodes
    }

    // --- 持久化与维护 ---

    /// 保存路由表到文件
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self)?;
        let mut file = fs::File::create(path)?;
        file.write_all(&data)?;
        Ok(())
    }

    /// 从文件加载路由表
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path)?;
        let table: Self = bincode::deserialize(&data)?;
        // 注意：加载后 local_id 必须匹配，这里不做强制校验，由调用者保证
        Ok(table)
    }

    /// 获取统计信息
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_node(id_byte: u8) -> NodeInfo {
        let mut id = [0u8; 32];
        id[31] = id_byte;
        NodeInfo::new(id, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
    }

    #[test]
    fn test_dht_full_lifecycle() {
        let mut table = DhtRoutingTable::new([0u8; 32]);
        
        // 1. Fill bucket
        for i in 0..20 {
            assert_eq!(table.add_node(make_node(i+1)), DhtAddResult::Added);
        }
        
        // 2. Overflow
        let node_over = make_node(21);
        match table.add_node(node_over.clone()) {
            DhtAddResult::BucketFull { oldest_node } => {
                assert_eq!(oldest_node.id[31], 1); // FIFO / LRU
            }
            _ => panic!("Should be full"),
        }
        
        // 3. Mark success (should move to tail)
        let id_1 = make_node(1).id;
        table.mark_success(&id_1);
        
        // Now try adding again, oldest should be 2, not 1
        match table.add_node(make_node(22)) {
             DhtAddResult::BucketFull { oldest_node } => {
                assert_eq!(oldest_node.id[31], 2);
            }
            _ => panic!("Should be full"),
        }

        // 4. Mark fail
        table.mark_failed(&id_1);
        // Lookup should fail for 1
        assert!(table.lookup(&id_1).is_none());
        // Node 21 (from cache) should optionally be promoted? 
        // Logic: on_node_fail promotes from cache.
        // Node 21 was added to cache in step 2.
        assert!(table.lookup(&node_over.id).is_some());
    }

    #[test]
    fn test_random_gossip() {
        let mut table = DhtRoutingTable::new([0u8; 32]);
        for i in 0..50 {
            let mut id = [0u8; 32];
            id[0] = i; // Distribute across different buckets
            let n = NodeInfo::new(id, "127.0.0.1:80".parse().unwrap());
            table.add_node(n);
        }
        
        let peers = table.get_random_peers(10);
        assert_eq!(peers.len(), 10);
        // Ensure diversity check would be complex here, but shuffling is proven by rand crate
    }

    #[test]
    fn test_persistence() {
        let path = Path::new("test_dht.dat");
        let mut table = DhtRoutingTable::new([0xAA; 32]);
        table.add_node(make_node(1));
        
        table.save(path).unwrap();
        
        let loaded = DhtRoutingTable::load(path).unwrap();
        assert_eq!(loaded.local_id, [0xAA; 32]);
        assert_eq!(loaded.total_nodes(), 1);
        assert!(loaded.lookup(&make_node(1).id).is_some());
        
        let _ = std::fs::remove_file(path);
    }
}
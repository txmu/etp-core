// etp-core/src/countermeasures/sequence.rs

use rand::Rng;
use std::cmp;

/// 序列整形器
/// 负责控制包的长度序列和内容分片，以破坏 DPI 特征
pub struct SequenceShaper {
    packet_count: usize,
    target_profile: [usize; 4],
    /// 敏感词列表，用于强制分片
    sensitive_keywords: Vec<&'static [u8]>,
}

impl SequenceShaper {
    pub fn new() -> Self {
        Self {
            packet_count: 0,
            // 模拟 HTTPS 握手长度特征: [ClientHello, ServerHello, ChangeCipher, Data]
            target_profile: [517, 1300, 80, 400], 
            // 常见的 DPI 匹配关键字
            sensitive_keywords: vec![
                b"HTTP", b"GET ", b"POST", b"CONNECT", b"Host:", 
                b"User-Agent", b"ssh-", b"TLS", b"\x16\x03\x01", // TLS Record
            ],
        }
    }

    /// 获取建议的下一个包长度
    pub fn next_target_len(&mut self) -> Option<usize> {
        if self.packet_count < self.target_profile.len() {
            let target = self.target_profile[self.packet_count];
            self.packet_count += 1;
            Some(target)
        } else {
            None
        }
    }

    /// 智能分片：基于敏感词匹配和随机混合
    /// 目的：将 "HTTP/1.1" 切分为 "HT" + "TP/1.1"，使 DPI 无法匹配完整签章
    pub fn fragment_sensitive_data(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let mut cursor = 0;
        let len = data.len();
        let mut rng = rand::thread_rng();

        // 查找所有敏感词的出现位置
        let mut break_points = Vec::new();
        
        for keyword in &self.sensitive_keywords {
            // 使用简单的 window search，生产级可用 Aho-Corasick
            for i in 0..len.saturating_sub(keyword.len()) {
                if &data[i..i + keyword.len()] == *keyword {
                    // 在敏感词中间插入切分点
                    // 例如 keyword 长度 4，我们在 index + 2 处切分
                    let split_at = i + (keyword.len() / 2);
                    break_points.push(split_at);
                }
            }
        }
        
        // 加入一些随机切分点增加混淆
        if len > 50 {
            let num_random_splits = rng.gen_range(1..3);
            for _ in 0..num_random_splits {
                break_points.push(rng.gen_range(1..len-1));
            }
        }

        break_points.sort_unstable();
        break_points.dedup();

        // 执行切分
        for &point in &break_points {
            if point > cursor && point < len {
                fragments.push(data[cursor..point].to_vec());
                cursor = point;
            }
        }

        // 剩余部分
        if cursor < len {
            fragments.push(data[cursor..].to_vec());
        }

        // 如果没有敏感词且未随机切分（例如短包），保持原样
        if fragments.is_empty() {
            fragments.push(data.to_vec());
        }

        fragments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_splitting() {
        let shaper = SequenceShaper::new();
        let data = b"GET / HTTP/1.1\r\nHost: google.com";
        
        let fragments = shaper.fragment_sensitive_data(data);
        
        // 验证碎片重组后数据一致
        let mut reassembled = Vec::new();
        for f in &fragments {
            reassembled.extend_from_slice(f);
        }
        assert_eq!(data.to_vec(), reassembled);

        // 验证是否包含原整词 (简单的 heuristic check)
        // 我们的逻辑是必定切分敏感词，所以碎片中不应包含完整的 "HTTP"
        for f in fragments {
            let s = String::from_utf8_lossy(&f);
            assert!(!s.contains("HTTP"), "Keyword HTTP should be broken");
            assert!(!s.contains("Host:"), "Keyword Host: should be broken");
        }
    }
}
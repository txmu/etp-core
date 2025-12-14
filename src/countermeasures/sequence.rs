// etp-core/src/countermeasures/sequence.rs

use rand::Rng;

/// 序列整形器
/// 强制前几次交互的数据包长度落在 OpenGFW 决策树的 "False" 分支上。
/// 同时通过分片（Fragmentation）打断特征字符串。
pub struct SequenceShaper {
    packet_count: usize,
    target_profile: [usize; 4], // 预设的安全长度序列
}

impl SequenceShaper {
    pub fn new() -> Self {
        Self {
            packet_count: 0,
            // 这是一个精心构造的序列，旨在避开 Trojan/V2Ray 的特征检测
            // 依据 OpenGFW 源码 trojan.go 的 isTrojanSeq 函数
            // 例如：如果 len1 > 892 且 len3 > 40 ...
            // 我们不仅要避开 Trojan，还要模拟正常浏览行为
            // Profile: [ClientHello-ish, ServerHello-ish, Ack/Data, Data]
            target_profile: [517, 1300, 80, 400], 
        }
    }

    /// 获取建议的下一个包长度
    /// 如果返回 Some(len)，则调用者必须将包填充或分片到该长度
    pub fn next_target_len(&mut self) -> Option<usize> {
        if self.packet_count < 4 {
            let target = self.target_profile[self.packet_count];
            self.packet_count += 1;
            Some(target)
        } else {
            None
        }
    }

    /// 智能分片：将敏感关键词切分到不同的包中
    /// 例如 "HTTP/1.1" -> "HTT" + "P/1.1"
    pub fn fragment_sensitive_data(data: &[u8]) -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let mut offset = 0;
        let len = data.len();
        
        // 简单的随机切分，实际应基于关键词匹配
        let mut rng = rand::thread_rng();
        
        while offset < len {
            let remaining = len - offset;
            let chunk_size = if remaining > 10 {
                rng.gen_range(1..remaining/2)
            } else {
                remaining
            };
            
            fragments.push(data[offset..offset+chunk_size].to_vec());
            offset += chunk_size;
        }
        
        fragments
    }
}
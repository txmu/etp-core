// etp-core/src/extensions/kns_adapter.rs

// 仅当 extensions (KNS) 和 persistence (TNS/Sled) 都启用时才编译此文件
#![cfg(all(feature = "extensions", feature = "persistence"))]

use std::sync::Arc;
use anyhow::{Result, anyhow, Context};
use log::{debug, trace, warn};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};

// 引入 KNS 接口
use crate::extensions::kns::{ExternalResolver, KnsRecord, KnsPath};
// 引入 TNS 实现
use crate::plugin::flavors::tns::{TnsFlavor, TnsRecord};
// 引入基础类型
use crate::NodeID;

/// TNS 支持的 KNS 解析器适配器
/// 
/// 该适配器实现了 `ExternalResolver` 接口，充当 KNS Kernel 与 TNS Flavor 之间的桥梁。
/// 它将 KNS 的盲索引 (Blind Index) 转换为 Hex 字符串，作为 TNS 的域名进行查询。
/// 
/// # 架构图
/// KNS Kernel -> [resolve_blind] -> Adapter -> [resolve string] -> TnsFlavor -> DHT/Network
pub struct TnsBackedKnsResolver {
    tns: Arc<TnsFlavor>,
    /// 可选：添加一个特定的后缀以区分普通域名和 KNS 索引
    /// 例如: "7f8a...1b.kns_idx"
    suffix: String,
}

impl TnsBackedKnsResolver {
    /// 创建适配器实例
    pub fn new(tns: Arc<TnsFlavor>) -> Self {
        Self {
            tns,
            suffix: ".kns_idx".to_string(),
        }
    }

    /// 辅助：将 KnsRecord 包装进 TnsRecord 并发布到网络
    /// 
    /// KNS 核心通常负责生成加密的 KnsRecord，但它不负责传输。
    /// 当上层应用想要通过 TNS 网络发布 KNS 记录时，可以使用此方法。
    pub async fn publish_kns_via_tns(&self, blind_index: &[u8; 32], record: &KnsRecord) -> Result<()> {
        // 1. 生成伪域名
        let name = format!("{}{}", hex::encode(blind_index), self.suffix);
        
        // 2. 序列化 KnsRecord
        let kns_bytes = bincode::serialize(record)
            .context("Failed to serialize KnsRecord")?;

        // 3. 构造元数据
        // 注意：TNS 的 target_id 通常用于路由。对于 KNS 记录，target_id 可能不重要，
        // 或者我们可以将其设置为 record.signer_id 以提供路由提示。
        let target_id = record.signer_id;

        // 4. 调用 TNS 发布
        // TNS Flavor 会负责签名（使用本节点的身份）、存入 Sled 并推送到 DHT
        self.tns.register_name(&name, target_id, kns_bytes).await
            .context("Failed to register KNS record via TNS")?;

        debug!("KNS-Adapter: Published blind index {} via TNS", name);
        Ok(())
    }
}

#[async_trait]
impl ExternalResolver for TnsBackedKnsResolver {
    fn provider_id(&self) -> &str {
        "tns_adapter_v1"
    }

    /// 解析逻辑
    async fn resolve_blind(&self, blind_index: &[u8; 32]) -> Result<Option<KnsRecord>> {
        // 1. 将盲索引转换为 TNS 域名字符串
        let query_name = format!("{}{}", hex::encode(blind_index), self.suffix);
        trace!("KNS-Adapter: Resolving blind index as '{}'", query_name);

        // 2. 调用 TnsFlavor 进行网络解析
        // 这会触发 TNS 的本地缓存查找、挂起请求合并以及网络广播/DHT查询
        let tns_result = self.tns.resolve(&query_name).await;

        match tns_result {
            Ok(tns_record) => {
                // 3. 从 TnsRecord 的 metadata 中提取 KnsRecord
                if tns_record.metadata.is_empty() {
                    return Ok(None);
                }

                match bincode::deserialize::<KnsRecord>(&tns_record.metadata) {
                    Ok(kns_record) => {
                        // 成功还原
                        // 注意：这里不需要再做 KNS 层面的签名验证，
                        // 因为 KnsKernel 在接收到结果后，会根据 KnsRecord 内部的 signature 和 signer_id
                        // 再次进行严格的 decrypt_and_verify。
                        // TNS 的签名保证了“传输层”没人篡改这个 Blob，
                        // KNS 的签名保证了“内容层”是合法的。
                        Ok(Some(kns_record))
                    },
                    Err(e) => {
                        warn!("KNS-Adapter: Failed to deserialize KnsRecord from TNS metadata: {}", e);
                        // 数据损坏或类型不匹配
                        Ok(None) 
                    }
                }
            },
            Err(e) => {
                // TNS 解析失败 (超时或网络错误)
                debug!("KNS-Adapter: TNS resolution failed: {}", e);
                // 对于 KNS 接口来说，网络错误通常意味着找不到
                Ok(None) 
            }
        }
    }
}

// ============================================================================
//  单元测试 (Mock TnsFlavor interaction)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use crate::plugin::flavors::tns::TnsFlavor;
    use crate::extensions::kns::{RecordKind, SecurityDomain};
    use crate::extensions::identity::{IdentityManager, IdentityType};
    use crate::common::DhtStoreRequest;

    #[tokio::test]
    async fn test_adapter_flow() {
        // 1. 初始化环境
        let (dht_tx, _dht_rx) = mpsc::channel(10);
        let (net_tx, _net_rx) = mpsc::channel(10);
        
        // 生成临时密钥用于 TNS 初始化
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signing_bytes = signing_key.to_bytes();

        // 临时 DB 路径
        let db_path = format!("test_kns_adapter_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&db_path); // Cleanup prev

        let tns = TnsFlavor::new(
            &db_path,
            &signing_bytes,
            dht_tx,
            net_tx
        ).unwrap();

        let adapter = TnsBackedKnsResolver::new(tns.clone());

        // 2. 准备 KNS 数据
        let anchor = IdentityManager::create_anchor();
        let domain = SecurityDomain::new("test_domain", anchor.clone());
        let path = KnsPath::new(vec!["secret".into()]).unwrap();
        
        // 发布一个 KNS 记录 (生成 encrypted payload & signature)
        let kns_record = domain.publish(&path, b"SuperSecretData", RecordKind::Static, 3600).unwrap();
        
        // 获取盲索引 (为了测试，我们手动计算一下，或者假设 publish 返回了 record 我们并不知 blind index)
        // 实际上 domain.publish 内部计算了 blind index 但没返回。
        // 我们需要重新计算它来作为 Key。
        // 这里为了测试方便，我们假设我们知道怎么算 (需要访问 secrets，但 secrets 是私有的)
        // 在真实使用中，SignalDrop 会自己算出 Blind Index。
        
        // Hack: 为了测试，我们在 domain 内部没有暴露 blind seed。
        // 但我们可以通过 KnsKernel 的流程来测，或者在这里仅测试序列化/反序列化流程。
        
        let mock_blind_index = [0xAAu8; 32]; 

        // 3. 通过 Adapter 发布 (Publish via TNS)
        adapter.publish_kns_via_tns(&mock_blind_index, &kns_record).await.expect("Publish failed");

        // 4. 通过 Adapter 解析 (Resolve via TNS)
        let resolved_opt = adapter.resolve_blind(&mock_blind_index).await.expect("Resolve failed");
        
        assert!(resolved_opt.is_some());
        let resolved_rec = resolved_opt.unwrap();

        // 5. 验证一致性
        assert_eq!(resolved_rec.payload, kns_record.payload);
        assert_eq!(resolved_rec.signature, kns_record.signature);

        // Cleanup
        let _ = std::fs::remove_dir_all(&db_path);
    }
}


// 用例：
// ... 初始化 TnsFlavor ...
// let tns_flavor = TnsFlavor::new(...)?;

// ... 初始化 KnsKernel ...
// let kns_kernel = KnsKernel::new();

// 创建适配器
// #[cfg(all(feature = "extensions", feature = "persistence"))]
// {
//    use etp_core::extensions::kns_adapter::TnsBackedKnsResolver;
    
//    let adapter = Arc::new(TnsBackedKnsResolver::new(tns_flavor.clone()));
    
    // 注册到 KNS 内核
//    kns_kernel.register_resolver(adapter);
    
//    info!("Registered TNS-backed KNS Resolver.");
// }
// etp-core/src/anonymity/isolation.rs

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::{Result, anyhow};
use log::{info, warn};

use crate::network::node::{EtpEngine, EtpHandle, NodeConfig};
use crate::plugin::PluginRegistry;
use crate::crypto::noise::KeyPair;

/// 安全等级
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 红色域：不受信任，高风险 (e.g. 公共 Wi-Fi, 匿名浏览)
    Untrusted,
    /// 黄色域：一般用途 (e.g. 聊天, 游戏)
    Standard,
    /// 绿色域：高敏感，完全隔离 (e.g. 密钥管理, 内部通信)
    Vault,
}

/// 安全域上下文
pub struct SecurityDomain {
    pub name: String,
    pub level: SecurityLevel,
    pub handle: EtpHandle,
    pub storage_root: PathBuf,
}

/// 域隔离管理器
/// 类似于 Qubes OS 的 Dom0，负责管理和隔离不同的 AppVM (Engine 实例)
pub struct IsolationManager {
    domains: RwLock<HashMap<String, SecurityDomain>>,
    base_path: PathBuf,
}

impl IsolationManager {
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            domains: RwLock::new(HashMap::new()),
            base_path,
        }
    }

    /// 启动一个新的隔离域
    /// 每个域拥有独立的：
    /// 1. 密钥对 (Identity Key)
    /// 2. 数据库路径 (Storage)
    /// 3. 网络配置 (Config)
    pub async fn spawn_domain(
        &self, 
        name: &str, 
        level: SecurityLevel, 
        mut config: NodeConfig
    ) -> Result<EtpHandle> {
        info!("Isolation: Spawning Security Domain '{}' [{:?}]", name, level);

        // 1. 路径隔离
        let domain_path = self.base_path.join(name);
        std::fs::create_dir_all(&domain_path)?;

        // 2. 身份隔离 (从不复用密钥)
        let identity_path = domain_path.join("identity.json");
        let keys = if identity_path.exists() {
            // Load existing (implementation omitted for brevity)
            KeyPair::generate() 
        } else {
            let k = KeyPair::generate();
            // Save k...
            k
        };
        config.keypair = keys;

        // 3. 配置强制覆盖 (基于安全等级)
        match level {
            SecurityLevel::Vault => {
                // 金库模式：强制最高安全配置，甚至可能禁用网络只允许本地环回
                config.anonymity.enable_cover_traffic = true;
                config.security.handshake_zero_tolerance = true;
                config.security.strict_rekey_interval_secs = 60; // 1分钟换一次密钥
            },
            SecurityLevel::Untrusted => {
                // 不受信任模式：可能使用一次性身份
                config.security.allow_dynamic_side_channels = false;
            },
            _ => {}
        }

        // 4. 启动独立的 Engine 实例
        let registry = Arc::new(PluginRegistry::new());
        // 这里应根据 level 注册不同的 Flavor
        // e.g. Vault 只有 Chat，没有 FileShare
        
        let (engine, handle, _) = EtpEngine::new(config, registry).await?;
        
        // Spawn engine in background
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                warn!("Domain '{}' crashed: {}", name, e);
            }
        });

        // 5. 注册域
        let domain = SecurityDomain {
            name: name.to_string(),
            level,
            handle: handle.clone(),
            storage_root: domain_path,
        };
        
        self.domains.write().await.insert(name.to_string(), domain);
        
        Ok(handle)
    }

    /// 获取特定域的句柄
    pub async fn get_handle(&self, name: &str) -> Option<EtpHandle> {
        self.domains.read().await.get(name).map(|d| d.handle.clone())
    }

    /// 紧急自毁：清除指定等级的所有域
    pub async fn panic_nuke(&self, target_level: SecurityLevel) {
        let mut map = self.domains.write().await;
        let keys: Vec<String> = map.iter()
            .filter(|(_, d)| d.level == target_level)
            .map(|(k, _)| k.clone())
            .collect();

        for k in keys {
            if let Some(d) = map.remove(&k) {
                let _ = d.handle.shutdown().await;
                // 安全擦除文件...
                info!("Isolation: Nuked domain '{}'", k);
            }
        }
    }
}
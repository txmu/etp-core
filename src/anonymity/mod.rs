// etp-core/src/anonymity/mod.rs

pub mod adapter;
pub mod isolation;
pub mod canary;
pub mod facade;

use serde::{Deserialize, Serialize};

/// 深度匿名模块的全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepProfile {
    /// 是否启用 Tor/I2P 代理模式
    /// 如果启用，将禁用内部的轻量级 Onion 路由，转而使用外部匿名网络
    pub enable_external_anonymity: bool,
    
    /// 外部匿名网络的 SOCKS5 代理地址 (例如 127.0.0.1:9050)
    pub proxy_addr: Option<String>,
    
    /// 是否开启 Qubes 风格的安全域隔离
    /// 开启后，将强制使用 DomainContext 运行
    pub enable_domain_isolation: bool,
    
    /// 是否启用金丝雀防御
    pub enable_canary_traps: bool,
}

impl Default for DeepProfile {
    fn default() -> Self {
        Self {
            enable_external_anonymity: false,
            proxy_addr: None,
            enable_domain_isolation: false,
            enable_canary_traps: true,
        }
    }
}
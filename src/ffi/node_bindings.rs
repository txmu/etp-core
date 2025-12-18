// etp-core/src/ffi/node_bindings.rs

#![cfg(feature = "binding-node")]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::Arc;
use std::net::SocketAddr;

use crate::network::node::{EtpEngine, NodeConfig};
use crate::plugin::PluginRegistry;

/// Node.js 包装类
#[napi]
pub struct EtpNodeJs {
    handle: crate::network::node::EtpHandle,
}

#[napi]
impl EtpNodeJs {
    /// 静态工厂方法：启动节点
    /// 返回 Promise<EtpNodeJs>
    #[napi(factory)]
    pub async fn start(bind_addr: String) -> Result<Self> {
        let mut config = NodeConfig::default();
        config.bind_addr = bind_addr;

        let registry = Arc::new(PluginRegistry::new());
        // 默认注册基础插件
        registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
        registry.register_flavor(Arc::new(crate::plugin::StandardFlavor));

        let (engine, handle, _) = EtpEngine::new(config, registry)
            .await
            .map_err(|e| Error::new(Status::GenericFailure, format!("Engine init failed: {}", e)))?;

        // 这里的 spawn 会利用 NAPI 提供的 Tokio Runtime 或全局 Runtime
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                // Node 环境下 log 可能需要桥接，这里简单打印
                eprintln!("ETP Engine crashed: {}", e);
            }
        });

        Ok(EtpNodeJs { handle })
    }

    /// 发送数据
    /// data: Buffer 类型
    #[napi]
    pub async fn send(&self, target: String, data: Buffer) -> Result<()> {
        let addr: SocketAddr = target.parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid IP: {}", e)))?;
        
        let vec_data: Vec<u8> = data.into();
        
        self.handle.send_data(addr, vec_data).await
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
            
        Ok(())
    }

    /// 连接到对等节点
    #[napi]
    pub async fn connect(&self, target: String, pub_key_hex: String) -> Result<()> {
        let addr: SocketAddr = target.parse()
            .map_err(|_| Error::new(Status::InvalidArg, "Invalid IP"))?;
            
        let key_bytes = hex::decode(&pub_key_hex)
            .map_err(|_| Error::new(Status::InvalidArg, "Invalid Hex Key"))?;

        self.handle.connect(addr, key_bytes).await
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
    }

    /// 获取状态
    #[napi]
    pub async fn get_stats(&self) -> Result<String> {
        self.handle.get_stats().await
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
    }
    
    /// 关闭
    #[napi]
    pub async fn shutdown(&self) -> Result<()> {
        self.handle.shutdown().await
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
    }
}
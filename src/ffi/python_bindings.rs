// etp-core/src/ffi/python_bindings.rs

#![cfg(feature = "binding-python")]

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;

// 引入核心组件
use crate::network::node::{EtpEngine, NodeConfig};
use crate::plugin::PluginRegistry;
use crate::error::EtpError;

/// Python 包装的 ETP 节点句柄
#[pyclass(name = "EtpNode")]
struct PyEtpNode {
    // 使用 Arc 可以在 Python GIL 释放时保持引用
    handle: crate::network::node::EtpHandle,
}

/// 辅助：将 EtpError 转换为 PyErr
fn to_py_err(err: EtpError) -> PyErr {
    match err {
        EtpError::Timeout => pyo3::exceptions::PyTimeoutError::new_err("ETP operation timed out"),
        EtpError::PayloadTooLarge(s, l) => pyo3::exceptions::PyValueError::new_err(format!("Payload too large: {} > {}", s, l)),
        _ => pyo3::exceptions::PyRuntimeError::new_err(err.to_string()),
    }
}

#[pymethods]
impl PyEtpNode {
    /// 异步启动节点
    /// bind_addr: "0.0.0.0:4000"
    #[staticmethod]
    fn start(py: Python<'_>, bind_addr: String) -> PyResult<&PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, async move {
            // 1. 配置构建
            let mut config = NodeConfig::default();
            config.bind_addr = bind_addr;
            
            // 2. 插件注册 (这里可以使用默认集，也可以扩展 API 让 Python 注入)
            let registry = Arc::new(PluginRegistry::new());
            registry.register_dialect(Arc::new(crate::plugin::StandardDialect));
            registry.register_flavor(Arc::new(crate::plugin::StandardFlavor));

            // 3. 启动引擎
            let (engine, handle, _) = EtpEngine::new(config, registry)
                .await
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

            // 4. 后台运行 (Spawn 到 Tokio Runtime)
            tokio::spawn(async move {
                if let Err(e) = engine.run().await {
                    log::error!("Python ETP Engine crashed: {}", e);
                }
            });

            Ok(PyEtpNode { handle })
        })
    }

    /// 异步发送数据
    fn send<'p>(&self, py: Python<'p>, target: String, data: Vec<u8>) -> PyResult<&'p PyAny> {
        let handle = self.handle.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let addr: SocketAddr = target.parse()
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid address: {}", e)))?;
            
            handle.send_data(addr, data).await
                .map_err(to_py_err)?;
                
            Ok(())
        })
    }

    /// 异步连接
    fn connect<'p>(&self, py: Python<'p>, target: String, remote_pub_hex: String) -> PyResult<&'p PyAny> {
        let handle = self.handle.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let addr: SocketAddr = target.parse()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid address"))?;
            
            let pub_key = hex::decode(&remote_pub_hex)
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid hex key"))?;

            handle.connect(addr, pub_key).await
                .map_err(to_py_err)?;
            
            Ok(())
        })
    }

    /// 获取统计信息
    fn get_stats<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let handle = self.handle.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let stats = handle.get_stats().await.map_err(to_py_err)?;
            Ok(stats)
        })
    }

    /// 优雅停机
    fn shutdown<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let handle = self.handle.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            handle.shutdown().await.map_err(to_py_err)?;
            Ok(())
        })
    }
}

/// 注册 Python 模块
#[pymodule]
fn etp_core_py(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyEtpNode>()?;
    Ok(())
}
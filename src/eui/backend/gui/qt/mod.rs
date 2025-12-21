// src/eui/backend/gui/qt/mod.rs

#![cfg(feature = "eui-gui-qt")]

pub mod bridge;

use std::sync::Arc;
use qmetaobject::*;
use anyhow::{Result, anyhow};
use parking_lot::Mutex;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use crate::eui::bridge::BackendBridgeExt;
use self::bridge::QtBackendBridge;

pub struct QtBackend {
    // 桥接对象必须被封装在 QPointer 或类似的持久化容器中
    // 由于 qmetaobject 的限制，通常通过全局单例或 Arc<Mutex> 管理
    bridge: Arc<Mutex<QtBackendBridge>>,
}

impl QtBackend {
    pub fn new() -> Self {
        Self {
            bridge: Arc::new(Mutex::new(QtBackendBridge::default())),
        }
    }
}

impl EuiBackend for QtBackend {
    fn name(&self) -> &'static str {
        if cfg!(feature = "qt4") { "Qt 4.8 (Industrial Legacy)" } else { "Qt 5.15 (Modern Desktop)" }
    }

    fn init(&self) -> Result<()> {
        log::info!("QtBackend: Probing system Qt installation...");
        Ok(())
    }

    fn run(&self, handle: EtpHandle, _initial_state: NodeSummary) -> Result<()> {
        // 1. 初始化 Qt 引擎
        let mut engine = QmlEngine::new();
        
        // 2. 注入桥接对象到 QML 上下文
        let mut bridge_lock = self.bridge.lock();
        
        // 设置关机回调
        let h_clone = handle.clone();
        bridge_lock.on_shutdown = Some(Box::new(move || {
            let h = h_clone.clone();
            tokio::spawn(async move {
                let _ = h.bridge().dispatch(crate::eui::EuiCommand::ShutdownNode).await;
            });
        }));

        // 将 bridge 注册为全局 "Backend" 变量
        // 这一行实现了 Rust 对象在 QML 中的透明访问
        let bridge_variant = bridge_lock.to_qvariant(); // 假设实现了相应转换
        // 实际上 qmetaobject 采用宏注册：
        qml_register_type::<QtBackendBridge>(std::ffi::CStr::from_bytes_with_nul(b"EtpNative\0").unwrap(), 1, 0, std::ffi::CStr::from_bytes_with_nul(b"Backend\0").unwrap());
        
        // 正确的用法是在 QML 中实例化或注入上下文
        engine.set_object_property("Backend".into(), bridge_lock.clone_as_qvm()); 

        // 3. 加载界面文件
        let qml_data = include_str!("dashboard.qml");
        engine.load_data(qml_data.into());

        // 4. 接管主线程，运行 Qt 事件循环
        info!("QtBackend: Event loop started.");
        engine.exec();
        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        // Qt UI 不是线程安全的，必须通过事件循环执行更新
        let bridge = Arc::clone(&self.bridge);
        
        // qmetaobject 提供了一个极好的宏：execute_from_main_thread
        // 它会把任务排队到 Qt 的事件队列中执行
        execute_from_main_thread(move || {
            let mut guard = bridge.lock();
            guard.apply_snapshot(snapshot);
        });
    }

    fn shutdown(&self) {
        execute_from_main_thread(|| {
            // 退出 Qt 事件循环
            app_exit();
        });
    }
}
// etp-core/src/extensions/config.rs

use std::sync::{Arc, RwLock};
use std::time::Duration;
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use log::{info, error};
use std::path::PathBuf;

/// 动态配置容器
pub struct DynamicConfig {
    configs: Arc<RwLock<serde_json::Value>>,
}

impl DynamicConfig {
    pub fn new(initial: serde_json::Value) -> Self {
        Self {
            configs: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Option<T> {
        let guard = self.configs.read().unwrap();
        // 简化的 JSON Path 解析
        guard.get(path).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    pub fn update(&self, new_val: serde_json::Value) {
        let mut guard = self.configs.write().unwrap();
        *guard = new_val;
    }
}

/// 配置文件监听器
pub struct ConfigWatcher;

impl ConfigWatcher {
    pub fn watch(path: PathBuf, config: Arc<DynamicConfig>) {
        std::thread::spawn(move || {
            let (tx, rx) = channel();
            let mut watcher = watcher(tx, Duration::from_secs(2)).unwrap();
            watcher.watch(&path, RecursiveMode::NonRecursive).unwrap();

            loop {
                match rx.recv() {
                    Ok(event) => {
                        info!("Config file changed: {:?}", event);
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Ok(val) = serde_json::from_str(&content) {
                                config.update(val);
                                info!("Config reloaded successfully");
                            }
                        }
                    },
                    Err(e) => error!("Watch error: {:?}", e),
                }
            }
        });
    }
}
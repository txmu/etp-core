// etp-core/src/extensions/state.rs

use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};
use anyhow::{Result, anyhow};

/// 支持事务的共享状态容器
pub struct SharedState {
    data: DashMap<String, Arc<RwLock<Vec<u8>>>>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
        }
    }

    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let bytes = bincode::serialize(value)?;
        self.data.insert(key.to_string(), Arc::new(RwLock::new(bytes)));
        Ok(())
    }

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        match self.data.get(key) {
            Some(wrapper) => {
                let guard = wrapper.read();
                let val = bincode::deserialize(&guard)?;
                Ok(val)
            },
            None => Err(anyhow!("Key not found")),
        }
    }

    /// 原子更新 (CAS 模拟)
    pub fn update<T, F>(&self, key: &str, mut f: F) -> Result<()> 
    where 
        T: Serialize + DeserializeOwned,
        F: FnMut(&mut T)
    {
        if let Some(wrapper) = self.data.get(key) {
            let mut guard = wrapper.write();
            let mut val: T = bincode::deserialize(&guard)?;
            f(&mut val);
            *guard = bincode::serialize(&val)?;
            Ok(())
        } else {
            Err(anyhow!("Key not found"))
        }
    }
}
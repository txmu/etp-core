// etp-core/src/extensions/huoban.rs

use std::sync::Arc;
use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use rand::{Rng, thread_rng};

// 引入 Pool Memory 以实现“紧密集成”
use crate::extensions::pool_memory::{get_global_pool, Permissions};

// ============================================================================
//  用户与安全
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub hashed_password: String,
    pub salt: String,
    pub is_admin: bool,
    pub is_blacklisted: bool,
    // 扩展属性
    pub profile: HashMap<String, String>,
}

impl User {
    pub fn new(name: &str, password: &str) -> Self {
        let salt = Self::generate_salt();
        let hashed = Self::hash_password(password, &salt);
        Self {
            name: name.to_string(),
            hashed_password: hashed,
            salt,
            is_admin: false,
            is_blacklisted: false,
            profile: HashMap::new(),
        }
    }

    fn generate_salt() -> String {
        let mut rng = thread_rng();
        let rand_val: u128 = rng.gen();
        format!("{:x}", rand_val)
    }

    fn hash_password(password: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let hashed = Self::hash_password(password, &self.salt);
        self.hashed_password == hashed
    }
}

// ============================================================================
//  消息板核心
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub sender: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub is_private: bool,
    pub target: Option<String>,
}

pub struct HuoBanBoard {
    pub users: RwLock<HashMap<String, User>>,
    pub messages: RwLock<Vec<Message>>,
    // 特权码：Code -> Action (Closure)
    // Rust 闭包很难序列化，这里简化为 Enum 指令
    pub hooks: RwLock<Vec<Box<dyn BoardHook + Send + Sync>>>,
}

// 指令枚举
#[derive(Debug, PartialEq)]
pub enum PrivilegeAction {
    DebugMode,
    AdminMode,
    SecretAdmin,
}

impl HuoBanBoard {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            messages: RwLock::new(Vec::new()),
            hooks: RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, name: &str, password: &str) -> Result<()> {
        let mut users = self.users.write();
        if users.contains_key(name) {
            return Err(anyhow!("Username exists"));
        }
        users.insert(name.to_string(), User::new(name, password));
        Ok(())
    }

    pub fn login(&self, name: &str, password: &str) -> Result<User> {
        let users = self.users.read();
        if let Some(user) = users.get(name) {
            if user.verify_password(password) {
                if user.is_blacklisted {
                    return Err(anyhow!("User is blacklisted"));
                }
                return Ok(user.clone());
            }
        }
        Err(anyhow!("Invalid credentials"))
    }

    pub fn post_message(&self, user: &User, text: &str) {
        // Trigger Hooks
        {
            let hooks = self.hooks.read();
            for hook in hooks.iter() {
                if !hook.on_post_message(self, user, text) {
                    return; // Hook 阻止了消息
                }
            }
        }

        let msg = Message {
            sender: user.name.clone(),
            content: text.to_string(),
            timestamp: Utc::now(),
            is_private: false,
            target: None,
        };
        self.messages.write().push(msg);
        
        // 紧密集成：将消息备份到 PoolMemory (使用压缩)
        self.backup_to_memory(&text).ok();
    }

    fn backup_to_memory(&self, text: &str) -> Result<()> {
        let pool = get_global_pool();
        // 申请内存
        let segment = pool.allocate(text.len(), "HuoBanSystem".to_string(), 1)?;
        let mut guard = segment.write();
        // 写入数据
        guard.memory_ref.write(0, text.as_bytes())?;
        Ok(())
    }

    pub fn view_messages(&self) -> Vec<String> {
        self.messages.read().iter()
            .map(|m| format!("[{}] {}: {}", m.timestamp, m.sender, m.content))
            .collect()
    }
}

// ============================================================================
//  Hook 系统 (Rust Trait 实现)
// ============================================================================

pub trait BoardHook {
    /// 消息发送前触发，返回 false 则拦截
    fn on_post_message(&self, board: &HuoBanBoard, user: &User, text: &str) -> bool { true }
    fn on_debug_data(&self, board: &HuoBanBoard) -> Option<String> { None }
}

/// 沙箱钩子：模拟发送但不实际存储
pub struct SandboxHook {
    pub sandbox_messages: RwLock<Vec<Message>>,
}

impl SandboxHook {
    pub fn new() -> Self {
        Self { sandbox_messages: RwLock::new(Vec::new()) }
    }
}

impl BoardHook for SandboxHook {
    fn on_post_message(&self, _board: &HuoBanBoard, user: &User, text: &str) -> bool {
        // 拦截真实发送，存入沙箱
        println!("[Sandbox] Captured message from {}: {}", user.name, text);
        let msg = Message {
            sender: user.name.clone(),
            content: text.to_string(),
            timestamp: Utc::now(),
            is_private: false,
            target: None,
        };
        self.sandbox_messages.write().push(msg);
        false // Block real propagation
    }
}

/// 隐写术终端钩子：解析命令行
pub struct TerminalHook;

impl BoardHook for TerminalHook {
    fn on_post_message(&self, board: &HuoBanBoard, user: &User, text: &str) -> bool {
        if text.starts_with('/') {
            // 是命令，不作为普通消息存储
            let output = self.execute_command(text);
            // 将结果作为系统消息存入 (模拟回显)
            let sys_msg = Message {
                sender: "System".into(),
                content: output,
                timestamp: Utc::now(),
                is_private: true,
                target: Some(user.name.clone()),
            };
            board.messages.write().push(sys_msg);
            return false;
        }
        true
    }
}

impl TerminalHook {
    fn execute_command(&self, cmd: &str) -> String {
        let parts: Vec<&str> = cmd[1..].splitn(2, ' ').collect();
        match parts[0] {
            "hide" => "Steganography: Message hidden.".to_string(),
            "decrypt" => "Decryption challenge started...".to_string(),
            "ping" => "pong".to_string(),
            _ => format!("Unknown command: {}", parts[0]),
        }
    }
}

// ============================================================================
//  黑客终端模拟 (Hacker Terminal)
// ============================================================================

pub struct HackerTerminal {
    pub history: Vec<String>,
}

impl HackerTerminal {
    pub fn new() -> Self {
        Self { history: Vec::new() }
    }

    pub fn run_challenge(&self, challenge_type: &str) -> String {
        match challenge_type {
            "decode" => {
                // 模拟解密挑战
                "Challenge: Decrypt 'U2FsdGVk...'. Hint: AES".to_string()
            },
            "network" => {
                // 模拟网络扫描
                "Scanning... Found 3 hosts: 192.168.1.101, 10.0.0.5".to_string()
            },
            _ => "Available challenges: decode, network".to_string()
        }
    }
}
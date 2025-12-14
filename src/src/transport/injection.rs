// etp-core/src/transport/injection.rs

use crate::wire::frame::{Frame, InjectionCommand};
use crate::NodeID;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};
use parking_lot::RwLock; // 高性能读写锁
use bincode;

pub const CAP_ROUTE_HINT: u32 = 1 << 0;
pub const CAP_THROTTLE:   u32 = 1 << 1;
pub const CAP_SERVICE_AD: u32 = 1 << 2;
/// 超级管理员权限：允许修改 ACL 本身或执行所有操作
pub const CAP_ADMIN:      u32 = 0xFFFFFFFF;

/// 生产级 ACL 管理器
/// 支持运行时动态更新、零信任鉴权与指令审计
pub struct AclManager {
    /// 白名单: NodeID -> (Permissions, Public Key Bytes)
    /// 使用 RwLock 允许在运行时动态添加新的信任节点
    whitelist: RwLock<HashMap<NodeID, (u32, [u8; 32])>>,
    
    /// 黑名单: 被封禁的 NodeID
    blacklist: RwLock<HashSet<NodeID>>,
    
    /// 是否开启严格零信任模式 (Strict Mode)
    /// true: 只有白名单内的节点允许握手
    /// false: 允许陌生节点握手 (但 Injection 仍需权限)
    strict_mode: bool,
}

impl AclManager {
    /// 创建 ACL 管理器
    /// strict_mode: 建议生产环境设为 true
    pub fn new(strict_mode: bool) -> Self {
        Self {
            whitelist: RwLock::new(HashMap::new()),
            blacklist: RwLock::new(HashSet::new()),
            strict_mode,
        }
    }

    /// 动态添加/更新信任节点 (热加载)
    pub fn trust_node(&self, pub_key: [u8; 32], permissions: u32) {
        let id = blake3::hash(&pub_key).into();
        let mut wl = self.whitelist.write();
        wl.insert(id, (permissions, pub_key));
        
        // 如果该节点在黑名单中，移除它
        let mut bl = self.blacklist.write();
        bl.remove(&id);
    }

    /// 动态封禁节点
    pub fn block_node(&self, id: NodeID) {
        let mut bl = self.blacklist.write();
        bl.insert(id);
        // 从白名单移除
        let mut wl = self.whitelist.write();
        wl.remove(&id);
    }

    /// 核心：零信任连接检查 (Zero Trust Connection Check)
    /// 在握手阶段调用。如果返回 false，该包将被静默丢弃，不暴露任何端口特征。
    pub fn allow_connection(&self, remote_static_pub: &[u8]) -> bool {
        let id: NodeID = blake3::hash(remote_static_pub).into();

        // 1. 检查黑名单 (O(1))
        if self.blacklist.read().contains(&id) {
            return false;
        }

        // 2. 检查白名单 (O(1))
        let wl = self.whitelist.read();
        if wl.contains_key(&id) {
            return true;
        }

        // 3. 策略判定
        // 如果不是严格模式，且不在黑名单，则允许连接 (开放模式)
        // 如果是严格模式，未在白名单即拒绝
        !self.strict_mode
    }

    /// 验证控制帧的安全性与权限
    pub fn verify_frame(&self, frame: &Frame) -> Result<bool> {
        match frame {
            Frame::Injection { target_session, injector_id, command, signature } => {
                // 1. 再次检查黑名单 (防止连接建立后被拉黑)
                if self.blacklist.read().contains(injector_id) {
                    return Err(anyhow!("Node is blacklisted"));
                }

                // 2. 获取权限与公钥
                let wl = self.whitelist.read();
                let (perms, pub_key_bytes) = wl.get(injector_id)
                    .ok_or_else(|| anyhow!("Node not authorized for injection"))?;

                // 3. 权限位检查
                let required_perm = match command {
                    InjectionCommand::RouteHint { .. } => CAP_ROUTE_HINT,
                    InjectionCommand::Throttle { .. } => CAP_THROTTLE,
                    InjectionCommand::ServiceAdvertisement { .. } => CAP_SERVICE_AD,
                };

                if (perms & required_perm) == 0 && (perms & CAP_ADMIN) == 0 {
                    return Err(anyhow!("Permission denied: Missing capability"));
                }

                // 4. Ed25519 签名验证 (防篡改)
                // 验证内容必须包含 SessionID 和 Command，防止重放攻击到其他 Session
                let verify_key = VerifyingKey::from_bytes(pub_key_bytes)
                    .map_err(|_| anyhow!("Invalid stored public key"))?;
                
                let sig_obj = Signature::from_bytes(signature);

                let mut msg = Vec::new();
                msg.extend_from_slice(&target_session.to_le_bytes());
                // 序列化 Command，确保字节序一致
                let cmd_bytes = bincode::serialize(command)?;
                msg.extend_from_slice(&cmd_bytes);

                verify_key.verify(&msg, &sig_obj)
                    .map_err(|_| anyhow!("Invalid signature verification"))?;

                Ok(true)
            },
            // 其他非控制帧由 Session 层的加密保证安全性，无需 ACL 介入
            _ => Ok(true),
        }
    }
}
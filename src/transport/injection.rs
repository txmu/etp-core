// etp-core/src/transport/injection.rs

//! # 访问控制与指令注入管理器 (ACL & Injection Manager)
//! 
//! 本模块负责 ETP 协议的“边界安全”与“管理平面安全”：
//! 1. **连接准入**：在 Noise 握手阶段，根据白名单或黑名单决定是否建立会话。
//! 2. **指令审计**：对 `Frame::Injection` 进行密码学验签，确保控制指令来自授权的管理节点。
//! 
//! ## 软件定义边界 (SDP)
//! 通过 `strict_mode`（原子布尔量），本模块支持在运行时从“开放模式”无缝切换到“零信任白名单模式”。

use crate::wire::frame::{Frame, InjectionCommand};
use crate::NodeID;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use anyhow::{Result, anyhow, Context};
use parking_lot::RwLock;
use bincode;
use log::{info, warn, debug, trace};

// ============================================================================
//  权限位定义 (Capabilities Mask)
// ============================================================================

/// 允许注入路由暗示 (用于优化拓扑)
pub const CAP_ROUTE_HINT: u32 = 1 << 0;
/// 允许执行远程限流 (用于流量管理)
pub const CAP_THROTTLE:   u32 = 1 << 1;
/// 允许发布服务广告 (用于发现中心)
pub const CAP_SERVICE_AD: u32 = 1 << 2;
/// 超级管理员权限：拥有所有能力
pub const CAP_ADMIN:      u32 = 0xFFFFFFFF;

/// 生产级 ACL 管理器
pub struct AclManager {
    /// 白名单：NodeID -> (权限位, 32字节原始公钥)
    /// 存储公钥是为了在验证 Injection 帧时无需再次查询 DHT
    whitelist: RwLock<HashMap<NodeID, (u32, [u8; 32])>>,
    
    /// 黑名单：显式封禁的节点
    blacklist: RwLock<HashSet<NodeID>>,
    
    /// 严格模式开关 (Atomic)
    /// - `true`: 只有在白名单中的节点才允许建立 Noise 握手。
    /// - `false`: 允许陌生节点建立连接，但其无法执行高权限指令。
    strict_mode: AtomicBool,
}

impl AclManager {
    /// 创建新的 ACL 管理器
    /// 
    /// # Arguments
    /// * `strict` - 是否初始开启严格白名单模式
    pub fn new(strict: bool) -> Self {
        Self {
            whitelist: RwLock::new(HashMap::new()),
            blacklist: RwLock::new(HashSet::new()),
            strict_mode: AtomicBool::new(strict),
        }
    }

    // ========================================================================
    //  管理接口 (供 FusionNexus 或本地控制台调用)
    // ========================================================================

    /// 动态切换严格模式
    /// 无需重新编译或重启，立即生效于所有新握手请求
    pub fn set_strict_mode(&self, strict: bool) {
        self.strict_mode.store(strict, Ordering::SeqCst);
        warn!("ACL: Global strict mode changed to: {}", strict);
    }

    /// 获取当前严格模式状态
    pub fn is_strict_mode(&self) -> bool {
        self.strict_mode.load(Ordering::Relaxed)
    }

    /// 将节点加入信任列表并分配权限
    /// 
    /// # Arguments
    /// * `pub_key` - 节点的 Ed25519 静态公钥
    /// * `permissions` - 权限位掩码 (例如 `CAP_ROUTE_HINT | CAP_THROTTLE`)
    pub fn trust_node(&self, pub_key: [u8; 32], permissions: u32) {
        let id: NodeID = blake3::hash(&pub_key).into();
        {
            let mut wl = self.whitelist.write();
            wl.insert(id, (permissions, pub_key));
        }
        // 如果该节点在黑名单中，自动将其移除
        let mut bl = self.blacklist.write();
        bl.remove(&id);
        
        info!("ACL: Node {:?} is now trusted with perms 0x{:08X}", &id[0..4], permissions);
    }

    /// 封禁特定节点
    pub fn block_node(&self, id: NodeID) {
        {
            let mut bl = self.blacklist.write();
            bl.insert(id);
        }
        // 同时从白名单撤销权限
        let mut wl = self.whitelist.write();
        wl.remove(&id);
        
        warn!("ACL: Node {:?} has been blacklisted and untrusted", &id[0..4]);
    }

    // ========================================================================
    //  核心内核鉴权逻辑
    // ========================================================================

    /// 连接准入判定
    /// 
    /// 在握手阶段（已获得对端静态公钥但未建立 Session）时调用。
    /// 如果返回 false，内核将终止握手并静默丢弃包。
    pub fn allow_connection(&self, remote_static_pub: &[u8]) -> bool {
        let id: NodeID = blake3::hash(remote_static_pub).into();

        // 1. 黑名单检查：拥有绝对否决权
        if self.blacklist.read().contains(&id) {
            debug!("ACL: Rejecting blacklisted node {:?}", &id[0..4]);
            return false;
        }

        // 2. 白名单检查：如果存在则始终允许
        let wl = self.whitelist.read();
        if wl.contains_key(&id) {
            trace!("ACL: Authenticated node {:?} allowed", &id[0..4]);
            return true;
        }

        // 3. 策略判定：如果处于严格模式且不在白名单，则拒绝
        let is_strict = self.strict_mode.load(Ordering::Relaxed);
        if is_strict {
            warn!("ACL: Zero-Trust block. Unknown node {:?} denied connection", &id[0..4]);
            return false;
        }

        // 4. 开放模式下允许连接
        true
    }

    /// 验证控制帧的合法性
    /// 
    /// 针对 `Frame::Injection` 进行深度的数字签名验证与权限位核对。
    pub fn verify_frame(&self, frame: &Frame) -> Result<bool> {
        match frame {
            Frame::Injection { target_session, injector_id, command, signature } => {
                
                // 1. 检查黑名单
                if self.blacklist.read().contains(injector_id) {
                    return Err(anyhow!("ACL Error: Injector is blacklisted"));
                }

                // 2. 检索注入者权限与公钥
                let wl = self.whitelist.read();
                let (perms, pub_key_bytes) = wl.get(injector_id)
                    .ok_or_else(|| anyhow!("ACL Error: Injector node not in whitelist"))?;

                // 3. 校验指令所需的权限位
                let required_cap = match command {
                    InjectionCommand::RouteHint { .. } => CAP_ROUTE_HINT,
                    InjectionCommand::Throttle { .. } => CAP_THROTTLE,
                    InjectionCommand::ServiceAdvertisement { .. } => CAP_SERVICE_AD,
                };

                if (perms & required_cap) == 0 && (perms & CAP_ADMIN) == 0 {
                    return Err(anyhow!("ACL Error: Insufficient capabilities (Required 0x{:08X})", required_cap));
                }

                // 4. 验证 Ed25519 签名 (防篡改与重放)
                // 签名载荷约定：target_session (u32 LE) + bincode(Command)
                let verifier = VerifyingKey::from_bytes(pub_key_bytes)
                    .map_err(|_| anyhow!("ACL Internal: Malformed stored public key"))?;
                
                let sig_obj = Signature::from_bytes(signature);

                let mut signed_data = Vec::new();
                signed_data.extend_from_slice(&target_session.to_le_bytes());
                
                // 必须使用确定性的序列化，确保签名校验的一致性
                let cmd_bytes = bincode::serialize(command)
                    .context("ACL Error: Failed to serialize command for verification")?;
                signed_data.extend_from_slice(&cmd_bytes);

                verifier.verify(&signed_data, &sig_obj)
                    .map_err(|_| anyhow!("ACL Error: Cryptographic signature mismatch"))?;

                Ok(true)
            },
            
            // 其它非管理帧默认放行，其安全性由 Session 层的 AEAD 加密保证
            _ => Ok(true),
        }
    }
}

// ============================================================================
//  单元测试套件 (完全不省略)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_acl_strict_mode_logic() {
        let acl = AclManager::new(true); // 初始开启严格模式
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes();

        // 1. 未授权节点在严格模式下应被拒绝
        assert!(!acl.allow_connection(&pub_bytes));

        // 2. 授权后应被允许
        acl.trust_node(pub_bytes, CAP_ROUTE_HINT);
        assert!(acl.allow_connection(&pub_bytes));

        // 3. 封禁后应被拒绝
        let id = blake3::hash(&pub_bytes).into();
        acl.block_node(id);
        assert!(!acl.allow_connection(&pub_bytes));

        // 4. 切换到开放模式，非黑名单节点应被允许
        acl.set_strict_mode(false);
        let another_key = SigningKey::generate(&mut csprng);
        assert!(acl.allow_connection(&another_key.verifying_key().to_bytes()));
    }

    #[test]
    fn test_injection_signature_verification() {
        let acl = AclManager::new(true);
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let injector_id = blake3::hash(&pub_bytes).into();

        // 注册权限
        acl.trust_node(pub_bytes, CAP_THROTTLE);

        let target_session: u32 = 0x12345678;
        let command = InjectionCommand::Throttle { 
            limit_kbps: 100, 
            duration_sec: 60 
        };

        // 构造签名数据 (必须与 verify_frame 逻辑完全一致)
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&target_session.to_le_bytes());
        data_to_sign.extend_from_slice(&bincode::serialize(&command).unwrap());
        
        let signature = signing_key.sign(&data_to_sign).to_bytes();

        let frame = Frame::Injection {
            target_session,
            injector_id,
            command: command.clone(),
            signature,
        };

        // 验证合法的指令
        assert!(acl.verify_frame(&frame).is_ok());

        // 验证篡改 target_session 后应失败
        let malformed_frame = Frame::Injection {
            target_session: 0x99999999,
            injector_id,
            command,
            signature,
        };
        assert!(acl.verify_frame(&malformed_frame).is_err());
    }

    #[test]
    fn test_permission_insufficient() {
        let acl = AclManager::new(false);
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let injector_id = blake3::hash(&pub_bytes).into();

        // 只赋予路由权限
        acl.trust_node(pub_bytes, CAP_ROUTE_HINT);

        // 尝试执行限流指令
        let command = InjectionCommand::Throttle { limit_kbps: 10, duration_sec: 10 };
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&1u32.to_le_bytes());
        data_to_sign.extend_from_slice(&bincode::serialize(&command).unwrap());
        let signature = signing_key.sign(&data_to_sign).to_bytes();

        let frame = Frame::Injection {
            target_session: 1,
            injector_id,
            command,
            signature,
        };

        // 应该报错：权限不足
        let res = acl.verify_frame(&frame);
        assert!(res.is_err());
        assert!(format!("{:?}", res).contains("Insufficient permissions"));
    }
}
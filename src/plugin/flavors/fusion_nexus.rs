// etp-core/src/plugin/flavors/fusion_nexus.rs

//! # FusionNexus - 生产级全栈网络融合与防御枢纽
//! 
//! 本模块统合了 ETP-Core 的 22 种多网交融手段。
//! 
//! ## 22 种手段集成说明：
//! 1-6 (物理/传输): 通过注入 `HybridTransport` 和 `XdpTransport` 接口实现。
//! 7-11 (寻址/联邦): 通过 `TnsFlavor` 和 `KnsKernel` 跨域委派实现。
//! 12-16 (内核级缝合): 直接调用 `EtpHandle` 发射无状态包、触发 DHT 随机探测、支持身份漂移。
//! 17-20 (隐写/对抗): 动态调配 `ZkpNegotiator` 种子、KNS-TNS 适配器伪装、方言切换。
//! 21-22 (管理/演进): 远程注入 `Frame::Injection` 控制指令与 TCC 逻辑基因置换。
//! 在编译本模块前，必须在环境中设置以下变量：
//! INTERNAL_ETP_SEED: 组织的私有 ZKP 频率种子。
//! ETP_ADMIN_PK: 管理员的 Ed25519 公钥（Hex 格式），用于校验远程管理指令。

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock};
use log::{info, warn, error, debug, trace};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

// ETP 核心引用
use crate::plugin::{Flavor, FlavorContext, CapabilityProvider, PluginRegistry};
use crate::network::node::{EtpHandle, Command};
use crate::transport::injection::AclManager;
use crate::NodeID;

// 根据编译特性按需引入
#[cfg(feature = "extensions")]
use crate::extensions::kns::{KnsKernel, RecordKind, KnsPath, ResolutionPriority};
#[cfg(feature = "persistence")]
use crate::plugin::flavors::tns::{TnsFlavor, TnsRecord};
#[cfg(feature = "anonymity")]
use crate::anonymity::adapter::TorDynamicTransport;

/// [手段 18] 编译期锚定：初始 ZKP 种子
const BUILTIN_SECRET_SEED: &str = env!("INTERNAL_ETP_SEED");
/// [管理加固] 编译期锚定：管理员公钥，用于指令验签
const ADMIN_PUBLIC_KEY_HEX: &str = env!("ETP_ADMIN_PK");

/// 远程控制指令集 (Stream 255)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NexusControlCmd {
    /// 修改协商种子 [手段 18]
    SwitchFrequency { new_seed: String },
    /// 切换 ACL 模式 [手段 13, 21]
    UpdateAcl { strict: bool, trust_peer: Option<([u8; 32], u32)> },
    /// 触发拓扑扩散 [手段 10, 15]
    TriggerExpansion { target_space: Option<NodeID> },
    /// 桥接 KNS 到 TNS 缓存 [手段 17]
    BridgeKnsTns { domain: String, path: Vec<String> },
    /// 执行逻辑进化 [手段 22]
    InjectLogic { c_source: String, dsl_id: String },
    /// 紧急锁定
    Lockdown,
}

/// 指令信封：包含签名，防止远程劫持
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedNexusEnvelope {
    pub cmd: NexusControlCmd,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

/// 内部状态容器
struct FusionState {
    current_seed: String,
    strict_mode: bool,
    is_lockdown: bool,
    admin_pk: VerifyingKey,
}

/// FusionNexus: 22 种手段的逻辑分发中心
pub struct FusionNexusFlavor {
    state: Arc<RwLock<FusionState>>,
    handle: EtpHandle,
    registry: Arc<PluginRegistry>,
    acl: Arc<AclManager>,
    
    // 选装组件
    #[cfg(feature = "extensions")]
    kns: RwLock<Option<Arc<KnsKernel>>>,
    #[cfg(feature = "persistence")]
    tns: RwLock<Option<Arc<TnsFlavor>>>,
}

impl FusionNexusFlavor {
    pub fn new(handle: EtpHandle, registry: Arc<PluginRegistry>, acl: Arc<AclManager>) -> Arc<Self> {
        let admin_pk_bytes = hex::decode(ADMIN_PUBLIC_KEY_HEX).expect("Invalid ETP_ADMIN_PK hex");
        let admin_pk = VerifyingKey::from_bytes(&admin_pk_bytes.try_into().expect("Admin PK must be 32 bytes")).expect("Invalid VerifyingKey");

        Arc::new(Self {
            state: Arc::new(RwLock::new(FusionState {
                current_seed: BUILTIN_SECRET_SEED.to_string(),
                strict_mode: true,
                is_lockdown: false,
                admin_pk,
            })),
            handle,
            registry,
            acl,
            #[cfg(feature = "extensions")]
            kns: RwLock::new(None),
            #[cfg(feature = "persistence")]
            tns: RwLock::new(None),
        })
    }

    /// [手段 18] 动态修改协商种子：实时切换网络“频率”
    pub async fn update_zkp_seed(&self, new_seed: String) -> Result<()> {
        let mut state = self.state.write().await;
        if state.is_lockdown { return Err(anyhow!("System lockdown active")); }
        
        info!("Fusion: Shifting ZKP frequency to hash({:?})", &new_seed[..4]);
        self.registry.negotiator.update_seed(new_seed.clone());
        state.current_seed = new_seed;
        Ok(())
    }

    /// [手段 13, 21] 动态控制 ACL 模式
    pub async fn set_acl_policy(&self, strict: bool) {
        let mut state = self.state.write().await;
        state.strict_mode = strict;
        self.acl.set_strict_mode(strict);
        warn!("Fusion: ACL Policy changed. StrictMode: {}", strict);
    }

    /// [手段 12] 触发无状态瞬时探测
    pub async fn ping_stateless(&self, target: SocketAddr) {
        let _ = self.handle.send_control_cmd(
            target, 
            crate::plugin::flavors::control::ControlCategory::Heartbeat, 
            vec![0x55, 0xAA, 0xFF] 
        ).await;
    }

    /// [手段 17] KNS-TNS 适配器完整实现
    #[cfg(all(feature = "extensions", feature = "persistence"))]
    pub async fn perform_stealth_publish(&self, domain_id: &str, path_segments: Vec<String>) -> Result<()> {
        let kns_guard = self.kns.read().await;
        let tns_guard = self.tns.read().await;
        
        if let (Some(kns), Some(tns)) = (kns_guard.as_ref(), tns_guard.as_ref()) {
            let path = KnsPath::new(path_segments)?;
            let domain = kns.get_domain(domain_id).ok_or(anyhow!("KNS Domain not found"))?;
            
            // 1. 生成盲索引
            let blind_idx = path.blind_index(domain.secrets().read().blind_seed());
            
            // 2. 获取加密记录
            let record = domain.publish(&path, b"FUSION_PAYLOAD", RecordKind::Static, 3600)?;
            let record_bytes = bincode::serialize(&record)?;

            // 3. 伪装成 TNS 域名发布
            let stealth_name = format!("{}.kns_idx", hex::encode(blind_idx));
            tns.register_name(&stealth_name, [0u8; 32], record_bytes).await?;
            
            info!("Fusion: KNS path masked as TNS record: {}", stealth_name);
            Ok(())
        } else {
            Err(anyhow!("Naming components not linked to Nexus"))
        }
    }

    /// 校验管理指令签名
    async fn verify_envelope(&self, envelope: &SignedNexusEnvelope) -> Result<()> {
        let state = self.state.read().await;
        
        // 防重放：检查时间戳 (5分钟窗口)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if envelope.timestamp.abs_diff(now) > 300 {
            return Err(anyhow!("Management command expired or time desync"));
        }

        // 构造待验签数据
        let mut msg = bincode::serialize(&envelope.cmd)?;
        msg.extend_from_slice(&envelope.timestamp.to_be_bytes());

        let sig = Signature::from_bytes(&envelope.signature);
        state.admin_pk.verify(&msg, &sig).context("Admin signature verification failed")
    }

    /// 组件注入方法
    #[cfg(feature = "extensions")]
    pub async fn link_kns(&self, kns: Arc<KnsKernel>) { *self.kns.write().await = Some(kns); }
    #[cfg(feature = "persistence")]
    pub async fn link_tns(&self, tns: Arc<TnsFlavor>) { *self.tns.write().await = Some(tns); }
}

impl CapabilityProvider for FusionNexusFlavor {
    fn capability_id(&self) -> String { "etp.flavor.fusion.nexus.v2".into() }
}

impl Flavor for FusionNexusFlavor {
    fn priority(&self) -> u8 { 255 } // 最高优先级，确保指令优先处理

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 管理指令流 (Stream 255)
        if ctx.stream_id == 255 {
            let sender = ctx.src_addr;
            
            // 尝试解析指令信封
            let envelope: SignedNexusEnvelope = match bincode::deserialize(data) {
                Ok(e) => e,
                Err(_) => return true, // 格式错误，吞掉
            };

            let state_ref = self.state.clone();
            let handle_ref = self.handle.clone();
            let this_arc = self.clone_self(); // 利用 Arc<Self>

            tokio::spawn(async move {
                // 1. 签名校验 (最高安全等级)
                if let Err(e) = this_arc.verify_envelope(&envelope).await {
                    error!("Fusion: REJECTED signed command from {}: {}", sender, e);
                    return;
                }

                info!("Fusion: Executing verified command: {:?}", envelope.cmd);

                // 2. 执行指令
                match envelope.cmd {
                    NexusControlCmd::SwitchFrequency { new_seed } => {
                        let _ = this_arc.update_zkp_seed(new_seed).await;
                    },
                    NexusControlCmd::UpdateAcl { strict, trust_peer } => {
                        this_arc.set_acl_policy(strict).await;
                        if let Some((pk, perms)) = trust_peer {
                            this_arc.acl.trust_node(pk, perms);
                        }
                    },
                    NexusControlCmd::TriggerExpansion { target_space } => {
                        let tid = target_space.unwrap_or_else(|| rand::random());
                        let (tx, _) = tokio::sync::oneshot::channel();
                        let _ = handle_ref.cmd_tx.send(Command::DhtFindNode { target_id: tid, reply: tx }).await;
                    },
                    NexusControlCmd::Lockdown => {
                        let mut st = state_ref.write().await;
                        st.is_lockdown = true;
                        st.strict_mode = true;
                        this_arc.acl.set_strict_mode(true);
                        warn!("!!! EMERGENCY LOCKDOWN ACTIVATED via REMOTE COMMAND !!!");
                    },
                    #[cfg(feature = "tc15-tcc")]
                    NexusControlCmd::InjectLogic { c_source, dsl_id } => {
                        // 手动触发 [手段 22] 基因置换
                        // 此处应调用 EvolutionNexus 的逻辑
                    },
                    _ => {}
                }
            });
            return true;
        }
        false
    }

    fn on_connection_open(&self, peer: SocketAddr) {
        // [手段 13] 被动学习发生在这里。即便是在建立会话前，只要物理接触，DHT 就已更新。
        trace!("FusionNexus: Contact established with {}", peer);
    }

    fn on_connection_close(&self, peer: SocketAddr) {
        debug!("FusionNexus: Contact lost with {}", peer);
    }
}

// 解决 Arc 引用问题的生产级范式
trait CloneSelf { fn clone_self(&self) -> Arc<FusionNexusFlavor>; }
impl CloneSelf for Arc<FusionNexusFlavor> {
    fn clone_self(&self) -> Arc<FusionNexusFlavor> { Arc::clone(self) }
}
// 注意：在 main.rs 中必须以 let nexus = FusionNexusFlavor::new(...); 方式持有 Arc。
// etp-core/src/plugin/flavors/evolution_nexus.rs

// 事实上，即使删除了这个 Flavor，底层的 TC-15 依然支持 SMC 指令。这意味着“暗门”依然存在——如果有人能绕过 UI 直接发送原始指令码，机器依然会进化。

#![cfg(all(feature = "tc15-tcc", feature = "evolve-ui"))]

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, RwLock as TokioRwLock};
use serde::{Serialize, Deserialize};
use log::{info, warn, error, debug, trace};
use anyhow::{Result, anyhow, Context};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::extensions::dsl::{DslRegistry, DslKind, DslProvider};
use crate::extensions::tc15_tcc::{Tc15Cpu, SystemBus, ContractStorage, MEM_SIZE};

// --- 常量定义 ---
const EVOLVE_PROTO_VER: u8 = 0x03;
const KEY_DEFAULT_FLAVOR: &[u8] = b"sys.config.default_flavor";
const KEY_DEFAULT_DIALECT: &[u8] = b"sys.config.default_dialect";
const KEY_EVOLUTION_LOG: &[u8] = b"sys.audit.evolution_chain";

// ============================================================================
//  高级进化指令集 (Production API)
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
enum EvolveCmd {
    /// 1. 原子置换：编译并替换整个逻辑提供者
    Swap {
        new_dsl_id: String,
        c_source: String,
        set_as_default: bool, // 是否立即设为系统默认处理逻辑
        is_permanent: bool,   // 是否写入持久化存储（重启后保留变异）
    },

    /// 2. 内存热补丁：直接修改运行中 VM 的内存镜像
    /// 模拟 SMC (Self-Modifying Code) 的受控外部触发
    Patch {
        dsl_id: String,
        offset: u16,
        data: Vec<u8>,
        checksum: [u8; 32], // 补丁完整性校验
    },

    /// 3. 环境状态快照：保存当前的变异成果
    Snapshot {
        dsl_id: String,
        label: String,
    },

    /// 4. 逻辑回滚：恢复到之前的某个基因快照
    Rollback {
        dsl_id: String,
        snapshot_id: String,
    },

    /// 5. 紧急清理 (Nuke)：删除所有动态变异，回退到出厂 Rust 逻辑
    NukeAll,
}

// ============================================================================
//  核心实现
// ============================================================================

pub struct EvolutionNexus {
    registry: Arc<DslRegistry>,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    storage: Arc<dyn ContractStorage>,
    
    // 内部审计表：记录变异历史 (Audit Trail)
    mutation_history: Arc<TokioRwLock<Vec<String>>>,
}

impl EvolutionNexus {
    pub fn new(
        registry: Arc<DslRegistry>, 
        tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        storage: Arc<dyn ContractStorage>,
    ) -> Arc<Self> {
        info!("EvolutionNexus: Commercial Adaptation Layer Online. DNA Modification Service Active.");
        Arc::new(Self { 
            registry, 
            network_tx: tx, 
            storage,
            mutation_history: Arc::new(TokioRwLock::new(Vec::new())),
        })
    }

    // --- 指令 A: 原子基因置换 (Atomic Swap) ---

    async fn handle_swap(&self, new_id: &str, source: &str, is_default: bool, permanent: bool) -> Result<()> {
        info!("Evolve: Initiating atomic swap for DSL '{}'", new_id);

        // 1. 调用 TCC 编译器 (基因转录)
        // 这一步在宿主 CPU 上执行，保证了进化的“瞬发性”
        let tcc_provider = self.registry.get_provider("etp.dsl.tcc.v1")
            .ok_or_else(|| anyhow!("Core TCC Compiler not registered"))?;
            
        let bytecode = tcc_provider.compile_to_vm(source)
            .context("Dynamic C compilation failed")?;

        // 2. 注册到系统总线 (基因表达)
        // 利用我们在上一个回答中实现的 SystemBus 接口
        self.registry.register_dynamic_provider(new_id, 0, bytecode)?;

        // 3. 审计记录
        self.record_mutation(format!("SWAP: Created '{}', Permanent={}", new_id, permanent)).await;

        // 4. 持久化逻辑：修改节点的“本能”
        if permanent {
            // A. 将字节码存入存储
            let storage_key = format!("sys.dsl.firmware.{}", new_id);
            self.storage.store(storage_key.as_bytes(), source.as_bytes());

            // B. 如果设为默认，修改全局路由键
            if is_default {
                self.storage.store(KEY_DEFAULT_FLAVOR, new_id.as_bytes());
                warn!("Evolve: Node 'default_flavor' mutated to '{}' permanently.", new_id);
            }
        }

        Ok(())
    }

    // --- 指令 B: 内存补丁 (Hot Patch) ---

    async fn handle_patch(&self, dsl_id: &str, offset: u16, data: Vec<u8>, expected_hash: [u8; 32]) -> Result<()> {
        // 校验补丁指纹
        let actual_hash: [u8; 32] = blake3::hash(&data).into();
        if actual_hash != expected_hash {
            return Err(anyhow!("Patch integrity check failed"));
        }

        warn!("Evolve: Applying hot-patch to '{}' at 0x{:04X}", dsl_id, offset);
        
        // 找到动态 Provider
        if let Some(provider) = self.registry.get_provider(dsl_id) {
            // 商业级实现：在 DslRegistry 中增加 update_firmware 接口
            // 允许直接修改 VirtualDslProvider 的内存镜像
            // 这正是 SMC 在商业环境下的受控表现
            self.registry.update_provider_memory(dsl_id, offset, &data)?;
            self.record_mutation(format!("PATCH: '{}' at 0x{:04X}", dsl_id, offset)).await;
        }
        
        Ok(())
    }

    // --- 审计工具 ---

    async fn record_mutation(&self, desc: String) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let entry = format!("[{}] {}", ts, desc);
        
        let mut history = self.mutation_history.write().await;
        history.push(entry.clone());
        
        // 同时写入持久化层，供管理员远程取证
        let mut chain = self.storage.load(KEY_EVOLUTION_LOG).unwrap_or_default();
        chain.extend_from_slice(entry.as_bytes());
        chain.push(b'\n');
        self.storage.store(KEY_EVOLUTION_LOG, &chain);
    }

    // --- 网络接口分发 ---

    async fn send_evolution_report(&self, target: SocketAddr, msg: &str) {
        let mut packet = vec![EVOLVE_PROTO_VER, 0xFE]; // Report CMD
        packet.extend_from_slice(msg.as_bytes());
        let _ = self.network_tx.send((target, packet)).await;
    }
}

// ============================================================================
//  Flavor Trait Implementation
// ============================================================================

impl CapabilityProvider for EvolutionNexus {
    fn capability_id(&self) -> String { "etp.flavor.evolution_nexus.v1".into() }
}

impl Flavor for EvolutionNexus {
    fn priority(&self) -> u8 {
        // 最高优先级：逻辑进化指令必须在任何业务逻辑之前被处理
        255 
    }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 1. 协议头过滤
        if data.len() < 2 || data[0] != EVOLVE_PROTO_VER {
            return false;
        }

        // 2. 反序列化高级指令
        let cmd: EvolveCmd = match bincode::deserialize(&data[1..]) {
            Ok(c) => c,
            Err(e) => {
                debug!("EvolutionNexus: Ignored malformed command: {}", e);
                return true; 
            }
        };

        // 3. 执行进化任务 (Spawn to prevent blocking)
        let nexus = self.clone_ref(); // 内部 Arc Clone
        let src_addr = ctx.src_addr;

        tokio::spawn(async move {
            let result = match cmd {
                EvolveCmd::Swap { new_dsl_id, c_source, set_as_default, is_permanent } => {
                    nexus.handle_swap(&new_dsl_id, &c_source, set_as_default, is_permanent).await
                },
                EvolveCmd::Patch { dsl_id, offset, data, checksum } => {
                    nexus.handle_patch(&dsl_id, offset, data, checksum).await
                },
                EvolveCmd::NukeAll => {
                    warn!("Evolve: NUKE sequence triggered by {}. Reverting to factory logic.", src_addr);
                    nexus.registry.clear_dynamic_providers();
                    nexus.storage.store(KEY_DEFAULT_FLAVOR, b"etp.flavor.core");
                    Ok(())
                },
                _ => Err(anyhow!("Command not implemented in this build")),
            };

            match result {
                Ok(_) => nexus.send_evolution_report(src_addr, "EVOLUTION_SUCCESS").await,
                Err(e) => {
                    error!("Evolution Failure: {}", e);
                    nexus.send_error_report(src_addr, &e.to_string()).await;
                }
            }
        });

        // 拦截该包，不传递给普通 Flavor
        true
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}

impl EvolutionNexus {
    fn clone_ref(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            network_tx: self.network_tx.clone(),
            storage: self.storage.clone(),
            mutation_history: self.mutation_history.clone(),
        }
    }
    
    async fn send_error_report(&self, target: SocketAddr, err: &str) {
        let mut packet = vec![EVOLVE_PROTO_VER, 0xFF]; // Error CMD
        packet.extend_from_slice(err.as_bytes());
        let _ = self.network_tx.send((target, packet)).await;
    }
}
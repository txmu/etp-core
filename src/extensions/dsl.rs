// etp-core/src/extensions/dsl.rs

#![cfg(feature = "dsl-runtime")]

use std::sync::Arc;
use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use anyhow::{Result, anyhow, Context};
use log::{info, warn, debug, error};

// 引入 TC-15 (如果启用)
#[cfg(feature = "tc15-tcc")]
use crate::extensions::tc15_tcc::{Tc15Cpu, ContractStorage, MEM_SIZE, REG_COUNT};

// ============================================================================
//  1. DSL 抽象定义
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DslKind {
    /// 声明式/非图灵完备 (Declarative)
    /// 预期执行时间极短 (e.g. < 1ms)，通常是规则匹配。
    /// 尽管如此，生产环境仍建议将其视为 CPU 密集型任务处理。
    Declarative,

    /// 图灵完备 (Turing Complete)
    /// 必须在 TC-15 沙箱中执行，受 Gas 和 Memory 限制。
    /// 编译和执行过程可能较慢。
    TuringComplete,
}

/// 这是一个特殊的 Provider，它不跑 Rust 代码，而是启动一个新的 TC-15 VM
struct VirtualDslProvider {
    id: String,
    entry_pc: u16,
    firmware: Vec<u8>,
    storage: Arc<dyn ContractStorage>,
}

/// DSL 提供者接口 (由开发者实现)
/// 所有方法都是同步的，因为它们将在 blocking_thread 中被调用
impl DslProvider for VirtualDslProvider {
    fn id(&self) -> &str { &self.id }
    fn kind(&self) -> DslKind { DslKind::TuringComplete }

    fn execute_declarative(&self, _: &str, _: &Value) -> Result<Value> {
        Err(anyhow!("Virtual providers are Turing Complete only"))
    }

    #[cfg(feature = "tc15-tcc")]
    fn compile_to_vm(&self, _: &str) -> Result<Vec<u8>> {
        // 它已经是机器码了，直接返回镜像
        Ok(self.firmware.clone())
    }
}

// 为 DslRegistry 实现 SystemBus
impl SystemBus for DslRegistry {
    fn register_dynamic_provider(&self, id: &str, entry_pc: u16, code: Vec<u8>) -> Result<()> {
        let new_provider = Arc::new(VirtualDslProvider {
            id: id.to_string(),
            entry_pc,
            firmware: code,
            storage: self.vm_storage.clone(),
        });
        
        // 核心：直接插入现有的 HashMap，实现秒级进化
        self.register(new_provider); 
        Ok(())
    }
}

// ============================================================================
//  2. DSL 注册表与引擎 (The Engine)
// ============================================================================

pub struct DslRegistry {
    providers: RwLock<HashMap<String, Arc<dyn DslProvider>>>,
    
    // 全局 VM 存储接口 (用于 EXT 指令访问持久化数据)
    #[cfg(feature = "tc15-tcc")]
    vm_storage: Arc<dyn ContractStorage>,
}

impl DslRegistry {
    #[cfg(not(feature = "tc15-tcc"))]
    pub fn new() -> Self {
        Self { providers: RwLock::new(HashMap::new()) }
    }

    #[cfg(feature = "tc15-tcc")]
    pub fn new(storage: Arc<dyn ContractStorage>) -> Self {
        Self { 
            providers: RwLock::new(HashMap::new()),
            vm_storage: storage,
        }
    }

    /// 注册 DSL Provider
    pub fn register(&self, provider: Arc<dyn DslProvider>) {
        let id = provider.id().to_string();
        info!("DSL Registry: Registered '{}' ({:?})", id, provider.kind());
        self.providers.write().insert(id, provider);
    }

    /// 获取 Provider (用于在 Executor 中判断类型)
    pub fn get_provider(&self, dsl_id: &str) -> Option<Arc<dyn DslProvider>> {
        self.providers.read().get(dsl_id).cloned()
    }

    /// 执行 DSL 脚本 (同步阻塞方法，调用者负责线程调度)
    /// gas_limit: 仅对 TuringComplete 有效
    pub fn run_blocking(&self, dsl_id: &str, script: &str, context: &Value, gas_limit: u64) -> Result<String> {
        let provider = self.providers.read().get(dsl_id)
            .ok_or_else(|| anyhow!("Unknown DSL ID: {}", dsl_id))?
            .clone();

        match provider.kind() {
            DslKind::Declarative => {
                let res = provider.execute_declarative(script, context)
                    .context("Declarative execution failed")?;
                // 统一返回 String 格式
                Ok(res.to_string())
            },
            DslKind::TuringComplete => {
                self.run_vm_logic(provider.as_ref(), script, context, gas_limit)
            }
        }
    }

    #[cfg(feature = "tc15-tcc")]
    fn run_vm_logic(&self, provider: &dyn DslProvider, script: &str, context: &Value, gas_limit: u64) -> Result<String> {
        // 1. 编译 (CPU Intensive)
        let bytecode = provider.compile_to_vm(script)
            .context("DSL Compilation failed")?;

        if bytecode.len() > MEM_SIZE / 2 {
            return Err(anyhow!("Bytecode exceeds 50% of VM memory limit"));
        }

        // 2. 初始化 VM (Sandbox)
        let mut cpu = Tc15Cpu::new(self.vm_storage.clone());
        
        // 3. 内存布局与上下文注入
        // Layout: [Bytecode ... ] [Padding] [Context Data]
        // 约定: 
        //   R1 = Context Data Start Address
        //   R2 = Context Data Length
        
        // 加载代码
        cpu.load_code(&bytecode, 0);

        // 序列化上下文
        let ctx_str = context.to_string();
        let ctx_bytes = ctx_str.as_bytes();
        
        // 计算数据存放位置 (从内存末尾向前存放，防止覆盖代码)
        // 这是一个安全的内存布局策略
        let data_addr = (MEM_SIZE - ctx_bytes.len()) as u16;
        
        // 检查栈溢出风险 (SP 初始在末尾)
        // 在此简化模型中，我们假设数据区是只读的输入，放在堆区上方，
        // 实际 TC-15 的 SP 初始化在 MEM_SIZE - 2。
        // 为了安全，我们将数据放在代码段之后，并留出足够的栈空间。
        let code_end = bytecode.len() as u16;
        let data_start = if code_end < 0x8000 { 0x8000 } else { code_end + 256 }; // 0x8000 (32KB) 处作为数据区
        
        if (data_start as usize) + ctx_bytes.len() >= MEM_SIZE {
             return Err(anyhow!("OOM: Code + Context too large"));
        }

        // 写入 Context
        for (i, b) in ctx_bytes.iter().enumerate() {
            cpu.memory[data_start as usize + i] = *b;
        }

        // 设置寄存器参数 (ABI)
        cpu.regs[1] = data_start;
        cpu.regs[2] = ctx_bytes.len() as u16;

        // 4. 执行 (受 Gas 限制)
        cpu.execute(gas_limit).context("VM Execution runtime error")?;

        // 5. 获取输出
        Ok(cpu.get_output())
    }

    #[cfg(not(feature = "tc15-tcc"))]
    fn run_vm_logic(&self, _p: &dyn DslProvider, _s: &str, _c: &Value, _g: u64) -> Result<String> {
        Err(anyhow!("Feature 'tc15-tcc' is disabled"))
    }
}
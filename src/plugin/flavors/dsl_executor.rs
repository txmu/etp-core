// etp-core/src/plugin/flavors/dsl_executor.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;

use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use serde_json::Value;

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::extensions::dsl::DslRegistry;

// --- 协议定义 ---
const DSL_PROTO_VER: u8 = 0x01;
const CMD_EXEC: u8 = 0x01;
const CMD_RESULT: u8 = 0x02;
const CMD_ERROR: u8 = 0xFF;

// --- 生产配置 ---
const MAX_CONCURRENT_SCRIPTS: usize = 16; // 限制同时执行的脚本数量，防止耗尽线程池
const SCRIPT_TIMEOUT_MS: u64 = 5000;      // 5秒超时
const DEFAULT_GAS_LIMIT: u64 = 1_000_000; // 1M Gas

#[derive(Serialize, Deserialize, Debug)]
struct ExecRequest {
    dsl_id: String,
    script: String,
    context: Value,
    // 可选：请求方可以建议一个更低的 Gas，但不能超过节点上限
    gas_limit: Option<u64>,
}

pub struct DslExecutorFlavor {
    registry: Arc<DslRegistry>,
    network_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    // 并发信号量：防止 DoS 攻击导致节点 CPU 100%
    concurrency_limiter: Arc<Semaphore>,
}

impl DslExecutorFlavor {
    pub fn new(registry: Arc<DslRegistry>, tx: mpsc::Sender<(SocketAddr, Vec<u8>)>) -> Arc<Self> {
        Arc::new(Self { 
            registry, 
            network_tx: tx,
            concurrency_limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_SCRIPTS)),
        })
    }

    async fn send_response(&self, target: SocketAddr, result: Result<String>) {
        let mut packet = vec![DSL_PROTO_VER];
        match result {
            Ok(output) => {
                packet.push(CMD_RESULT);
                packet.extend(output.into_bytes());
            },
            Err(e) => {
                packet.push(CMD_ERROR);
                packet.extend(e.to_string().into_bytes());
            }
        }
        
        if let Err(_) = self.network_tx.send((target, packet)).await {
            debug!("DSL: Failed to send response to {}", target);
        }
    }
}

impl CapabilityProvider for DslExecutorFlavor {
    fn capability_id(&self) -> String { "etp.flavor.dsl_exec.v2".into() }
}

impl Flavor for DslExecutorFlavor {
    fn priority(&self) -> u8 { 120 }

    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        // 1. 基础协议检查
        if data.len() < 2 || data[0] != DSL_PROTO_VER { return false; }
        if data[1] != CMD_EXEC { return false; }

        // 2. 反序列化请求
        let req: ExecRequest = match bincode::deserialize(&data[2..]) {
            Ok(r) => r,
            Err(e) => {
                warn!("DSL: Malformed request from {}: {}", ctx.src_addr, e);
                // 格式错误不回包，防止反射攻击
                return true; 
            }
        };

        // 3. 检查 DSL 是否存在 (Fail Fast)
        if self.registry.get_provider(&req.dsl_id).is_none() {
            let tx_clone = self.network_tx.clone();
            let addr = ctx.src_addr;
            tokio::spawn(async move {
                // 构造错误包
                let msg = format!("Unknown DSL: {}", req.dsl_id);
                let resp = vec![DSL_PROTO_VER, CMD_ERROR, msg.len() as u8]; // Simplified error frame
                // ... 发送逻辑 ...
            });
            return true;
        }

        // 4. 准备异步执行环境
        // 需要 Clone Arc 以便传入 Future
        let registry = self.registry.clone();
        let limiter = self.concurrency_limiter.clone();
        let myself = self.clone_ref(); // 需要实现 Helper 或手动 Arc Clone
        // 由于 Flavor trait 是 &self，我们假设 Flavor 自身在外部被 Arc 包裹，
        // 但在这里我们只能 clone 内部字段来构造闭包
        let network_tx = self.network_tx.clone();
        let src_addr = ctx.src_addr;

        // 5. 启动异步任务
        tokio::spawn(async move {
            // A. 获取并发许可 (Backpressure)
            // 如果并发满了，立即拒绝或等待。这里选择等待（带超时）。
            let _permit = match timeout(Duration::from_millis(100), limiter.acquire()).await {
                Ok(Ok(p)) => p,
                _ => {
                    warn!("DSL: Server busy, dropping request from {}", src_addr);
                    // Server Busy Error Response
                    let resp = vec![DSL_PROTO_VER, CMD_ERROR]; 
                    let _ = network_tx.send((src_addr, resp)).await;
                    return;
                }
            };

            info!("DSL: Scheduling execution for {} from {}", req.dsl_id, src_addr);

            // B. 卸载到 Blocking Thread (核心生产级要求)
            // 无论是声明式还是图灵完备，DSL 解析和执行都是 CPU 密集型的。
            // 绝对不能在 Tokio Reactor 线程中运行。
            let gas = req.gas_limit.unwrap_or(DEFAULT_GAS_LIMIT).min(DEFAULT_GAS_LIMIT);
            
            let exec_result = tokio::task::spawn_blocking(move || {
                registry.run_blocking(&req.dsl_id, &req.script, &req.context, gas)
            }).await;

            // C. 处理结果 (JoinError vs ExecutionError)
            let final_result = match exec_result {
                Ok(res) => res, // 内部执行结果 (Ok/Err)
                Err(join_err) => {
                    error!("DSL: Task panic or cancelled: {}", join_err);
                    Err(anyhow::anyhow!("Internal Server Error: Task Panic"))
                }
            };

            // D. 发送响应
            // 手动构造响应逻辑 (复用上文 send_response 的逻辑)
            let mut packet = vec![DSL_PROTO_VER];
            match final_result {
                Ok(output) => {
                    packet.push(CMD_RESULT);
                    packet.extend(output.into_bytes());
                },
                Err(e) => {
                    packet.push(CMD_ERROR);
                    packet.extend(e.to_string().into_bytes());
                }
            }
            let _ = network_tx.send((src_addr, packet)).await;
            
            // _permit Drop 这里会自动释放信号量
        });

        true
    }

    fn on_connection_open(&self, _: SocketAddr) {}
    fn on_connection_close(&self, _: SocketAddr) {}
}

// 辅助: 需要手动实现 clone 逻辑，因为 &self 无法直接转 Arc
impl DslExecutorFlavor {
    fn clone_ref(&self) -> Self {
        // 这不是真的 Arc Clone，而是创建新结构体共享内部 Arc
        Self {
            registry: self.registry.clone(),
            network_tx: self.network_tx.clone(),
            concurrency_limiter: self.concurrency_limiter.clone(),
        }
    }
}
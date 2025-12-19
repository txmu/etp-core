// etp-core/src/extensions/tc15_tcc.rs

#![cfg(feature = "tc15-tcc")]

use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicBool, Ordering};
use std::time::{Instant, Duration};

use parking_lot::{Mutex, RwLock};
use log::{info, debug, warn, error, trace};
use anyhow::{Result, anyhow, Context};
use byteorder::{LittleEndian, ByteOrder};
use serde::{Serialize, Deserialize};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::NodeID;

// ============================================================================
//  1. ISA 架构定义 (修复版)
// ============================================================================

pub const MEM_SIZE: usize = 65536;
pub const REG_COUNT: usize = 16;

// 寄存器别名规范 (ABI)
pub const REG_RA: usize = 0;  // Return Value / Accumulator
pub const REG_SP: usize = 15; // Stack Pointer
pub const REG_FP: usize = 14; // Frame Pointer
pub const REG_LR: usize = 13; // Link Register (Return Address)
pub const REG_IM: usize = 12; // Interrupt Mask / Temp

// 内存映射 IO (MMIO)
pub const MMIO_BASE: u16 = 0xFF00;
pub const MMIO_STDOUT: u16    = 0xFF00; // Write Only
pub const MMIO_STDIN: u16     = 0xFF01; // Read Only
pub const MMIO_INT_ACK: u16   = 0xFF02; // Interrupt Acknowledge
pub const MMIO_GAS_LEFT: u16  = 0xFF03; // Gas Remaining (Smart Contract)
pub const MMIO_BLOCK_TS: u16  = 0xFF04; // Block Timestamp

// 标志位
pub const FLAG_Z: u8 = 0b0000_0001; // Zero
pub const FLAG_C: u8 = 0b0000_0010; // Carry
pub const FLAG_S: u8 = 0b0000_0100; // Sign
pub const FLAG_O: u8 = 0b0000_1000; // Overflow
pub const FLAG_I: u8 = 0b0010_0000; // Interrupt Enable (Global)
pub const FLAG_E: u8 = 0b0100_0000; // Execution Error (Fault)

// ETP 协议头
const TC15_PROTO_VER: u8 = 0x02;
const CMD_DEPLOY: u8 = 0x01; // 部署合约
const CMD_CALL: u8   = 0x02; // 调用合约
const CMD_SIGNAL: u8 = 0x03; // 发送中断信号

// ============================================================================
//  2. 虚拟机核心 (CPU)
// ============================================================================

/// 智能合约状态存储接口
pub trait ContractStorage: Send + Sync {
    fn load(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn store(&self, key: &[u8], value: &[u8]);
}

/// 内存中的简单存储实现
#[derive(Default)]
struct EphemeralStorage {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}
impl ContractStorage for EphemeralStorage {
    fn load(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.read().get(key).cloned()
    }
    fn store(&self, key: &[u8], value: &[u8]) {
        self.data.write().insert(key.to_vec(), value.to_vec());
    }
}

/// 定义 CPU 可以调用的外部系统服务
pub trait SystemBus: Send + Sync {
    /// 注册一个新的 DSL 处理函数
    /// id: 插件 ID
    /// entry_pc: 虚拟机内存中的入口地址
    /// code: 该插件的完整机器码镜像
    fn register_dynamic_provider(&self, id: &str, entry_pc: u16, code: Vec<u8>) -> Result<()>;
}

pub struct Tc15Cpu {
    // 寄存器堆 R0-R15
    pub regs: [u16; REG_COUNT], // 升级为 16位 寄存器以支持 64KB 地址空间
    pub pc: u16,
    pub flags: u8,
    
    // 内存
    pub memory: Vec<u8>,
    
    // 中断控制器
    // interrupt_pending 每一位代表一个中断线 (0-7)
    pub interrupt_pending: Arc<AtomicU8>, 
    pub interrupt_vectors: [u16; 8],
    
    // 运行状态
    pub running: bool,
    pub gas_limit: u64,
    pub gas_used: u64,
    
    // IO & Storage
    pub output_buffer: Vec<u8>,
    pub storage: Arc<dyn ContractStorage>,
    
    pub bus: Option<Arc<dyn SystemBus>>, // 注入系统总线
}

/// 虚拟机指令周期执行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmStatus {
    Running,            // 正常运行
    Halted,             // 遇到 HALT 指令或主动停机
    WaitingForInterrupt, // 挂起并等待外部信号（Yield 模式）
    ExecutionFault,      // 运行时致命错误（如非法指令或越界）
}

impl Tc15Cpu {

    /// 生产级内存读取：安全地从内存获取一个 16 位小端序整数
    /// 边界检查失败时返回 ExecutionFault 错误，防止 Rust 进程 panic
    pub fn read_u16_safe(&self, addr: u16) -> Result<u16> {
        let start = addr as usize;
        let end = start + 2;

        // 利用 slice 的 get 方法进行零开销边界检查
        if let Some(bytes) = self.memory.get(start..end) {
            // TC-15 架构约定为小端序 (Little Endian)
            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            Err(anyhow::anyhow!(
                "VM Segmentation Fault: Read u16 out of bounds at 0x{:04X}",
                addr
            ))
        }
    }

    /// 生产级内存写入：安全地向内存写入一个 16 位小端序整数
    /// 用于支持受控的自修改代码 (SMC)
    pub fn write_u16_safe(&mut self, addr: u16, val: u16) -> Result<()> {
        let start = addr as usize;
        let end = start + 2;
        let bytes = val.to_le_bytes();

        if let Some(mem_slice) = self.memory.get_mut(start..end) {
            mem_slice.copy_from_slice(&bytes);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "VM Segmentation Fault: Write u16 out of bounds at 0x{:04X}",
                addr
            ))
        }
    }

    /// 安全读取定长字节块（常用于获取 32 字节加密密钥或 NodeID）
    pub fn read_bytes_safe(&self, addr: u16, len: usize) -> Result<Vec<u8>> {
        let start = addr as usize;
        let end = start + len;

        if let Some(bytes) = self.memory.get(start..end) {
            Ok(bytes.to_vec())
        } else {
            Err(anyhow::anyhow!(
                "VM Segmentation Fault: Read bytes out of bounds at 0x{:04X}, len {}",
                addr, len
            ))
        }
    }

    /// 安全读取以 \0 结尾的字符串
    /// 用于 EXT_REGISTER_PROVIDER 动态注册插件名称
    pub fn read_string_safe(&self, addr: u16) -> Result<String> {
        let start = addr as usize;
        let mut result = Vec::new();

        for i in start..MEM_SIZE {
            let byte = self.memory[i];
            if byte == 0 {
                return String::from_utf8(result).map_err(|e| anyhow::anyhow!("Invalid UTF-8 string in VM memory: {}", e));
            }
            result.push(byte);
            if result.len() > 255 { // 强制上限，防止恶意构造的超长字符串消耗内存
                return Err(anyhow::anyhow!("VM String exceeded max length of 255"));
            }
        }
        Err(anyhow::anyhow!("VM String not null-terminated"))
    }

    /// 安全写入大块数据（Blob）
    /// 用于向虚拟机注入上下文数据或从 Storage 恢复数据
    pub fn write_blob_safe(&mut self, addr: u16, data: &[u8]) -> Result<()> {
        let start = addr as usize;
        let end = start + data.len();

        if let Some(mem_slice) = self.memory.get_mut(start..end) {
            mem_slice.copy_from_slice(data);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "VM Segmentation Fault: Write blob out of bounds at 0x{:04X}, len {}",
                addr, data.len()
            ))
        }
    }

    /// 获取寄存器索引的辅助函数
    /// 确保 C 编译器生成的字节码不会引用 R15 以外的非法寄存器
    fn fetch_reg_idx(&mut self) -> Result<usize> {
        let idx = self.fetch_u8() as usize;
        if idx < REG_COUNT {
            Ok(idx)
        } else {
            Err(anyhow::anyhow!("VM Error: Invalid register index R{}", idx))
        }
    }

    /// 核心执行入口
    /// gas_limit: 本轮允许消耗的最大算力配额
    pub fn execute(&mut self, gas_limit: u64) -> Result<VmStatus> {
        self.running = true;
        self.gas_limit = gas_limit;

        while self.running {
            // 1. 严格 Gas 校验
            if self.gas_used >= self.gas_limit {
                self.flags |= FLAG_E;
                return Err(anyhow!("Gas limit exceeded (Execution resource exhaustion)"));
            }

            // 2. 硬件中断处理（原子性检查）
            // 使用 Acquire 语义确保看到最新的中断线信号
            let pending = self.interrupt_pending.load(Ordering::Acquire);
            if (self.flags & FLAG_I) != 0 && pending != 0 {
                let irq = pending.trailing_zeros() as u8;
                if irq < 8 {
                    self.trigger_interrupt(irq);
                }
            }

            // 3. 取指阶段 (Instruction Fetch)
            // 支持动态指令重映射：从内存取出的原始字节通过解码表转义
            let raw_op = self.fetch_u8();
            let decoded_op = self.decoding_table[raw_op as usize];

            // 4. 执行阶段 (Execution Step)
            match self.step(decoded_op)? {
                VmStatus::Running => {
                    // 指令正常完成，进入下一循环
                    continue;
                }
                VmStatus::WaitingForInterrupt => {
                    // 指令流挂起：交还 CPU 给宿主，维持当前 PC 指针
                    self.running = false;
                    trace!("VM [PC:0x{:04X}] suspended, yielding to host.", self.pc);
                    return Ok(VmStatus::WaitingForInterrupt);
                }
                VmStatus::Halted => {
                    // 程序正常结束
                    self.running = false;
                    return Ok(VmStatus::Halted);
                }
                VmStatus::ExecutionFault => {
                    self.running = false;
                    self.flags |= FLAG_E;
                    return Ok(VmStatus::ExecutionFault);
                }
            }
        }
        Ok(VmStatus::Halted)
    }

    /// 基础指令集逻辑
    /// 包含严格的寄存器索引与内存访问边界检查
    fn step(&mut self, opcode: u8) -> Result<VmStatus> {
        match opcode {
            // --- 0x0X: 系统控制 ---
            0x00 => return Ok(VmStatus::Halted), // HALT
            0x01 => { self.gas_used += 1; },      // NOP

            // --- 0x1R / 0x2R: 栈帧优化访问 (C 语言局部变量热路径) ---
            op if op >= 0x10 && op <= 0x2F => {
                let is_store = op >= 0x20;
                let reg_idx = (op & 0x0F) as usize;
                let offset = self.fetch_i8() as i16;
                let addr = self.regs[REG_FP].wrapping_add_signed(offset);
                
                if is_store {
                    self.write_u16_safe(addr, self.regs[reg_idx])?;
                    self.gas_used += 3; // 内存写入权重更高
                } else {
                    self.regs[reg_idx] = self.read_u16_safe(addr)?;
                    self.gas_used += 2;
                }
            }

            // --- 0x3X: 通用数据传输 ---
            0x30 => { // MOVI Rd, Imm16
                let rd = self.fetch_reg_idx()?;
                self.regs[rd] = self.fetch_u16();
                self.gas_used += 1;
            },
            0x31 => { // MOV Rd, Rs
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize;
                let rs = (byte & 0x0F) as usize;
                self.regs[rd] = self.regs[rs];
                self.gas_used += 1;
            },
            0x32 => { // LOAD Rd, [Rs]
                let byte = self.fetch_u8();
                let (rd, rs) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                self.regs[rd] = self.read_u16_safe(self.regs[rs])?;
                self.gas_used += 2;
            },
            0x33 => { // STORE [Rd], Rs (支持自修改代码 SMC)
                let byte = self.fetch_u8();
                let (rd, rs) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                self.write_u16_safe(self.regs[rd], self.regs[rs])?;
                self.gas_used += 3;
            },

            // --- 0x4X: ALU 算术逻辑单元 ---
            0x40..=0x45 => {
                self.execute_alu_op(opcode)?;
                self.gas_used += 1;
            },

            // --- 0x5X: 栈操作 ---
            0x50 => { // PUSH Rs
                let rs = self.fetch_reg_idx()?;
                self.push_u16(self.regs[rs])?;
                self.gas_used += 2;
            },
            0x51 => { // POP Rd
                let rd = self.fetch_reg_idx()?;
                self.regs[rd] = self.pop_u16()?;
                self.gas_used += 2;
            },

            // --- 0x6X: 流程控制 ---
            0x60 => { // JMP Imm16
                self.pc = self.fetch_u16();
                self.gas_used += 1;
            },
            0x61 | 0x62 => { // JZ / JNZ
                let target = self.fetch_u16();
                let zero = (self.flags & FLAG_Z) != 0;
                if (opcode == 0x61 && zero) || (opcode == 0x62 && !zero) {
                    self.pc = target;
                }
                self.gas_used += 1;
            },
            0x63 => { // CALL Imm16
                let target = self.fetch_u16();
                let return_addr = self.pc;
                self.push_u16(return_addr)?;
                self.pc = target;
                self.gas_used += 2;
            },
            0x64 => { // RET
                self.pc = self.pop_u16()?;
                self.gas_used += 2;
            },

            // --- 0xFF: 扩展指令前缀 ---
            0xFF => return self.step_extended(),

            _ => {
                error!("VM: Illegal instruction 0x{:02X} at PC:0x{:04X}", opcode, self.pc.wrapping_sub(1));
                return Ok(VmStatus::ExecutionFault);
            }
        }
        Ok(VmStatus::Running)
    }

    /// 扩展指令集 (System & Evolution Layer)
    fn step_extended(&mut self) -> Result<VmStatus> {
        let sub_op = self.fetch_u8();
        match sub_op {
            // 0x01: SWAP Rd, Rs
            0x01 => {
                let byte = self.fetch_u8();
                let (rd, rs) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                self.regs.swap(rd, rs);
                self.gas_used += 1;
            },
            
            // 0x02: CONTRACT_LOAD R_keyptr, R_dst
            0x02 => {
                let byte = self.fetch_u8();
                let (rk, rd) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                let key = self.read_bytes_safe(self.regs[rk], 32)?;
                if let Some(val) = self.storage.load(&key) {
                    self.write_blob_safe(self.regs[rd], &val)?;
                }
                self.gas_used += 50; // 存储操作极重
            },

            // 0x03: CONTRACT_STORE R_keyptr, R_valptr
            0x03 => {
                let byte = self.fetch_u8();
                let (rk, rv) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                let key = self.read_bytes_safe(self.regs[rk], 32)?;
                let val = self.read_blob_safe(self.regs[rv])?;
                self.storage.store(&key, &val);
                self.gas_used += 100;
            },

            // 0x04: RETI (中断返回)
            0x04 => {
                self.flags = (self.pop_u16()? & 0xFF) as u8;
                self.pc = self.pop_u16()?;
                self.flags |= FLAG_I; // 重新开启中断
                self.gas_used += 2;
            },

            // 0x05: WAIT (生产级异步 Yield 实现)
            0x05 => {
                if self.interrupt_pending.load(Ordering::Acquire) == 0 {
                    // 指向当前 WAIT 指令前缀(FF 05)，下次恢复时重新执行校验
                    self.pc = self.pc.wrapping_sub(2);
                    return Ok(VmStatus::WaitingForInterrupt);
                }
                self.gas_used += 1;
            },

            // 0x06: EXT_REGISTER_PROVIDER R_id_ptr, R_entry_pc
            // 核心进化指令：将当前 VM 镜像注册为新的 DSL 提供者
            0x06 => {
                let byte = self.fetch_u8();
                let (rid, rpc) = ((byte >> 4) as usize, (byte & 0x0F) as usize);
                if let Some(bus) = &self.bus {
                    let id_str = self.read_string_safe(self.regs[rid])?;
                    let entry_pc = self.regs[rpc];
                    let image = self.memory.clone();
                    bus.register_dynamic_provider(&id_str, entry_pc, image)?;
                    info!("VM: Evolutionary mutation complete. New provider '{}' registered.", id_str);
                }
                self.gas_used += 500; // 进化操作最重
            },

            _ => return Err(anyhow!("Unknown extended opcode 0xFF{:02X}", sub_op)),
        }
        Ok(VmStatus::Running)
    }
}

    // --- 辅助方法 ---

    fn fetch_u8(&mut self) -> u8 {
        let val = self.read_mem(self.pc);
        self.pc = self.pc.wrapping_add(1);
        val
    }

    fn fetch_u16(&mut self) -> u16 {
        let low = self.fetch_u8();
        let high = self.fetch_u8();
        u16::from_le_bytes([low, high])
    }
    
    fn fetch_i8(&mut self) -> i8 {
        self.fetch_u8() as i8
    }

    fn read_mem(&self, addr: u16) -> u8 {
        // MMIO Map
        if addr == MMIO_STDIN {
            // Read from IO buffer
            return 0; // Stub
        }
        if addr == MMIO_INT_ACK {
            return 0;
        }
        if addr == MMIO_BLOCK_TS {
            // Mock timestamp low byte
            return (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() & 0xFF) as u8;
        }
        self.memory[addr as usize]
    }

    fn write_mem(&mut self, addr: u16, val: u8) {
        if addr == MMIO_STDOUT {
            self.output_buffer.push(val);
            return;
        }
        if addr == MMIO_INT_ACK {
            // Acknowledge interrupt bit
            self.interrupt_pending.fetch_and(!val, Ordering::SeqCst);
            return;
        }
        self.memory[addr as usize] = val;
    }

    fn read_u16(&self, addr: u16) -> u16 {
        let low = self.read_mem(addr);
        let high = self.read_mem(addr.wrapping_add(1));
        u16::from_le_bytes([low, high])
    }

    fn write_u16(&mut self, addr: u16, val: u16) {
        let bytes = val.to_le_bytes();
        self.write_mem(addr, bytes[0]);
        self.write_mem(addr.wrapping_add(1), bytes[1]);
    }

    fn push(&mut self, val: u16) {
        self.write_u16(self.regs[REG_SP], val);
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_sub(2);
    }

    fn pop(&mut self) -> u16 {
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_add(2);
        self.read_u16(self.regs[REG_SP])
    }

    fn alu_op<F>(&mut self, op: F) 
    where F: FnOnce(u16, u16) -> (u16, bool) 
    {
        let byte = self.fetch_u8();
        let rd = (byte >> 4) as usize;
        let rs = (byte & 0x0F) as usize;
        let (res, carry) = op(self.regs[rd], self.regs[rs]);
        self.regs[rd] = res;
        self.update_flags(res);
        if carry { self.flags |= FLAG_C; } else { self.flags &= !FLAG_C; }
    }

    fn alu_logic<F>(&mut self, op: F)
    where F: FnOnce(u16, u16) -> u16
    {
        let byte = self.fetch_u8();
        let rd = (byte >> 4) as usize;
        let rs = (byte & 0x0F) as usize;
        let res = op(self.regs[rd], self.regs[rs]);
        self.regs[rd] = res;
        self.update_flags(res);
    }

    fn update_flags(&mut self, res: u16) {
        if res == 0 { self.flags |= FLAG_Z; } else { self.flags &= !FLAG_Z; }
        if (res & 0x8000) != 0 { self.flags |= FLAG_S; } else { self.flags &= !FLAG_S; }
    }

    fn trigger_interrupt(&mut self, irq: u8) {
        // 1. Disable interrupts
        self.flags &= !FLAG_I;
        
        // 2. Push Context (PC, Flags)
        self.push(self.pc);
        self.push(self.flags as u16);
        
        // 3. Jump to vector
        // Vector table is at memory 0x0000 + irq*2 ? Or hardcoded?
        // Let's use fixed locations for simplicity: 0xFF00 + irq*2
        // Or user programmable in interrupt_vectors array.
        // For simulation, we assume user loaded vector table at 0x0000.
        // Let's use a convention: Vector 0 is at 0x0002, etc. Reset vector at 0x0000.
        // Simplified: Fixed handler per IRQ.
        let handler = self.read_u16((irq as u16) * 2);
        self.pc = handler;
    }
}

// ============================================================================
//  3. TCC 编译器 (Recursive Descent with Frame Pointer)
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum TokenType {
    KwInt, KwVoid, KwIf, KwReturn, KwFor, KwContract,
    Id(String),
    Num(u16),
    Op(String),
    LPar, RPar, LBrace, RBrace, Semi, Comma, Eq,
    Eof
}

struct Compiler {
    tokens: Vec<TokenType>,
    pos: usize,
    bytecode: Vec<u8>,
    
    // 符号表 (Name -> LocalOffset from FP)
    locals: HashMap<String, i16>,
    local_offset: i16,
    
    // 函数表 (Name -> Address)
    functions: HashMap<String, u16>,
    // 待回填的调用 (AddressOfCall -> FunctionName)
    pending_calls: Vec<(usize, String)>,
}

impl Compiler {
    fn new() -> Self {
        Self {
            tokens: Vec::new(),
            pos: 0,
            bytecode: Vec::new(),
            locals: HashMap::new(),
            local_offset: 0,
            functions: HashMap::new(),
            pending_calls: Vec::new(),
        }
    }

    fn compile(&mut self, src: &str) -> Result<Vec<u8>> {
        self.tokenize(src)?;
        
        // Entry point setup: CALL main; HALT
        self.emit(0x63); // CALL
        let main_call_patch = self.bytecode.len();
        self.emit_u16(0); // Placeholder
        self.emit(0x00);  // HALT

        // Program body
        while self.peek() != TokenType::Eof {
            self.parse_function()?;
        }

        // Patch main address
        if let Some(&addr) = self.functions.get("main") {
            let bytes = addr.to_le_bytes();
            self.bytecode[main_call_patch] = bytes[0];
            self.bytecode[main_call_patch+1] = bytes[1];
        } else {
            return Err(anyhow!("Missing main function"));
        }

        // Patch all pending calls
        for (patch_pos, name) in &self.pending_calls {
            if let Some(&addr) = self.functions.get(name) {
                let bytes = addr.to_le_bytes();
                self.bytecode[*patch_pos] = bytes[0];
                self.bytecode[*patch_pos+1] = bytes[1];
            } else {
                return Err(anyhow!("Undefined function: {}", name));
            }
        }

        Ok(self.bytecode.clone())
    }

    // --- Lexer ---
    fn tokenize(&mut self, src: &str) -> Result<()> {
        let mut chars = src.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
            } else if c.is_alphabetic() || c == '_' {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        s.push(chars.next().unwrap());
                    } else { break; }
                }
                let token = match s.as_str() {
                    "int" => TokenType::KwInt,
                    "void" => TokenType::KwVoid,
                    "if" => TokenType::KwIf,
                    "return" => TokenType::KwReturn,
                    "contract_store" => TokenType::KwContract, // Intrinsics
                    _ => TokenType::Id(s),
                };
                self.tokens.push(token);
            } else if c.is_numeric() {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_numeric() {
                        s.push(chars.next().unwrap());
                    } else { break; }
                }
                self.tokens.push(TokenType::Num(s.parse()?));
            } else {
                match c {
                    '(' => self.tokens.push(TokenType::LPar),
                    ')' => self.tokens.push(TokenType::RPar),
                    '{' => self.tokens.push(TokenType::LBrace),
                    '}' => self.tokens.push(TokenType::RBrace),
                    ';' => self.tokens.push(TokenType::Semi),
                    ',' => self.tokens.push(TokenType::Comma),
                    '=' => {
                        chars.next();
                        if chars.peek() == Some(&'=') {
                            chars.next();
                            self.tokens.push(TokenType::Op("==".into()));
                            continue;
                        }
                        self.tokens.push(TokenType::Eq);
                        continue;
                    },
                    '+' | '-' | '*' | '&' => self.tokens.push(TokenType::Op(c.to_string())),
                    _ => return Err(anyhow!("Unknown char: {}", c)),
                }
                chars.next();
            }
        }
        self.tokens.push(TokenType::Eof);
        Ok(())
    }

    // --- Parser & Codegen ---

    fn parse_function(&mut self) -> Result<()> {
        self.expect_type()?; // int/void
        let name = self.expect_id()?;
        self.functions.insert(name, self.bytecode.len() as u16);
        
        self.consume(TokenType::LPar)?;
        // Args parsing simplified (omitted for brevity, assume void args for now)
        self.consume(TokenType::RPar)?;
        
        self.consume(TokenType::LBrace)?;
        
        // Function Prologue
        // PUSH FP
        self.emit(0x50); self.emit(REG_FP as u8);
        // MOV FP, SP
        self.emit(0x31); self.emit((REG_FP as u8) << 4 | (REG_SP as u8));
        
        self.locals.clear();
        self.local_offset = 0; // Stack grows down

        while self.peek() != TokenType::RBrace {
            self.parse_statement()?;
        }
        self.consume(TokenType::RBrace)?;
        
        // Epilogue (Implicit return if void)
        // MOV SP, FP
        self.emit(0x31); self.emit((REG_SP as u8) << 4 | (REG_FP as u8));
        // POP FP
        self.emit(0x51); self.emit(REG_FP as u8);
        // RET
        self.emit(0x64);
        
        Ok(())
    }

    fn parse_statement(&mut self) -> Result<()> {
        match self.peek() {
            TokenType::KwInt => {
                // int x = 5;
                self.advance();
                let name = self.expect_id()?;
                self.consume(TokenType::Eq)?;
                self.parse_expression()?; // Result in R0
                self.consume(TokenType::Semi)?;
                
                // Allocate local
                self.local_offset -= 2; // u16
                self.locals.insert(name, self.local_offset);
                
                // PUSH R0 (Save to stack)
                self.emit(0x50); self.emit(0);
            },
            TokenType::KwReturn => {
                self.advance();
                self.parse_expression()?; // Result in R0 (RA)
                self.consume(TokenType::Semi)?;
                
                // Epilogue code
                self.emit(0x31); self.emit((REG_SP as u8) << 4 | (REG_FP as u8));
                self.emit(0x51); self.emit(REG_FP as u8);
                self.emit(0x64);
            },
            TokenType::KwContract => {
                // contract_store(key_ptr, val_ptr); (Intrinsic)
                self.advance();
                self.consume(TokenType::LPar)?;
                self.parse_expression()?; // Arg1 -> R0
                // MOV R1, R0 (Save key ptr)
                self.emit(0x31); self.emit(1<<4 | 0);
                self.consume(TokenType::Comma)?;
                self.parse_expression()?; // Arg2 -> R0 (Val ptr)
                self.consume(TokenType::RPar)?;
                self.consume(TokenType::Semi)?;
                
                // EXT: CONTRACT_KEY_STORE R1, R0
                self.emit(0xFF); self.emit(0x03); self.emit(1<<4 | 0);
            },
            _ => {
                // Expression statement (assignment or call)
                // Simplified: Assign only
                let name = self.expect_id()?;
                if let Some(&offset) = self.locals.get(&name) {
                    self.consume(TokenType::Eq)?;
                    self.parse_expression()?;
                    self.consume(TokenType::Semi)?;
                    
                    // STORE [FP+Offset], R0
                    self.emit(0x20); self.emit(0); self.emit(offset as u8);
                } else {
                    return Err(anyhow!("Unknown variable {}", name));
                }
            }
        }
        Ok(())
    }

    fn parse_expression(&mut self) -> Result<()> {
        self.parse_term()?;
        while let TokenType::Op(op) = self.peek() {
            self.advance();
            // Push R0 (Left)
            self.emit(0x50); self.emit(0);
            self.parse_term()?; // Right in R0
            
            // Pop Left to R1
            self.emit(0x51); self.emit(1);
            
            if op == "+" {
                // ADD R0, R1 (R0 += R1)
                self.emit(0x40); self.emit(0<<4 | 1);
            } else if op == "-" {
                // SUB R1, R0 (Need Left - Right). Current: R1=Left, R0=Right.
                // SUB R1, R0 -> R1 = R1 - R0.
                self.emit(0x41); self.emit(1<<4 | 0);
                // Move result back to R0
                self.emit(0x31); self.emit(0<<4 | 1);
            }
        }
        Ok(())
    }

    fn parse_term(&mut self) -> Result<()> {
        match self.peek() {
            TokenType::Num(n) => {
                self.advance();
                // MOVI R0, n
                self.emit(0x30); self.emit(0); self.emit_u16(n);
            },
            TokenType::Id(name) => {
                self.advance();
                if let Some(&offset) = self.locals.get(&name) {
                    // LOAD R0, [FP+Offset]
                    self.emit(0x10); self.emit(0); self.emit(offset as u8);
                } else {
                    return Err(anyhow!("Undefined var {}", name));
                }
            },
            _ => return Err(anyhow!("Unexpected token in expression")),
        }
        Ok(())
    }

    // --- Helpers ---
    fn peek(&self) -> TokenType {
        if self.pos >= self.tokens.len() { TokenType::Eof } else { self.tokens[self.pos].clone() }
    }
    fn advance(&mut self) { self.pos += 1; }
    fn consume(&mut self, ty: TokenType) -> Result<()> {
        if self.peek() == ty { self.advance(); Ok(()) } else { Err(anyhow!("Expected {:?}", ty)) }
    }
    fn expect_id(&mut self) -> Result<String> {
        if let TokenType::Id(s) = self.peek() { self.advance(); Ok(s) } else { Err(anyhow!("Expected ID")) }
    }
    fn expect_type(&mut self) -> Result<()> {
        match self.peek() {
            TokenType::KwInt | TokenType::KwVoid => { self.advance(); Ok(()) },
            _ => Err(anyhow!("Expected type"))
        }
    }
    fn emit(&mut self, b: u8) { self.bytecode.push(b); }
    fn emit_u16(&mut self, v: u16) {
        let b = v.to_le_bytes();
        self.emit(b[0]); self.emit(b[1]);
    }
}

// ============================================================================
//  4. ETP Flavor 集成
// ============================================================================

pub struct Tc15Flavor {
    network_tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>,
    storage: Arc<dyn ContractStorage>,
    
    // 中断控制器引用 (用于 Flavor 线程注入信号)
    // 实际运行时，每个会话可能有一个 VM。为了简单，这里演示无状态执行。
    // 如果需要有状态的中断，需要 SessionContext 持有 CPU。
    // 在这里，我们只实现 "执行一次" 的模型。
}

impl Tc15Flavor {
    pub fn new(
        network_tx: tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>
    ) -> Arc<Self> {
        Arc::new(Self { 
            network_tx,
            storage: Arc::new(EphemeralStorage::default()),
        })
    }

    fn run_vm(&self, code: &[u8]) -> String {
        let mut cpu = Tc15Cpu::new(self.storage.clone());
        cpu.load_code(code, 0);
        
        let start = Instant::now();
        match cpu.execute(1_000_000) { // 1M Gas Limit
            Ok(_) => format!("Success. Output: {}", cpu.get_output()),
            Err(e) => format!("Error: {} (Gas: {})", e, cpu.gas_used),
        }
    }
}

impl CapabilityProvider for Tc15Flavor {
    fn capability_id(&self) -> String { "etp.flavor.tc15.v2".into() }
}

impl Flavor for Tc15Flavor {
    fn on_stream_data(&self, ctx: FlavorContext, data: &[u8]) -> bool {
        if data.len() < 2 || data[0] != TC15_PROTO_VER { return false; }

        match data[1] {
            CMD_DEPLOY | CMD_EXEC_CODE => {
                let code = &data[2..];
                info!("TC15: Executing contract (size {} bytes)", code.len());
                let result = self.run_vm(code);
                
                let tx = self.network_tx.clone();
                let addr = ctx.src_addr;
                tokio::spawn(async move {
                    let mut resp = vec![TC15_PROTO_VER, 0xFF];
                    resp.extend(result.into_bytes());
                    let _ = tx.send((addr, resp)).await;
                });
                true
            },
            CMD_COMPILE_RUN => {
                if let Ok(src) = String::from_utf8(data[2..].to_vec()) {
                    let mut compiler = Compiler::new();
                    match compiler.compile(&src) {
                        Ok(bytecode) => {
                            let result = self.run_vm(&bytecode);
                            let tx = self.network_tx.clone();
                            let addr = ctx.src_addr;
                            tokio::spawn(async move {
                                let mut resp = vec![TC15_PROTO_VER, 0xFF];
                                resp.extend(result.into_bytes());
                                let _ = tx.send((addr, resp)).await;
                            });
                        },
                        Err(e) => {
                            warn!("TC15 Compile Error: {}", e);
                        }
                    }
                }
                true
            },
            _ => false
        }
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}
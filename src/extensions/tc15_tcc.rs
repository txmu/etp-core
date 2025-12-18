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
}

impl Tc15Cpu {
    pub fn new(storage: Arc<dyn ContractStorage>) -> Self {
        let mut cpu = Self {
            regs: [0; REG_COUNT],
            pc: 0,
            flags: 0,
            memory: vec![0; MEM_SIZE],
            interrupt_pending: Arc::new(AtomicU8::new(0)),
            interrupt_vectors: [0; 8], // 默认向量表，通常由 OS 初始化
            running: false,
            gas_limit: 0,
            gas_used: 0,
            output_buffer: Vec::new(),
            storage,
        };
        // 初始化 SP
        cpu.regs[REG_SP] = (MEM_SIZE - 2) as u16;
        cpu
    }

    pub fn reset(&mut self) {
        self.regs.fill(0);
        self.regs[REG_SP] = (MEM_SIZE - 2) as u16;
        self.pc = 0;
        self.flags = 0;
        self.gas_used = 0;
        self.output_buffer.clear();
        self.running = false;
        self.interrupt_pending.store(0, Ordering::Relaxed);
    }

    pub fn load_code(&mut self, code: &[u8], start: u16) {
        let end = start as usize + code.len();
        if end <= MEM_SIZE {
            self.memory[start as usize..end].copy_from_slice(code);
        }
    }

    // --- 核心执行 ---

    /// 运行直到 Gas 耗尽、Halt 或发生错误
    pub fn execute(&mut self, gas_limit: u64) -> Result<()> {
        self.running = true;
        self.gas_limit = gas_limit;
        self.gas_used = 0;

        while self.running {
            if self.gas_used >= self.gas_limit {
                return Err(anyhow!("Gas limit exceeded"));
            }

            // 1. 检查中断
            if (self.flags & FLAG_I) != 0 {
                let pending = self.interrupt_pending.load(Ordering::SeqCst);
                if pending != 0 {
                    // 找到优先级最高的中断 (最低位)
                    let irq = pending.trailing_zeros() as u8;
                    self.trigger_interrupt(irq);
                }
            }

            // 2. 取指
            let opcode = self.fetch_u8();
            
            // 3. 执行
            self.step(opcode)?;
            
            // 4. 计费 (简化模型：每指令 1 Gas)
            self.gas_used += 1;
        }
        Ok(())
    }

    // --- 指令集实现 (修复版) ---
    // 基础指令占据 0x00-0xEF
    // 扩展指令前缀 0xFF
    
    fn step(&mut self, opcode: u8) -> Result<()> {
        match opcode {
            // 系统控制
            0x00 => { self.running = false; } // HALT
            0x01 => { // NOP
            }
            
            // 数据传输 (Load/Store)
            // 0x1R -> LOAD R, [FP+Offset] (Local Var Access Optimization)
            op if op >= 0x10 && op <= 0x1F => {
                let r = (op & 0x0F) as usize;
                let offset = self.fetch_i8() as i16; // 相对 FP 的有符号偏移
                let addr = self.regs[REG_FP].wrapping_add_signed(offset);
                self.regs[r] = self.read_u16(addr);
            }
            
            // 0x2R -> STORE [FP+Offset], R
            op if op >= 0x20 && op <= 0x2F => {
                let r = (op & 0x0F) as usize;
                let offset = self.fetch_i8() as i16;
                let addr = self.regs[REG_FP].wrapping_add_signed(offset);
                self.write_u16(addr, self.regs[r]);
            }

            // 0x30: MOVI Rd, Imm16
            0x30 => {
                let rd = self.fetch_u8() as usize;
                let imm = self.fetch_u16();
                if rd < REG_COUNT { self.regs[rd] = imm; }
            }
            
            // 0x31: MOV Rd, Rs
            0x31 => {
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize;
                let rs = (byte & 0x0F) as usize;
                if rd < REG_COUNT && rs < REG_COUNT {
                    self.regs[rd] = self.regs[rs];
                }
            }

            // 0x32: LOAD Rd, [Rs]
            0x32 => {
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize;
                let rs = (byte & 0x0F) as usize;
                let addr = self.regs[rs];
                self.regs[rd] = self.read_u16(addr);
            }

            // 0x33: STORE [Rd], Rs
            0x33 => {
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize; // Addr
                let rs = (byte & 0x0F) as usize; // Val
                let addr = self.regs[rd];
                self.write_u16(addr, self.regs[rs]);
            }

            // 算术运算 (ALU)
            // 0x40: ADD Rd, Rs
            0x40 => self.alu_op(|a, b| a.overflowing_add(b)),
            // 0x41: SUB Rd, Rs
            0x41 => self.alu_op(|a, b| a.overflowing_sub(b)),
            // 0x42: AND Rd, Rs
            0x42 => self.alu_logic(|a, b| a & b),
            // 0x43: OR Rd, Rs
            0x43 => self.alu_logic(|a, b| a | b),
            // 0x44: XOR Rd, Rs
            0x44 => self.alu_logic(|a, b| a ^ b),
            // 0x45: SHL Rd, Imm
            0x45 => {
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize;
                let bits = byte & 0x0F;
                self.regs[rd] <<= bits;
                self.update_flags(self.regs[rd]);
            }
            
            // 栈操作
            0x50 => { // PUSH Rs
                let rs = self.fetch_u8() as usize;
                if rs < REG_COUNT { self.push(self.regs[rs]); }
            }
            0x51 => { // POP Rd
                let rd = self.fetch_u8() as usize;
                if rd < REG_COUNT { self.regs[rd] = self.pop(); }
            }

            // 流程控制
            0x60 => { // JMP Imm16
                let target = self.fetch_u16();
                self.pc = target;
            }
            0x61 => { // JZ Imm16
                let target = self.fetch_u16();
                if (self.flags & FLAG_Z) != 0 { self.pc = target; }
            }
            0x62 => { // JNZ Imm16
                let target = self.fetch_u16();
                if (self.flags & FLAG_Z) == 0 { self.pc = target; }
            }
            0x63 => { // CALL Imm16
                let target = self.fetch_u16();
                self.push(self.pc);
                self.pc = target;
            }
            0x64 => { // RET
                self.pc = self.pop();
            }

            // --- 扩展指令前缀 (Extension Page) ---
            0xFF => {
                let sub_op = self.fetch_u8();
                self.step_extended(sub_op)?;
            }

            _ => {
                // Invalid Opcode
                self.flags |= FLAG_E;
                return Err(anyhow!("Invalid opcode 0x{:02X} at PC:{:04X}", opcode, self.pc-1));
            }
        }
        Ok(())
    }

    fn step_extended(&mut self, sub_op: u8) -> Result<()> {
        match sub_op {
            // 0x01: SWAP Rd, Rs (修复的原冲突指令)
            0x01 => {
                let byte = self.fetch_u8();
                let rd = (byte >> 4) as usize;
                let rs = (byte & 0x0F) as usize;
                self.regs.swap(rd, rs);
            },
            
            // 0x02: CONTRACT_KEY_LOAD R_keyptr, R_dest
            // 从 Storage 加载数据
            0x02 => {
                let byte = self.fetch_u8();
                let r_key = (byte >> 4) as usize;
                let r_dst = (byte & 0x0F) as usize;
                let key_addr = self.regs[r_key];
                
                // 假设 Key 是 32 字节，从 memory[key_addr] 读取
                let mut key = vec![0u8; 32];
                for i in 0..32 {
                    if (key_addr as usize + i) < MEM_SIZE {
                        key[i] = self.memory[key_addr as usize + i];
                    }
                }
                
                if let Some(val) = self.storage.load(&key) {
                    // 结果写入 dest 指向的内存缓冲区
                    let dst_addr = self.regs[r_dst];
                    // 写入长度 (2 bytes) + 数据
                    self.write_u16(dst_addr, val.len() as u16);
                    for (i, b) in val.iter().enumerate() {
                        self.write_mem(dst_addr.wrapping_add(2).wrapping_add(i as u16), *b);
                    }
                } else {
                    // Not found, write length 0
                    let dst_addr = self.regs[r_dst];
                    self.write_u16(dst_addr, 0);
                }
            },

            // 0x03: CONTRACT_KEY_STORE R_keyptr, R_valptr
            0x03 => {
                let byte = self.fetch_u8();
                let r_key = (byte >> 4) as usize;
                let r_val = (byte & 0x0F) as usize;
                
                // Read Key (32 bytes)
                let key_addr = self.regs[r_key];
                let mut key = vec![0u8; 32];
                for i in 0..32 {
                    key[i] = self.read_mem(key_addr.wrapping_add(i as u16));
                }
                
                // Read Value (Length prefixed)
                let val_addr = self.regs[r_val];
                let len = self.read_u16(val_addr);
                let mut val = vec![0u8; len as usize];
                for i in 0..len {
                    val[i as usize] = self.read_mem(val_addr.wrapping_add(2).wrapping_add(i));
                }
                
                self.storage.store(&key, &val);
            },

            // 0x04: RETI (Return from Interrupt)
            0x04 => {
                self.flags = (self.pop() & 0xFF) as u8;
                self.pc = self.pop();
                self.flags |= FLAG_I; // Re-enable interrupts
            },

            // 0x05: WAIT (Wait for Interrupt / Gas Saver)
            0x05 => {
                if self.interrupt_pending.load(Ordering::Relaxed) == 0 {
                    self.pc = self.pc.wrapping_sub(2); // Rewind PC to point to FF 05
                    // Yield execution in host loop
                    // In this sync step function we can't yield easily, 
                    // but in `execute` loop we could add a check.
                    // For now, it's a busy wait in simulation.
                }
            },

            _ => return Err(anyhow!("Unknown extended opcode 0xFF {:02X}", sub_op)),
        }
        Ok(())
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
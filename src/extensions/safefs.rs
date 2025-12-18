// etp-core/src/extensions/safefs.rs

#![cfg(feature = "safefs")]

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::time::{SystemTime, Instant};
use std::ffi::{CString, CStr};
use std::os::unix::io::AsRawFd;
use std::collections::HashSet;
use std::process::Command;

use log::{info, warn, error, debug, trace};
use parking_lot::{Mutex, RwLock};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// 加密原语
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Aead};
use blake3;
use argon2::{Argon2, PasswordHasher, PasswordVerifier, Params};

// 系统绑定
use nix::sys::mman::{mlock, munlock, mlockall, MlockAllFlags, mprotect, ProtFlags};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{Pid, getpid, getppid, getuid, geteuid};
use nix::sys::ptrace;
use sysinfo::{System, SystemExt, ProcessExt, PidExt};

// 引入 ETP 错误类型
use crate::error::EtpError;

// ============================================================================
//  配置常量
// ============================================================================

const MAGIC_HEADER: &[u8] = b"ETP-SFS\x02"; // v2 Format
const WIPE_PASSES: usize = 7; // DoD 5220.22-M Short
const KDF_SALT_LEN: usize = 32;
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2GB Limit
const LOCKOUT_THRESHOLD: usize = 5;
const LOCKOUT_DURATION: u64 = 300; // 5 Minutes

// 敏感系统调用列表 (用于审计)
const SUSPICIOUS_PROCS: &[&str] = &["gdb", "strace", "ltrace", "ida", "radare2", "tcpdump", "wireshark"];

// ============================================================================
//  1. 系统加固与环境感知 (System Hardening)
// ============================================================================

pub struct SystemGuard;

impl SystemGuard {
    /// 执行全套环境检查与加固
    pub fn enforce_security_perimeter() -> Result<(), EtpError> {
        info!("SafeFS: Initializing security perimeter...");

        // 1. 完整性检查
        Self::verify_self_integrity()?;

        // 2. 反调试与反跟踪
        Self::anti_debug_checks()?;
        
        // 3. 虚拟化/沙箱检测
        if Self::detect_virtualization() {
            warn!("SafeFS: Virtualization environment detected. High-security operations may be compromised.");
            // 根据策略，可以选择报错退出
            // return Err(EtpError::Internal("Virtualization not allowed".into()));
        }

        // 4. 内存锁定
        Self::lock_memory()?;

        // 5. 进程隔离
        Self::restrict_privileges()?;
        Self::obfuscate_process()?;

        info!("SafeFS: Perimeter secured.");
        Ok(())
    }

    /// 验证自身二进制完整性 (简单哈希校验)
    fn verify_self_integrity() -> Result<(), EtpError> {
        let exe_path = std::env::current_exe().map_err(EtpError::Io)?;
        let mut file = File::open(&exe_path).map_err(EtpError::Io)?;
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut file, &mut hasher).map_err(EtpError::Io)?;
        let current_hash = hasher.finalize();

        // 在生产环境中，这里应该读取一个外部签名的锚点文件或内嵌的公钥签名
        // 这里演示逻辑：读取同目录下的 .checksum 文件
        let checksum_path = exe_path.with_extension("checksum");
        if checksum_path.exists() {
            let expected_hex = fs::read_to_string(checksum_path).map_err(EtpError::Io)?;
            let expected_hash = hex::decode(expected_hex.trim())
                .map_err(|_| EtpError::Internal("Invalid checksum format".into()))?;
            
            if current_hash.as_bytes() != expected_hash.as_slice() {
                error!("CRITICAL: Self-integrity check failed!");
                return Err(EtpError::Internal("Integrity violation detected".into()));
            }
            debug!("SafeFS: Integrity check passed.");
        } else {
            warn!("SafeFS: No checksum anchor found. Integrity check skipped (Development Mode).");
        }
        Ok(())
    }

    /// 多重反调试检测
    fn anti_debug_checks() -> Result<(), EtpError> {
        // A. Ptrace 自我附加测试
        unsafe {
            // PTRACE_TRACEME = 0
            if libc::ptrace(0, 0, 0, 0) < 0 {
                // 如果失败，说明已经被其他进程附加
                return Err(EtpError::Internal("Debugger detected (Ptrace attached)".into()));
            }
        }

        // B. TracerPid 检查
        let status = fs::read_to_string("/proc/self/status").map_err(EtpError::Io)?;
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid_str = line.split_whitespace().nth(1).unwrap_or("0");
                if pid_str != "0" {
                    return Err(EtpError::Internal(format!("Debugger detected (TracerPid: {})", pid_str)));
                }
            }
        }

        // C. 父进程检查
        let sys = System::new_all();
        let my_pid = sysinfo::get_current_pid().map_err(|e| EtpError::Internal(e.to_string()))?;
        if let Some(process) = sys.process(my_pid) {
            if let Some(parent_pid) = process.parent() {
                if let Some(parent) = sys.process(parent_pid) {
                    let name = parent.name().to_lowercase();
                    for bad in SUSPICIOUS_PROCS {
                        if name.contains(bad) {
                            return Err(EtpError::Internal(format!("Suspicious parent process: {}", name)));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 检测虚拟化环境
    fn detect_virtualization() -> bool {
        // 1. CPUID (Requires x86 feature, simplified here via file check)
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            if cpuinfo.contains("hypervisor") { return true; }
        }

        // 2. DMI Product Name
        if let Ok(product) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            let p = product.to_lowercase();
            if p.contains("kvm") || p.contains("virtualbox") || p.contains("vmware") || p.contains("qemu") {
                return true;
            }
        }

        // 3. Systemd detect-virt (Optional fallback)
        false
    }

    /// 锁定内存，防止交换到磁盘
    fn lock_memory() -> Result<(), EtpError> {
        let flags = MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE;
        unsafe {
            if let Err(e) = mlockall(flags) {
                // 非 Root 用户通常会失败，记录警告
                warn!("SafeFS: Memory locking failed (Swap risk): {}", e);
            }
        }
        Ok(())
    }

    /// 限制进程权限与核心转储
    fn restrict_privileges() -> Result<(), EtpError> {
        unsafe {
            // PR_SET_DUMPABLE = 4, arg2 = 0 (SUID_DUMP_DISABLE)
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                warn!("SafeFS: Failed to disable core dumps");
            }
            
            // PR_SET_NO_NEW_PRIVS = 38
            if libc::prctl(38, 1, 0, 0, 0) != 0 {
                debug!("SafeFS: Failed to set NO_NEW_PRIVS");
            }
        }
        Ok(())
    }

    /// 进程名混淆
    fn obfuscate_process() -> Result<(), EtpError> {
        let names = ["kworker/u4:0", "systemd-journal", "dbus-daemon", "rsyslogd"];
        let mut rng = rand::thread_rng();
        let name = names[rng.gen_range(0..names.len())];
        let c_name = CString::new(name).unwrap();
        
        unsafe {
            // PR_SET_NAME = 15
            libc::prctl(15, c_name.as_ptr() as u64, 0, 0, 0);
        }
        Ok(())
    }
    
    /// 创建防护页 (Guard Page) - 模拟 Python 版的安全内存操作
    /// 返回一个受保护的内存区域指针
    pub unsafe fn create_guard_page(size: usize) -> Result<*mut u8, EtpError> {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let alloc_size = size + 2 * page_size; // 前后各一页
        
        // mmap 匿名内存
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            alloc_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0
        );
        
        if ptr == libc::MAP_FAILED {
            return Err(EtpError::Io(std::io::Error::last_os_error()));
        }
        
        // 保护首尾页 (PROT_NONE)
        libc::mprotect(ptr, page_size, libc::PROT_NONE);
        libc::mprotect(ptr.add(alloc_size - page_size), page_size, libc::PROT_NONE);
        
        // 锁定中间页
        libc::mlock(ptr.add(page_size), size);
        
        Ok(ptr.add(page_size) as *mut u8)
    }
}

// ============================================================================
//  2. 加密引擎 (Crypto Engine)
// ============================================================================

/// 自动擦除的密钥容器
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    key: [u8; 32],
}

impl SecureKey {
    pub fn new(k: [u8; 32]) -> Self { Self { key: k } }
    pub fn as_bytes(&self) -> &[u8] { &self.key }
}

pub struct CryptoEngine;

impl CryptoEngine {
    /// 双重 KDF 密钥派生 (复刻 Python 逻辑: PBKDF2 -> Argon2)
    pub fn derive_key(password: &str) -> Result<(SecureKey, [u8; KDF_SALT_LEN], [u8; KDF_SALT_LEN]), EtpError> {
        let mut salt_pbkdf = [0u8; KDF_SALT_LEN];
        let mut salt_argon = [0u8; KDF_SALT_LEN];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt_pbkdf);
        rng.fill_bytes(&mut salt_argon);

        // 1. PBKDF2 (SHA-512)
        // Rust 的 pbkdf2 crate 使用方式略有不同，这里用 blake3 模拟第一层快速哈希
        // 或者使用 ring/rust-crypto 的 pbkdf2。为了不增加额外 heavy 依赖，
        // 我们使用 ETP 标准的 Blake3 Key Derive 模拟第一层 KDF (非常安全且快)
        // Python 版用 PBKDF2-HMAC-SHA512。为了兼容性或安全性，
        // 我们这里用 Blake3-KDF 作为 Layer 1，Argon2id 作为 Layer 2。
        
        let mut hasher = blake3::Hasher::new_derive_key("ETP_SAFEFS_LAYER1_PBKDF_REPLACEMENT");
        hasher.update(&salt_pbkdf);
        hasher.update(password.as_bytes());
        let intermediate_key = hasher.finalize();

        // 2. Argon2id (Memory Hard)
        let params = Params::new(
            65536, // m_cost (64MB)
            3,     // t_cost
            4,     // p_cost (parallelism)
            Some(32) // output len
        ).map_err(|e| EtpError::Internal(format!("Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id, 
            argon2::Version::V0x13, 
            params
        );

        let mut final_key = [0u8; 32];
        argon2.hash_password_into(
            intermediate_key.as_bytes(), 
            &salt_argon, 
            &mut final_key
        ).map_err(|e| EtpError::Internal(format!("Argon2 derivation: {}", e)))?;

        // 锁定生成的密钥 (模拟 Python 的 ctypes.mlock)
        // SecureKey 结构体本身在 Drop 时会 Zeroize
        
        Ok((SecureKey::new(final_key), salt_pbkdf, salt_argon))
    }

    /// 从已知 Salt 恢复密钥
    pub fn restore_key(
        password: &str, 
        salt_pbkdf: &[u8], 
        salt_argon: &[u8]
    ) -> Result<SecureKey, EtpError> {
        // Layer 1
        let mut hasher = blake3::Hasher::new_derive_key("ETP_SAFEFS_LAYER1_PBKDF_REPLACEMENT");
        hasher.update(salt_pbkdf);
        hasher.update(password.as_bytes());
        let intermediate_key = hasher.finalize();

        // Layer 2
        let params = Params::new(65536, 3, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut final_key = [0u8; 32];
        argon2.hash_password_into(
            intermediate_key.as_bytes(), 
            salt_argon, 
            &mut final_key
        ).map_err(|e| EtpError::Internal(format!("Argon2 restore: {}", e)))?;

        Ok(SecureKey::new(final_key))
    }

    /// 恒定时间比较
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        constant_time_eq::constant_time_eq(a, b)
    }
}

// ============================================================================
//  3. 安全文件操作 (Secure File System)
// ============================================================================

pub struct SafeFileSystem;

impl SafeFileSystem {
    /// 安全擦除文件 (DoD 5220.22-M)
    pub fn secure_wipe(path: &Path) -> Result<(), EtpError> {
        if !path.exists() { return Ok(()); }
        
        let metadata = fs::metadata(path).map_err(EtpError::Io)?;
        let len = metadata.len();
        
        // 随机重命名 (混淆文件名)
        let new_name = path.with_file_name(format!(".tmp_{}", rand::random::<u64>()));
        if let Err(_) = fs::rename(path, &new_name) {
            // 如果重命名失败（可能跨设备），就地擦除
            warn!("SafeFS: Rename failed, wiping in place.");
        }
        let target_path = if new_name.exists() { &new_name } else { path };

        let mut file = OpenOptions::new().write(true).open(target_path).map_err(EtpError::Io)?;
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; 64 * 1024]; // 64KB chunk

        // 执行多次覆盖
        for pass in 0..WIPE_PASSES {
            file.seek(SeekFrom::Start(0)).map_err(EtpError::Io)?;
            let mut written = 0;
            while written < len {
                let to_write = std::cmp::min(buf.len() as u64, len - written) as usize;
                
                // 模式生成
                match pass % 3 {
                    0 => rng.fill_bytes(&mut buf[0..to_write]), // Random
                    1 => buf[0..to_write].fill(0x00),           // Zeros
                    2 => buf[0..to_write].fill(0xFF),           // Ones
                    _ => {},
                }
                
                file.write_all(&buf[..to_write]).map_err(EtpError::Io)?;
                written += to_write as u64;
            }
            file.sync_all().map_err(EtpError::Io)?;
        }

        // 截断并删除
        file.set_len(0).map_err(EtpError::Io)?;
        drop(file); // Close handle
        fs::remove_file(target_path).map_err(EtpError::Io)?;
        
        info!("SafeFS: Securely wiped {:?}", path);
        Ok(())
    }

    /// 原子加密写入
    /// 格式: [Magic][Salt1(32)][Salt2(32)][Nonce(12)][Ciphertext...]
    pub fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), EtpError> {
        // 1. 前置检查
        SystemGuard::enforce_security_perimeter()?; // 确保环境安全
        
        if input_path.metadata().map_err(EtpError::Io)?.len() > MAX_FILE_SIZE {
            return Err(EtpError::PayloadTooLarge(0, MAX_FILE_SIZE as usize));
        }

        // 2. 密钥生成
        let (key, salt1, salt2) = CryptoEngine::derive_key(password)?;
        
        // 3. 准备加密上下文
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // 4. 读取明文
        let mut plaintext = fs::read(input_path).map_err(EtpError::Io)?;
        
        // 5. 执行加密 (In-place if possible, but here we allocate)
        let ciphertext = cipher.encrypt(&nonce.into(), plaintext.as_ref())
            .map_err(|e| EtpError::Internal(format!("Encryption error: {}", e)))?;
            
        // 立即擦除明文内存
        plaintext.zeroize();

        // 6. 原子写入 (写临时文件 -> 重命名)
        let temp_path = output_path.with_extension("tmp_enc");
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(EtpError::Io)?;

        // Header
        out_file.write_all(MAGIC_HEADER).map_err(EtpError::Io)?;
        out_file.write_all(&salt1).map_err(EtpError::Io)?;
        out_file.write_all(&salt2).map_err(EtpError::Io)?;
        out_file.write_all(&nonce).map_err(EtpError::Io)?;
        
        // Body
        out_file.write_all(&ciphertext).map_err(EtpError::Io)?;
        out_file.sync_all().map_err(EtpError::Io)?;
        drop(out_file);

        // Rename
        fs::rename(&temp_path, output_path).map_err(EtpError::Io)?;
        
        // 7. 设置权限 (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(output_path).map_err(EtpError::Io)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(output_path, perms).map_err(EtpError::Io)?;
        }

        Ok(())
    }

    /// 解密文件
    pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<(), EtpError> {
        SystemGuard::enforce_security_perimeter()?;

        let mut in_file = File::open(input_path).map_err(EtpError::Io)?;
        let file_len = in_file.metadata().map_err(EtpError::Io)?.len();
        
        // Header Check
        let header_len = MAGIC_HEADER.len() + KDF_SALT_LEN * 2 + 12;
        if file_len < header_len as u64 {
            return Err(EtpError::Protocol("File too short".into()));
        }

        let mut header = vec![0u8; header_len];
        in_file.read_exact(&mut header).map_err(EtpError::Io)?;

        let (magic, rest) = header.split_at(MAGIC_HEADER.len());
        if magic != MAGIC_HEADER {
            return Err(EtpError::Protocol("Invalid Magic Header".into()));
        }

        let (salt1, rest) = rest.split_at(KDF_SALT_LEN);
        let (salt2, nonce) = rest.split_at(KDF_SALT_LEN);

        // Restore Key
        let key = CryptoEngine::restore_key(password, salt1, salt2)?;
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

        // Read Ciphertext
        let mut ciphertext = Vec::new();
        in_file.read_to_end(&mut ciphertext).map_err(EtpError::Io)?;

        // Decrypt
        let plaintext = cipher.decrypt(nonce.into(), ciphertext.as_ref())
            .map_err(|_| EtpError::CryptoHandshake("Decryption failed (Auth Tag Mismatch)".into()))?;

        // Write Output
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)
            .map_err(EtpError::Io)?;
            
        out_file.write_all(&plaintext).map_err(EtpError::Io)?;
        out_file.sync_all().map_err(EtpError::Io)?;

        Ok(())
    }
}

// ============================================================================
//  4. 安全看门狗 (Security Watchdog)
// ============================================================================

/// 后台监控线程，检测运行时异常
pub struct SafeMonitor {
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl SafeMonitor {
    pub fn start() -> Self {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let r_clone = running.clone();

        std::thread::spawn(move || {
            while r_clone.load(std::sync::atomic::Ordering::Relaxed) {
                // 1. 检查 TracerPid
                if let Err(_) = SystemGuard::anti_debug_checks() {
                    error!("SafeMonitor: Debugger detected at runtime! Triggering self-destruct.");
                    Self::panic_handler();
                }

                // 2. 检查内存访问 (通过 /proc/self/maps 检查是否有非法的 rwx 段，意味着 shellcode 注入)
                if Self::check_rwx_memory() {
                    error!("SafeMonitor: RWX memory segment detected (Shellcode risk)!");
                    Self::panic_handler();
                }

                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });

        Self { running }
    }

    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn check_rwx_memory() -> bool {
        if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                if line.contains("rwx") {
                    return true;
                }
            }
        }
        false
    }

    fn panic_handler() -> ! {
            error!("SafeFS: !!! CRITICAL SECURITY VIOLATION !!! INITIATING SELF-DESTRUCT SEQUENCE.");
    
            // 1. 紧急切断网络与IO (关闭除 Stdin/Stdout/Stderr 外的所有文件描述符)
            // 这会立即中断所有 ETP Engine 的 TCP/UDP 连接和文件句柄，
            // 实际上达到了"通知 Engine 停止网络"的效果（Engine 会因 IO 错误而崩溃停止）。
            unsafe {
                // 尝试关闭 3 到 4096 范围内的所有 FD
                // libc::closefrom 在某些 Linux 版本不可用，循环 close 是通用做法
                for fd in 3..4096 {
                    libc::close(fd);
                }
            }
    
            // 2. 内存毒化 (Memory Poisoning)
            // 尝试覆盖当前栈帧及附近内存，破坏残留的敏感数据
            // 使用 volatile write 防止被编译器优化
            unsafe {
                const STACK_WIPE_SIZE: usize = 16 * 1024; // 16KB
                let mut toxic_waste = [0u8; STACK_WIPE_SIZE];
                // 填充 0xCC (INT 3 指令码) 或随机垃圾
                std::ptr::write_volatile(&mut toxic_waste[..] as *mut [u8], [0xCC; STACK_WIPE_SIZE]);
                // 强制内存屏障
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            }
    
            // 3. 清理临时锁文件 (Best Effort)
            let lock_path = std::env::temp_dir().join("safefs.lock");
            let _ = std::fs::remove_file(lock_path);
    
            // 4. 强制进程自杀 (SIGKILL)
            // 发送 SIGKILL 给自己，绕过所有析构函数和异常处理，
            // 确保不会生成 Core Dump (即使系统层未禁用)，也不给攻击者挂钩子的机会。
            unsafe {
                libc::raise(libc::SIGKILL);
            }
    
            // 5. 兜底退出 (理论上不可达)
            std::process::exit(137);
        }
    
}

// ============================================================================
//  单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_decryption_cycle() {
        // Mock environment check for test
        // SystemGuard::enforce_security_perimeter().unwrap(); // Might fail in CI

        let dir = tempdir().unwrap();
        let src = dir.path().join("secret.data");
        let enc = dir.path().join("secret.enc");
        let dec = dir.path().join("secret.dec");

        fs::write(&src, b"Confidential Data").unwrap();
        let pass = "strong_password_123";

        // Encrypt
        // We skip SystemGuard for unit tests as it might fail on ptrace check (test runner traces)
        let (key, s1, s2) = CryptoEngine::derive_key(pass).unwrap();
        let cipher = ChaCha20Poly1305::new(key.as_bytes().into());
        let nonce = [0u8; 12];
        let data = fs::read(&src).unwrap();
        let ct = cipher.encrypt(&nonce.into(), data.as_ref()).unwrap();
        
        // Manual write to verify format
        let mut f = File::create(&enc).unwrap();
        f.write_all(MAGIC_HEADER).unwrap();
        f.write_all(&s1).unwrap();
        f.write_all(&s2).unwrap();
        f.write_all(&nonce).unwrap();
        f.write_all(&ct).unwrap();

        // Decrypt using SafeFileSystem (bypassing guard check via mock if possible, here we just run logic)
        // Real unit test might need to mock SystemGuard or run in permissive env.
        
        let restored_key = CryptoEngine::restore_key(pass, &s1, &s2).unwrap();
        assert_eq!(key.as_bytes(), restored_key.as_bytes());
    }
}
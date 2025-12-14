// etp-core/src/platform.rs

use std::env;
use std::path::PathBuf;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use log::{info, warn, debug, error};
use sysinfo::{System, SystemExt};

/// 操作系统类型定义
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsType {
    Linux,
    Windows,
    MacOS,
    Android,
    iOS,
    FreeBSD,
    OpenBSD,
    NetBSD,
    DragonFly,
    Illumos, // Solaris/SmartOS/OpenIndiana
    Unknown,
}

/// 电源状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerState {
    /// 接通电源 (AC)
    PluggedIn,
    /// 使用电池 (Battery)
    OnBattery,
    /// 明确的省电模式 (Battery Saver / Low Power Mode)
    PowerSaver,
    /// 未知
    Unknown,
}

/// 平台能力描述符
/// 该结构体会被序列化并提供给 Agent 和 Flavor，用于决策网络策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub os_type: OsType,
    pub has_admin_privileges: bool,
    pub supports_tun: bool,
    pub config_dir: PathBuf,
    
    /// 当前电源状态
    pub power_state: PowerState,
    
    /// 推荐的心跳间隔 (毫秒)
    /// 依据电源状态动态计算：接电时快，省电时慢
    pub recommended_heartbeat_ms: u64,
}

impl PlatformCapabilities {
    /// 深度探测当前环境能力
    pub fn probe() -> Self {
        let os_type = Self::detect_os();
        let has_admin = Self::check_admin_privileges();
        
        // TUN 支持判定
        // 通常需要 Root/Admin 权限，并且内核支持
        // Android 非 Root 环境通常通过 VpnService (Java) 而非原生 TUN 设备
        let supports_tun = has_admin && matches!(
            os_type, 
            OsType::Linux | OsType::Windows | OsType::MacOS | OsType::FreeBSD | OsType::OpenBSD
        );

        // 使用 dirs crate 获取标准配置路径
        let config_dir = dirs::config_dir()
            .map(|p| p.join("etp-core"))
            .unwrap_or_else(|| Self::fallback_config_dir(os_type));

        // 探测电源状态
        let power_state = Self::detect_power_state();
        
        // 计算推荐心跳
        let recommended_heartbeat_ms = match power_state {
            PowerState::PluggedIn => 25,      // 高性能: 25ms (40Hz)
            PowerState::OnBattery => 100,     // 均衡: 100ms (10Hz)
            PowerState::PowerSaver => 500,    // 省电: 500ms (2Hz) - 大幅减少唤醒
            PowerState::Unknown => 50,        // 默认
        };

        let caps = Self {
            os_type,
            has_admin_privileges: has_admin,
            supports_tun,
            config_dir,
            power_state,
            recommended_heartbeat_ms,
        };

        info!("Platform Probe: OS={:?}, Power={:?}, Heartbeat={}ms", 
            caps.os_type, caps.power_state, caps.recommended_heartbeat_ms);
        
        caps
    }

    /// 操作系统探测
    fn detect_os() -> OsType {
        // 使用条件编译宏进行静态判断
        #[cfg(target_os = "linux")]
        {
            // 运行时区分 Android
            // Android 通常有特定的环境变量或文件结构
            if std::path::Path::new("/system/bin/app_process").exists() || env::var("TERMUX_VERSION").is_ok() {
                return OsType::Android;
            }
            return OsType::Linux;
        }
        
        #[cfg(target_os = "windows")] return OsType::Windows;
        #[cfg(target_os = "macos")] return OsType::MacOS;
        #[cfg(target_os = "ios")] return OsType::iOS;
        #[cfg(target_os = "freebsd")] return OsType::FreeBSD;
        #[cfg(target_os = "openbsd")] return OsType::OpenBSD;
        #[cfg(target_os = "netbsd")] return OsType::NetBSD;
        #[cfg(target_os = "dragonfly")] return OsType::DragonFly;
        #[cfg(target_os = "illumos")] return OsType::Illumos;
        #[cfg(target_os = "solaris")] return OsType::Illumos;

        #[allow(unreachable_code)]
        OsType::Unknown
    }

    /// 管理员权限探测
    fn check_admin_privileges() -> bool {
        #[cfg(unix)]
        unsafe {
            // geteuid() == 0 即为 Root
            libc::geteuid() == 0
        }

        #[cfg(windows)]
        {
            use winapi::um::shell32::IsUserAnAdmin;
            unsafe {
                // 返回非零表示是管理员
                IsUserAnAdmin() != 0
            }
        }

        #[cfg(not(any(unix, windows)))]
        false
    }

    /// 路径回落策略 (当 dirs crate 失败时)
    fn fallback_config_dir(os: OsType) -> PathBuf {
        match os {
            OsType::Windows => PathBuf::from(r"C:\ProgramData\ETP"),
            OsType::Android => PathBuf::from("/data/local/tmp/etp"),
            _ => PathBuf::from("/etc/etp"),
        }
    }

    /// 电源状态深度探测
    fn detect_power_state() -> PowerState {
        #[cfg(target_os = "windows")]
        {
            return Self::detect_windows_power();
        }

        #[cfg(target_os = "linux")]
        {
            return Self::detect_linux_power();
        }
        
        #[cfg(target_os = "android")]
        {
            return Self::detect_linux_power(); // Android 内核基于 Linux，sysfs 结构类似
        }

        #[cfg(target_os = "macos")]
        {
            return Self::detect_macos_power();
        }

        // 其他系统暂不支持，默认未知
        PowerState::Unknown
    }

    // --- Windows Power Implementation ---
    #[cfg(target_os = "windows")]
    fn detect_windows_power() -> PowerState {
        use winapi::um::winbase::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        
        unsafe {
            let mut status: SYSTEM_POWER_STATUS = std::mem::zeroed();
            if GetSystemPowerStatus(&mut status) != 0 {
                // ACLineStatus: 0 = Battery, 1 = AC, 255 = Unknown
                let ac_status = status.ACLineStatus;
                // SystemStatusFlag: 0 = Off, 1 = On (Battery Saver)
                let saver_flag = status.SystemStatusFlag; 

                if saver_flag == 1 {
                    return PowerState::PowerSaver;
                }
                
                if ac_status == 1 {
                    return PowerState::PluggedIn;
                } else if ac_status == 0 {
                    return PowerState::OnBattery;
                }
            }
        }
        PowerState::Unknown
    }

    // --- Linux/Android Power Implementation (sysfs) ---
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn detect_linux_power() -> PowerState {
        use std::fs;
        // 遍历 /sys/class/power_supply/*/status
        // 状态通常为: "Discharging", "Charging", "Full", "Not charging", "Unknown"
        
        let supply_path = "/sys/class/power_supply";
        if let Ok(entries) = fs::read_dir(supply_path) {
            for entry in entries.flatten() {
                let status_path = entry.path().join("status");
                let type_path = entry.path().join("type"); // Optional check

                if status_path.exists() {
                    if let Ok(content) = fs::read_to_string(&status_path) {
                        let status = content.trim();
                        if status == "Discharging" {
                            // 进一步检查电量，如果极低则视为 PowerSaver
                            let cap_path = entry.path().join("capacity");
                            if let Ok(cap_str) = fs::read_to_string(cap_path) {
                                if let Ok(cap) = cap_str.trim().parse::<u8>() {
                                    if cap < 15 {
                                        return PowerState::PowerSaver;
                                    }
                                }
                            }
                            return PowerState::OnBattery;
                        }
                        if status == "Charging" || status == "Full" {
                            return PowerState::PluggedIn;
                        }
                    }
                }
            }
        }
        // 如果没有找到电池信息，通常对于服务器或台式机，假设接通电源
        // 但对于移动库，Unknown 更安全
        PowerState::Unknown 
    }

    // --- MacOS Power Implementation (CLI Fallback) ---
    #[cfg(target_os = "macos")]
    fn detect_macos_power() -> PowerState {
        use std::process::Command;
        // 使用 pmset -g batt
        // 输出示例: "Now drawing from 'AC Power'" 或 "Now drawing from 'Battery Power'"
        
        if let Ok(output) = Command::new("pmset").arg("-g").arg("batt").output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if out_str.contains("'Battery Power'") {
                // 检查是否开启低电量模式 (Low Power Mode) - macOS 12+
                // 需要解析 pmset -g therm 或 system_profiler，这里简化处理
                return PowerState::OnBattery;
            } else if out_str.contains("'AC Power'") {
                return PowerState::PluggedIn;
            }
        }
        PowerState::Unknown
    }
}
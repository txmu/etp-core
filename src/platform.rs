// etp-core/src/platform.rs

use std::env;
use sysinfo::{System, SystemExt};
use log::{info, warn};

#[derive(Debug, Clone, Copy)]
pub enum OsType {
    Linux,
    Windows,
    MacOS,
    Android,
    Unknown,
}

/// 平台能力描述符
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    pub os_type: OsType,
    pub has_admin_privileges: bool,
    pub supports_tun: bool,
    pub battery_saver_enabled: bool, // 针对移动端，可能需要降低心跳频率
}

impl PlatformCapabilities {
    /// 探测当前环境能力
    pub fn probe() -> Self {
        let os_type = Self::detect_os();
        let has_admin = Self::check_admin_privileges();
        let supports_tun = has_admin && (matches!(os_type, OsType::Linux | OsType::Windows | OsType::MacOS));
        
        // 简单检测是否在 Termux 环境 (Android)
        let is_termux = env::var("TERMUX_VERSION").is_ok();
        let effective_os = if is_termux { OsType::Android } else { os_type };

        let caps = Self {
            os_type: effective_os,
            has_admin_privileges: has_admin,
            supports_tun, // 如果是 Termux 且没有 Root，通常不支持标准 TUN
            battery_saver_enabled: false, // 暂未实现深度检测
        };

        info!("Platform Probe: {:?}", caps);
        if !caps.supports_tun {
            warn!("TUN device creation not supported or insufficient privileges. VPN flavor will be disabled.");
        }

        caps
    }

    fn detect_os() -> OsType {
        #[cfg(target_os = "linux")]
        return OsType::Linux;
        #[cfg(target_os = "windows")]
        return OsType::Windows;
        #[cfg(target_os = "macos")]
        return OsType::MacOS;
        #[cfg(target_os = "android")]
        return OsType::Android;
        #[allow(unreachable_code)]
        OsType::Unknown
    }

    fn check_admin_privileges() -> bool {
        #[cfg(unix)]
        unsafe {
            // 检查 euid 是否为 0 (Root)
            libc::geteuid() == 0
        }
        #[cfg(windows)]
        {
            // Windows 简单检查是否能打开 SC_MANAGER
            // 这是一个近似检查，实际可能需要更复杂的 Token 判断
            // 这里为了不引入过多 winapi 依赖，暂且假设 Release 构建在 Admin 下运行
            // 或者通过尝试执行特权操作来判断
            true // MVP 假设有权限，实际应完善
        }
        #[cfg(not(any(unix, windows)))]
        false
    }
}
// src/eui/auto_layout.rs

use std::env;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use log::{info, debug};

use crate::network::node::EtpHandle;
use super::facade::EuiManager;
use super::backend::UiBackendType;

pub struct AutoLayoutEngine;

impl AutoLayoutEngine {
    /// 自动探测并启动最佳 UI 体验
    pub async fn launch_best_fit(handle: EtpHandle, web_token: &str) -> Result<()> {
        let manager = EuiManager::new(handle);
        let backend = Self::detect_environment();
        
        info!("AutoLayout: Detected optimal environment. Backend selected: {:?}", backend);
        
        // --- WebBridge 自动化集成逻辑 ---
        if backend == UiBackendType::WebBridge {
            // 1. 确定元数据存放路径 (跨平台安全位置)
            // 优先使用 OS 级别的 Runtime Dir (如 Linux 的 /run/user/UID)，其次是 Config Dir
            let bridge_info_path = dirs::runtime_dir()
                .or_else(|| dirs::config_dir())
                .map(|p| p.join("etp-core").join("web_bridge.json"))
                .ok_or_else(|| anyhow!("Could not determine secure path for bridge metadata"))?;

            // 2. 构造连接描述符
            let metadata = serde_json::json!({
                "provider": "ETP-CORE-EUI",
                "version": crate::eui::EUI_VERSION,
                "ws_url": "ws://127.0.0.1:10101",
                "access_token": web_token,
                "pid": std::process::id(),
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });

            // 3. 确保父目录存在
            if let Some(parent) = bridge_info_path.parent() {
                std::fs::create_dir_all(parent).context("Failed to create EUI metadata directory")?;
            }

            // 4. 原子化写入并设置权限 (严格 0600)
            // 防止系统其他非特权用户读取到 access_token
            let content = serde_json::to_string_pretty(&metadata)?;
            
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                use std::fs::OpenOptions;
                use std::io::Write;

                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&bridge_info_path)
                    .context("Failed to open bridge metadata file")?;
                
                // 仅当前用户可读写 (Read/Write only by owner)
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                file.write_all(content.as_bytes())?;
            }

            #[cfg(not(unix))]
            {
                // Windows 环境下直接写入，依赖 NTFS 默认权限
                std::fs::write(&bridge_info_path, content)?;
            }

            info!("AutoLayout: Bridge credentials persisted to {:?}", bridge_info_path);
            debug!("AutoLayout: External UI (Tauri/Electron) can now auto-authenticate.");
        }
        
        manager.launch(backend).await
    }

    /// 环境嗅探逻辑：蓝图手段集成
    fn detect_environment() -> UiBackendType {
        // 1. 检查是否拥有图形显示器环境 (Unix/Linux/macOS)
        let has_display = env::var("DISPLAY").is_ok() || env::var("WAYLAND_DISPLAY").is_ok();
        
        // 2. 检查操作系统 (Windows 始终有 GUI 潜力)
        let is_windows = cfg!(target_os = "windows");

        if has_display || is_windows {
            // 优先选择 Slint，因为它具有最好的跨平台硬件加速表现
            #[cfg(feature = "eui-gui-slint")]
            return UiBackendType::GuiSlint;

            // 备选 GTK
            #[cfg(feature = "eui-gui-gtk")]
            return UiBackendType::GuiGtk;
        }

        // 3. 检查是否在交互式 TTY 环境中 (SSH/Console)
        let is_tty = atty::is(atty::Stream::Stdout);

        if is_tty {
            // 优先选择 ncurses 仪表盘
            #[cfg(feature = "eui-tui-ncurses")]
            return UiBackendType::TuiNcurses;

            // 备选简单 CLI
            #[cfg(feature = "eui-cli")]
            return UiBackendType::Cli;
        }

        // 4. 兜底方案：如果既没有显示器也不是 TTY (如后台 Service)
        // 则启动 Web 桥接器，允许用户从远程浏览器连接监控
        #[cfg(feature = "eui-gui-tauri")]
        return UiBackendType::WebBridge;

        // 终极 fallback，如果特性全关，则抛出逻辑错误（由外部 launch 处理）
        #[cfg(feature = "eui-cli")]
        return UiBackendType::Cli;
        
        // 编译期防御：确保至少有一个后端被选中
        panic!("EUI: No suitable backend enabled in features!");
    }
}
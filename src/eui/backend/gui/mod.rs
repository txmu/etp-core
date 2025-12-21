// src/eui/backend/gui/mod.rs

use std::sync::Arc;
use anyhow::{Result, anyhow};
use crate::network::node::EtpHandle;
use super::state::NodeSummary;
use super::backend::EuiBackend;

// --- 按特性条件加载子模块 ---

#[cfg(feature = "eui-gui-slint")]
pub mod slint;

#[cfg(feature = "eui-gui-gtk")]
pub mod gtk;

#[cfg(feature = "eui-gui-qt")]
pub mod qt;

#[cfg(feature = "eui-gui-fltk")]
pub mod fltk;

#[cfg(feature = "eui-gui-wx")]
pub mod wx;

#[cfg(feature = "eui-gui-tk")]
pub mod tk;

#[cfg(feature = "eui-gui-druid")]
pub mod druid;

/// GUI 终极工厂：根据编译优先级选择最佳原生体验
/// 优先级逻辑：
/// 1. Slint (旗舰级，硬件加速)
/// 2. Druid (Rust 原生数据驱动)
/// 3. Qt (桌面标准)
/// 4. GTK (Linux 首选)
/// 5. wxWidgets (系统原生)
/// 6. FLTK (极致轻量)
/// 7. Tk (最后保底)
pub fn create_best_gui() -> Result<Arc<dyn EuiBackend>> {
    #[cfg(feature = "eui-gui-slint")]
    { return Ok(Arc::new(self::slint::SlintBackend::new())); }

    #[cfg(feature = "eui-gui-druid")]
    { return Ok(Arc::new(self::druid::DruidBackend::new())); }

    #[cfg(feature = "eui-gui-qt")]
    { return Ok(Arc::new(self::qt::QtBackend::new())); }

    #[cfg(feature = "eui-gui-gtk")]
    { return Ok(Arc::new(self::gtk::GtkBackend::new())); }

    #[cfg(feature = "eui-gui-wx")]
    { return Ok(Arc::new(self::wx::WxBackend::new())); }

    #[cfg(feature = "eui-gui-fltk")]
    { return Ok(Arc::new(self::fltk::FltkBackend::new())); }

    #[cfg(feature = "eui-gui-tk")]
    { return Ok(Arc::new(self::tk::TkBackend::new())); }

    Err(anyhow!("No EUI-GUI features enabled. Please check your Cargo features."))
}
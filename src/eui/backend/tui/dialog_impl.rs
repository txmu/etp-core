// src/eui/backend/tui/dialog_impl.rs

#![cfg(feature = "eui-tui-dialog")]

use dialog::{Dialog, Input, Menu, Checklist};
use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use log::{info, warn};

use crate::network::node::{EtpHandle, NodeConfig};
use crate::eui::bridge::BackendBridgeExt;
use crate::eui::EuiCommand;
use crate::crypto::noise::KeyPair;

pub struct DialogInterface;

impl DialogInterface {
    /// 启动全自动配置向导
    /// 返回一个配置好的 NodeConfig，或者在用户取消时返回 Err
    pub fn run_setup_wizard() -> Result<NodeConfig> {
        let mut config = NodeConfig::default();

        // 1. 欢迎界面
        Dialog::new()
            .title("ETP-CORE // DEPLOYMENT WIZARD")
            .content("Welcome to the Evolutionary Transport Protocol setup.\n\nThis wizard will configure your node's identity and security parameters.")
            .show()?;

        // 2. 绑定地址设置
        let bind_addr: String = Input::new()
            .title("Network Interface")
            .content("Enter local bind address (e.g., 0.0.0.0:4433):")
            .default("0.0.0.0:4433")
            .show()?
            .ok_or_else(|| anyhow!("User cancelled bind configuration"))?;
        
        let _: SocketAddr = bind_addr.parse().map_err(|_| anyhow!("Invalid socket address format"))?;
        config.bind_addr = bind_addr;

        // 3. 身份管理菜单
        let id_choice = Menu::new("Identity Management")
            .item("generate", "Generate new cryptographic identity (Recommended)")
            .item("load", "Load existing identity from disk")
            .show()?;

        match id_choice {
            Some(ref s) if s == "generate" => {
                config.keypair = KeyPair::generate();
                Dialog::new().title("Success").content("New Ed25519/X25519 identity generated.").show()?;
            }
            _ => return Err(anyhow!("Identity loading not implemented in wizard")),
        }

        // 4. 业务功能 (Flavors) 选择
        let flavors = Checklist::new("Component Selection")
            .item("vpn", "VPN Tunneling (L3 Bridge)", true)
            .item("darknews", "Distributed Newsgroup (NNTP)", false)
            .item("chat", "E2EE Chat Service", true)
            .item("ipfs", "IPFS P2P Fusion", false)
            .show()?;
        
        // 此处逻辑会根据勾选结果动态调整 config.default_flavor (简化的策略映射)
        if flavors.contains(&"vpn".to_string()) {
             config.default_flavor = "etp.flavor.vpn.v1".to_string();
        }

        // 5. 安全强度确认
        let profile_choice = Menu::new("Security Profile")
            .item("turbo", "Turbo (High throughput, low obfuscation)")
            .item("balanced", "Balanced (Standard Jitter)")
            .item("paranoid", "Paranoid (Constant Bitrate, High Cover Traffic)")
            .show()?;

        info!("Wizard: Configuration finalized for node binding {}", config.bind_addr);
        Ok(config)
    }

    /// 确认危险操作：停机
    pub fn confirm_shutdown(handle: &EtpHandle) -> Result<bool> {
        let confirmed = Dialog::new()
            .title("!!! SECURITY ALERT !!!")
            .content("You are about to SHUTDOWN this node.\n\nAll active encrypted sessions and anonymous relays will be terminated. Proceed?")
            .show()?;

        if confirmed {
            let h = handle.clone();
            tokio::spawn(async move {
                let _ = h.bridge().dispatch(EuiCommand::ShutdownNode).await;
            });
        }
        Ok(confirmed)
    }
}
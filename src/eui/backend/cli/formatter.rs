// src/eui/backend/cli/formatter.rs

#![cfg(feature = "eui-cli")]

use crate::eui::state::{NodeSummary, SessionBrief, RssItem};
use colored::*;
use std::fmt::Write;

pub struct CliFormatter;

impl CliFormatter {
    /// 渲染完整监控仪表盘
    pub fn format_dashboard(snapshot: &NodeSummary) -> String {
        let mut out = String::new();

        // 1. 标题头
        writeln!(out, "{}", "=== ETP-CORE EVOLUTIONARY MONITOR ===".bold().bright_cyan()).unwrap();
        writeln!(out, "{:<15} : {} | {:<15} : {}", 
            "Node ID", snapshot.node_id_hex.yellow(),
            "Version", snapshot.version.green()
        ).unwrap();
        writeln!(out, "{:<15} : {}s", "Uptime", snapshot.uptime_secs.to_string().white()).unwrap();
        writeln!(out, "{}", "------------------------------------------------------------".dimmed()).unwrap();

        // 2. 核心网络指标
        writeln!(out, "{}", "[NETWORK DATA]".bold().bright_white()).unwrap();
        writeln!(out, "  {:<10} : {:<15} | {:<10} : {}", 
            "BPS IN", Self::format_bps(snapshot.bps_in).bright_green(),
            "TOTAL IN", Self::format_bytes(snapshot.total_bytes_in).dimmed()
        ).unwrap();
        writeln!(out, "  {:<10} : {:<15} | {:<10} : {}", 
            "BPS OUT", Self::format_bps(snapshot.bps_out).bright_blue(),
            "TOTAL OUT", Self::format_bytes(snapshot.total_bytes_out).dimmed()
        ).unwrap();
        writeln!(out, "  {:<10} : {}", 
            "COVERAGE", Self::format_bytes(snapshot.total_cover_bytes).magenta()
        ).unwrap();

        // 3. 安全统计 (异常指标显示红色)
        let acl_color = if snapshot.acl_drops > 0 { "red" } else { "white" };
        let fail_color = if snapshot.handshake_failed > 0 { "red" } else { "white" };

        writeln!(out, "\n{}", "[SECURITY & HEALTH]".bold().bright_white()).unwrap();
        writeln!(out, "  {:<12} : {:<10} | {:<12} : {}", 
            "HS SUCCESS", snapshot.handshake_success.to_string().green(),
            "HS FAILED", snapshot.handshake_failed.to_string().color(fail_color)
        ).unwrap();
        writeln!(out, "  {:<12} : {:<10} | {:<12} : {:.2}%", 
            "ACL DROPS", snapshot.acl_drops.to_string().color(acl_color),
            "LOSS RATE", snapshot.packet_loss_rate * 100.0
        ).unwrap();

        // 4. 活跃会话列表
        writeln!(out, "\n{} (Total: {})", "[ACTIVE SESSIONS]".bold().bright_white(), snapshot.active_sessions_count).unwrap();
        if snapshot.sessions.is_empty() {
            writeln!(out, "  {}", "No active connections.".dimmed()).unwrap();
        } else {
            writeln!(out, "  {:<16} | {:<20} | {:<8} | {}", "Identity", "Address", "RTT", "Flavor").unwrap();
            for s in snapshot.sessions.iter().take(5) { // 仅展示前 5 个
                writeln!(out, "  {:<16} | {:<20} | {:<8} | {}", 
                    s.peer_identity.yellow(),
                    s.socket_addr.dimmed(),
                    format!("{}ms", s.rtt_ms).cyan(),
                    s.flavor.blue()
                ).unwrap();
            }
        }

        // 5. RSS 情报流 (手段 18 扩展)
        #[cfg(feature = "eui-rss")]
        {
            writeln!(out, "\n{}", "[LATEST INTELLIGENCE (RSS)]".bold().bright_white()).unwrap();
            if snapshot.rss_feeds.is_empty() {
                writeln!(out, "  {}", "Waiting for feed aggregation...".dimmed()).unwrap();
            } else {
                for item in snapshot.rss_feeds.iter().take(3) {
                    writeln!(out, "  • [{}] {}", item.source_name.green(), item.title.bold()).unwrap();
                }
            }
        }

        out
    }

    /// 辅助：格式化字节速率
    fn format_bps(bps: u64) -> String {
        let kbps = bps as f64 / 1024.0;
        if kbps > 1024.0 {
            format!("{:.2} MB/s", kbps / 1024.0)
        } else {
            format!("{:.2} KB/s", kbps)
        }
    }

    /// 辅助：格式化总量
    fn format_bytes(bytes: u64) -> String {
        let mb = bytes as f64 / (1024.0 * 1024.0);
        if mb > 1024.0 {
            format!("{:.2} GB", mb / 1024.0)
        } else {
            format!("{:.2} MB", mb)
        }
    }
}
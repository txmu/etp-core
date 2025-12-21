// src/eui/backend/cli/mod.rs

pub mod formatter;

use std::sync::Arc;
use std::io::{self, Write};
use anyhow::Result;
use parking_lot::RwLock;
use getopts::Options;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use self::formatter::CliFormatter;

/// CLI 后端实现
pub struct CliBackend {
    /// 缓存最新的快照以便刷新循环使用
    current_snapshot: Arc<RwLock<NodeSummary>>,
    /// 停止信号
    should_exit: Arc<RwLock<bool>>,
}

impl CliBackend {
    pub fn new() -> Self {
        Self {
            current_snapshot: Arc::new(RwLock::new(NodeSummary::default())),
            should_exit: Arc::new(RwLock::new(false)),
        }
    }

    /// 辅助：清屏指令 (兼容 Windows 和 Unix)
    fn clear_screen(&self) {
        if cfg!(unix) {
            print!("{}[2J{}[1;1H", 27 as char, 27 as char);
        } else {
            // Windows 兼容性回退
            let _ = std::process::Command::new("cmd").args(&["/c", "cls"]).status();
        }
    }
}

impl EuiBackend for CliBackend {
    fn name(&self) -> &'static str {
        "Standard-CLI"
    }

    fn init(&self) -> Result<()> {
        // CLI 不需要特殊硬件初始化，检查终端标准输出是否可用
        if !atty::is(atty::Stream::Stdout) {
            log::warn!("CLI: Not a TTY, output might be garbled.");
        }
        Ok(())
    }

    fn run(&self, _handle: EtpHandle, initial_state: NodeSummary) -> Result<()> {
        // 1. 解析初始命令行参数 (虽然 Facade 已经调用了启动，但此处可处理 REPL 命令)
        let args: Vec<String> = std::env::args().collect();
        let mut opts = Options::new();
        opts.optflag("o", "once", "Print status once and exit");
        opts.optflag("h", "help", "Print this help menu");

        let matches = match opts.parse(&args[1..]) {
            Ok(m) => m,
            Err(f) => return Err(anyhow::anyhow!(f.to_string())),
        };

        if matches.opt_present("h") {
            println!("{}", opts.usage("Usage: etp [options]"));
            return Ok(());
        }

        // 2. 更新初始状态
        *self.current_snapshot.write() = initial_state;

        // 3. 判断运行模式
        if matches.opt_present("o") {
            // 单次打印模式 (适合脚本调用)
            let snap = self.current_snapshot.read();
            println!("{}", CliFormatter::format_dashboard(&snap));
            return Ok(());
        }

        // 4. 进入交互式刷新循环 (Top-like mode)
        info!("CLI: Entering interactive monitor mode (Press Ctrl+C to exit)");
        
        while !*self.should_exit.read() {
            self.clear_screen();
            
            // 获取最新快照并渲染
            let snap = self.current_snapshot.read();
            let dashboard = CliFormatter::format_dashboard(&snap);
            print!("{}", dashboard);
            
            // 提示栏
            println!("\n{}", ">> Controls: [Q] Quit | [R] Manual Rekey | [D] Disconnect All".dimmed());
            io::stdout().flush()?;

            // 500ms 刷新率，匹配 Facade 的推送频率
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        // 接收来自 Facade 的推送，更新本地缓存
        let mut guard = self.current_snapshot.write();
        *guard = snapshot;
    }

    fn shutdown(&self) {
        *self.should_exit.write() = true;
        println!("{}", "\nETP CLI Monitor Detached.".bright_red());
    }
}
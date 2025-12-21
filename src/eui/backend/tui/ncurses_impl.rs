// src/eui/backend/tui/ncurses_impl.rs

#![cfg(feature = "eui-tui-ncurses")]

use std::sync::Arc;
use ncurses::*;
use anyhow::Result;
use parking_lot::RwLock;

use crate::network::node::EtpHandle;
use crate::eui::state::NodeSummary;
use crate::eui::backend::EuiBackend;
use super::widgets::TuiWidgets;

pub struct NcursesBackend {
    snapshot: Arc<RwLock<NodeSummary>>,
    should_exit: Arc<RwLock<bool>>,
}

impl NcursesBackend {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(NodeSummary::default())),
            should_exit: Arc::new(RwLock::new(false)),
        }
    }

    fn init_colors() {
        start_color();
        init_pair(1, COLOR_CYAN, COLOR_BLACK);   // Header
        init_pair(2, COLOR_GREEN, COLOR_BLACK);  // Inbound
        init_pair(3, COLOR_BLUE, COLOR_BLACK);   // Outbound
        init_pair(4, COLOR_RED, COLOR_BLACK);    // Errors
        init_pair(5, COLOR_YELLOW, COLOR_BLACK); // Peer IDs
    }

    fn draw_layout(&self, snap: &NodeSummary) {
        let mut max_y = 0;
        let mut max_x = 0;
        getmaxyx(stdscr(), &mut max_y, &mut max_x);

        // 1. Header
        attron(COLOR_PAIR(1) | A_BOLD());
        mvaddstr(0, 1, &format!(" ETP-CORE NODE: {} | Uptime: {}s ", snap.node_id_hex, snap.uptime_secs));
        attroff(COLOR_PAIR(1) | A_BOLD());

        // 2. Traffic Sparklines (下行绿色，上行蓝色)
        let graph_width = (max_x / 2 - 4).max(10) as usize;
        let in_data: Vec<u64> = snap.traffic_history.iter().map(|p| p.bytes_in).collect();
        let out_data: Vec<u64> = snap.traffic_history.iter().map(|p| p.bytes_out).collect();

        let in_graph = TuiWidgets::draw_sparkline(&in_data, graph_width, 5);
        let out_graph = TuiWidgets::draw_sparkline(&out_data, graph_width, 5);

        for (i, line) in in_graph.iter().enumerate() {
            attron(COLOR_PAIR(2));
            mvaddstr(2 + i as i32, 2, line);
            attroff(COLOR_PAIR(2));
        }
        mvaddstr(7, 2, &format!("IN: {}/s", TuiWidgets::human_readable_size(snap.bps_in)));

        for (i, line) in out_graph.iter().enumerate() {
            attron(COLOR_PAIR(3));
            mvaddstr(2 + i as i32, (max_x / 2) + 2, line);
            attroff(COLOR_PAIR(3));
        }
        mvaddstr(7, (max_x / 2) + 2, &format!("OUT: {}/s", TuiWidgets::human_readable_size(snap.bps_out)));

        // 3. Session List
        mvaddstr(9, 1, "--- ACTIVE SESSIONS ---");
        attron(A_DIM());
        mvaddstr(10, 1, &format!("{:<16} | {:<18} | {:<8} | {}", "Peer", "Address", "RTT", "Flavor"));
        attroff(A_DIM());
        
        for (i, s) in snap.sessions.iter().take((max_y - 12) as usize).enumerate() {
            let y = 11 + i as i32;
            attron(COLOR_PAIR(5));
            mvaddstr(y, 1, &s.peer_identity);
            attroff(COLOR_PAIR(5));
            mvaddstr(y, 19, &format!("| {:<18} | {:<8} | {}", s.socket_addr, format!("{}ms", s.rtt_ms), s.flavor));
        }

        // 4. Footer
        mvaddstr(max_y - 1, 0, "[Q] Quit | [R] Rekey | [F] Flavors | [D] DHT");
        refresh();
    }
}

impl EuiBackend for NcursesBackend {
    fn name(&self) -> &'static str { "ncurses-dashboard" }

    fn init(&self) -> Result<()> {
        setlocale(LcCategory::all, ""); // 必须设置，否则 Unicode 乱码
        initscr();
        raw();
        keypad(stdscr(), true);
        noecho();
        curs_set(CURSOR_VISIBILITY::CURSOR_INVISIBLE);
        timeout(100); // 非阻塞读取输入
        Self::init_colors();
        Ok(())
    }

    fn run(&self, _handle: EtpHandle, initial_state: NodeSummary) -> Result<()> {
        *self.snapshot.write() = initial_state;
        
        while !*self.should_exit.read() {
            let snap = self.snapshot.read().clone();
            erase();
            self.draw_layout(&snap);
            
            let ch = getch();
            if ch == 'q' as i32 { break; }
            // 后续可在此处理 handle.bridge().dispatch(...)
        }
        Ok(())
    }

    fn update(&self, snapshot: NodeSummary) {
        *self.snapshot.write() = snapshot;
    }

    fn shutdown(&self) {
        *self.should_exit.write() = true;
        endwin();
    }
}
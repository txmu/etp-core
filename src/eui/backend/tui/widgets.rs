// src/eui/backend/tui/widgets.rs

use std::cmp;

pub struct TuiWidgets;

impl TuiWidgets {
    /// 绘制 Sparkline 字符示波器
    /// 使用 Unicode 块元素:  ▂▃▄▅▆▇█
    pub fn draw_sparkline(data: &[u64], width: usize, height: usize) -> Vec<String> {
        if data.is_empty() || width == 0 || height == 0 {
            return vec![String::new()];
        }

        let blocks = [' ', ' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let mut lines = vec![String::with_capacity(width); height];
        
        // 截取最后 width 个数据点
        let window = if data.len() > width {
            &data[data.len() - width..]
        } else {
            data
        };

        let max_val = *window.iter().max().unwrap_or(&1).max(&1);

        for &val in window {
            // 计算每个点在垂直方向上的高度（以 1/8 块为单位）
            let total_eighths = (val as f64 / max_val as f64 * (height * 8) as f64) as usize;
            
            for h in 0..height {
                let current_row_eighths = total_eighths.saturating_sub((height - 1 - h) * 8);
                let block_idx = cmp::min(current_row_eighths, 8);
                lines[h].push(blocks[block_idx]);
            }
        }
        
        // 补齐宽度
        for line in &mut lines {
            while line.chars().count() < width {
                line.insert(0, ' ');
            }
        }

        lines
    }

    /// 格式化单位
    pub fn human_readable_size(bytes: u64) -> String {
        const UNIT: f64 = 1024.0;
        if bytes < UNIT as u64 { return format!("{} B", bytes); }
        let exp = (bytes as f64).ln() / UNIT.ln();
        let pre = "KMGTPE".chars().nth(exp as usize - 1).unwrap();
        format!("{:.1} {}B", bytes as f64 / UNIT.powi(exp as i32), pre)
    }
}
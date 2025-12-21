// src/eui/backend/gui/fltk/theme.rs

use fltk::enums::{Color, Font, FrameType};
use fltk::app;

pub struct EuiTheme;

impl EuiTheme {
    // 调色盘定义
    pub const BG_MAIN: Color = Color::from_hex(0x1a1b26);
    pub const BG_CARD: Color = Color::from_hex(0x161925);
    pub const ACCENT: Color = Color::from_hex(0x7aa2f7);
    pub const GREEN: Color = Color::from_hex(0x9ece6a);
    pub const BLUE: Color = Color::from_hex(0x7dcfff);
    pub const TEXT_DIM: Color = Color::from_hex(0x565f89);
    pub const TEXT_MAIN: Color = Color::from_hex(0xc0caf5);

    /// 应用全局样式
    pub fn apply() {
        app::set_background_color(26, 27, 38);
        app::set_foreground_color(192, 202, 245);
        app::set_visible_focus(false);
        app::set_frame_type(FrameType::FlatBox);
        app::set_font(Font::Helvetica);
        
        // 设置默认输入框和滚动条颜色
        app::set_color(Color::Selection, 0x3d59a1);
    }
}
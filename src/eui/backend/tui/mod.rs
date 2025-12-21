// src/eui/backend/tui/mod.rs

pub mod widgets;

#[cfg(feature = "eui-tui-ncurses")]
pub mod ncurses_impl;
#[cfg(feature = "eui-tui-ncurses")]
pub use ncurses_impl::NcursesBackend;

#[cfg(feature = "eui-tui-dialog")]
pub mod dialog_impl;
#[cfg(feature = "eui-tui-dialog")]
pub use dialog_impl::DialogInterface;

// 注意：如果没有任何 TUI feature 开启，这里会编译为空
// 但 facade.rs 中的 create_backend 会处理这种缺失
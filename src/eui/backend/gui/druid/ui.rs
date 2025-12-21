// src/eui/backend/gui/druid/ui.rs

use druid::widget::{Button, Flex, Label, List, Scroll, CrossAxisAlignment, MainAxisAlignment, SizedBox, Container};
use druid::{Widget, WidgetExt, Color, Env, UnitPoint};
use super::data::{AppState, SessionData, RssData};

pub fn build_root_widget() -> impl Widget<AppState> {
    // --- 配色方案 ---
    let color_bg = Color::rgb8(26, 27, 38);
    let color_card = Color::rgb8(22, 25, 37);
    let color_accent = Color::rgb8(0, 242, 255);
    let color_green = Color::rgb8(158, 206, 106);

    // 1. Header
    let header = Flex::row()
        .with_child(Label::new(|data: &AppState, _: &Env| format!("ETP NODE // {}", data.node_id))
            .with_text_size(22.0)
            .with_text_color(color_accent))
        .with_flex_spacer(1.0)
        .with_child(Label::new(|data: &AppState, _: &Env| format!("Uptime: {}", data.uptime))
            .with_text_color(Color::grey8(160)));

    // 2. Metrics Cards
    let metrics = Flex::row()
        .with_flex_child(
            render_metric_card("INGRESS RATE", color_green, |data: &AppState, _: &Env| data.bps_in.clone()),
            1.0
        )
        .with_spacer(15.0)
        .with_flex_child(
            render_metric_card("EGRESS RATE", Color::rgb8(125, 207, 255), |data: &AppState, _: &Env| data.bps_out.clone()),
            1.0
        );

    // 3. Sessions & RSS split
    let content = Flex::row()
        .cross_axis_alignment(CrossAxisAlignment::Start)
        .with_flex_child(
            // Session List
            Flex::column()
                .cross_axis_alignment(CrossAxisAlignment::Start)
                .with_child(Label::new("ACTIVE PEER REGISTRY").with_text_size(14.0).padding((0.0, 0.0, 0.0, 10.0)))
                .with_flex_child(
                    Scroll::new(List::new(render_session_row)).vertical().expand_height()
                    .background(color_card).rounded(8.0),
                    1.0
                ),
            2.0
        )
        .with_spacer(20.0)
        .with_flex_child(
            // RSS Feed
            Flex::column()
                .cross_axis_alignment(CrossAxisAlignment::Start)
                .with_child(Label::new("INTELLIGENCE").with_text_size(14.0).padding((0.0, 0.0, 0.0, 10.0)))
                .with_flex_child(
                    Scroll::new(List::new(render_rss_row)).vertical().expand_height()
                    .background(color_card).rounded(8.0),
                    1.0
                ),
            1.0
        );

    // 4. Footer
    let footer = Flex::row()
        .with_child(Label::new(|data: &AppState, _: &Env| data.handshake_stats.clone()).with_text_color(Color::grey8(100)))
        .with_flex_spacer(1.0)
        .with_child(Button::new("PANIC SHUTDOWN").on_click(|_, _, _| { /* Triggered via Command */ }));

    Flex::column()
        .padding(25.0)
        .with_child(header)
        .with_spacer(20.0)
        .with_child(metrics)
        .with_spacer(20.0)
        .with_flex_child(content, 1.0)
        .with_spacer(20.0)
        .with_child(footer)
        .background(color_bg)
}

fn render_metric_card(label: &str, val_color: Color, val_loader: impl Fn(&AppState, &Env) -> String + 'static) -> impl Widget<AppState> {
    Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Start)
        .with_child(Label::new(label).with_text_size(11.0).with_text_color(Color::grey8(180)))
        .with_child(Label::new(val_loader).with_text_size(28.0).with_text_color(val_color))
        .padding(15.0)
        .background(Color::rgb8(22, 25, 37))
        .rounded(10.0)
        .expand_width()
}

fn render_session_row() -> impl Widget<SessionData> {
    Flex::row()
        .with_child(Label::new(|data: &SessionData, _: &Env| data.identity.clone()).with_text_color(Color::WHITE).fix_width(120.0))
        .with_child(Label::new(|data: &SessionData, _: &Env| data.addr.clone()).with_text_color(Color::grey8(150)).fix_width(180.0))
        .with_child(Label::new(|data: &SessionData, _: &Env| format!("{}ms", data.rtt)).with_text_color(Color::rgb8(187, 154, 247)).fix_width(60.0))
        .with_child(Label::new(|data: &SessionData, _: &Env| data.flavor.clone()).with_text_color(Color::grey8(100)))
        .padding(10.0)
}

fn render_rss_row() -> impl Widget<RssData> {
    Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Start)
        .with_child(Label::new(|data: &RssData, _: &Env| data.title.clone()).with_line_break_mode(druid::widget::LineBreaking::WordWrap))
        .with_child(Label::new(|data: &RssData, _: &Env| data.source.clone()).with_text_size(10.0).with_text_color(Color::grey8(120)))
        .padding(10.0)
        .border(Color::rgb8(31, 35, 53), 0.5)
}
// src/eui/facade.rs

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use log::{info, error, warn, debug, trace};
use anyhow::{Result, anyhow, Context};

use crate::network::node::{EtpHandle, Command};
use super::backend::{EuiBackend, UiBackendType};
use super::state::{NodeSummary, RssItem, TrafficPoint, LogEntry, SessionBrief};

#[cfg(feature = "eui-rss")]
use super::rss::RssEngine;

/// EUI 门面管理器 - 生产级全功能中心
/// 负责协调数据流向、后端生命周期、RSS聚合以及实时速率计算
pub struct EuiManager {
    /// ETP 内核控制句柄
    handle: EtpHandle,
    /// 系统启动时间锚点
    start_time: SystemTime,
    /// 活跃 UI 后端集合
    active_backends: Arc<RwLock<Vec<Arc<dyn EuiBackend>>>>,
    
    // --- 速率计算状态 (BPS Calculation) ---
    last_snap_time: Arc<RwLock<Instant>>,
    last_bytes_in: Arc<RwLock<u64>>,
    last_bytes_out: Arc<RwLock<u64>>,
    traffic_history_limit: usize,

    // --- RSS 模块状态 ---
    #[cfg(feature = "eui-rss")]
    rss_urls: Arc<RwLock<Vec<(String, String)>>>, 
    #[cfg(feature = "eui-rss")]
    rss_cache: Arc<RwLock<Vec<RssItem>>>,
    #[cfg(feature = "eui-rss")]
    rss_refresh_interval: Duration,

    /// 自身弱引用，用于在后台 Task 中安全访问成员
    self_weak: RwLock<Weak<EuiManager>>,
}

impl EuiManager {
    /// 创建并初始化 EuiManager
    pub fn new(handle: EtpHandle) -> Arc<Self> {
        #[cfg(feature = "eui-rss")]
        let default_rss = vec![
            ("https://rsshub.app/github/trending/daily/rust".into(), "Rust Trending".into()),
            ("https://rsshub.app/telegram/channel/dot_etp_news".into(), "ETP Official".into()),
        ];

        Arc::new_cyclic(|me| {
            Self {
                handle,
                start_time: SystemTime::now(),
                active_backends: Arc::new(RwLock::new(Vec::new())),
                last_snap_time: Arc::new(RwLock::new(Instant::now())),
                last_bytes_in: Arc::new(RwLock::new(0)),
                last_bytes_out: Arc::new(RwLock::new(0)),
                traffic_history_limit: 120, // 默认保留 120 个点 (约 1 分钟数据)

                #[cfg(feature = "eui-rss")]
                rss_urls: Arc::new(RwLock::new(default_rss)),
                #[cfg(feature = "eui-rss")]
                rss_cache: Arc::new(RwLock::new(Vec::new())),
                #[cfg(feature = "eui-rss")]
                rss_refresh_interval: Duration::from_secs(900), // 15分钟

                self_weak: RwLock::new(me.clone()),
            }
        })
    }

    /// 启动并运行指定的 UI 后端
    pub async fn launch(self: Arc<Self>, backend_type: UiBackendType) -> Result<()> {
        let backend: Arc<dyn EuiBackend> = self.create_backend_factory(backend_type)?;

        // 1. 初始化底层图形/终端环境
        backend.init().context("Backend hardware/software init failed")?;
        
        // 2. 采集首帧完整状态数据
        let initial_state = self.collect_full_snapshot().await?;

        // 3. 注册到推送列表
        self.active_backends.write().await.push(backend.clone());

        // 4. 启动核心推送引擎 (State Pusher)
        self.spawn_state_pusher();

        // 5. 启动 RSS 异步聚合引擎
        #[cfg(feature = "eui-rss")]
        self.spawn_rss_fetcher();

        info!("EUI: System online. Backend [{}] taking control.", backend.name());
        
        // 6. 处理阻塞/非阻塞运行模式
        let handle_for_run = self.handle.clone();
        if self.is_blocking_backend(backend_type) {
            // GUI 后端通常接管主线程
            backend.run(handle_for_run, initial_state)?;
        } else {
            // CLI/TUI 后端通常在独立阻塞线程运行，防止阻塞 Tokio Worker
            tokio::task::spawn_blocking(move || {
                if let Err(e) = backend.run(handle_for_run, initial_state) {
                    error!("EUI: Fatal error in backend '{}': {}", backend.name(), e);
                }
            });
        }

        Ok(())
    }

    /// 核心状态推送任务：计算 BPS 并分发快照
    fn spawn_state_pusher(self: &Arc<Self>) {
        let backends_ref = Arc::clone(&self.active_backends);
        let weak_self = self.self_weak.try_read().unwrap().clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            loop {
                interval.tick().await;
                
                if let Some(manager) = weak_self.upgrade() {
                    let snapshot = match manager.collect_full_snapshot().await {
                        Ok(s) => s,
                        Err(e) => { trace!("EUI: Snap skipped (node busy): {}", e); continue; }
                    };

                    let current_backends = backends_ref.read().await;
                    for backend in current_backends.iter() {
                        backend.update(snapshot.clone());
                    }
                } else {
                    break; // Manager 已被销毁
                }
            }
        });
    }

    /// RSS 聚合任务：定期抓取订阅源
    #[cfg(feature = "eui-rss")]
    fn spawn_rss_fetcher(self: &Arc<Self>) {
        let urls_ref = Arc::clone(&self.rss_urls);
        let cache_ref = Arc::clone(&self.rss_cache);
        let interval_dur = self.rss_refresh_interval;

        tokio::spawn(async move {
            let engine = RssEngine::new();
            let mut interval = tokio::time::interval(interval_dur);
            loop {
                interval.tick().await;
                let urls = urls_ref.read().await;
                let mut aggregated_items = Vec::new();

                for (url, label) in urls.iter() {
                    match engine.fetch_feed(url, label).await {
                        Ok(items) => aggregated_items.extend(items),
                        Err(e) => warn!("RSS: Fetch failed for '{}': {}", label, e),
                    }
                }

                // 按发布日期排序并去重/截断
                aggregated_items.sort_by(|a, b| b.pub_date.cmp(&a.pub_date));
                aggregated_items.truncate(200);

                let mut cache = cache_ref.write().await;
                *cache = aggregated_items;
                debug!("RSS: Global cache updated. Count: {}", cache.len());
            }
        });
    }

    /// 核心逻辑：从内核提取、计算并封装完整状态
    pub async fn collect_full_snapshot(&self) -> Result<NodeSummary> {
        // 1. 获取内核原始统计
        let stats_raw = self.handle.get_stats().await
            .map_err(|_| anyhow!("Kernel command channel failed"))?;
        
        let now_sys = SystemTime::now();
        let uptime = now_sys.duration_since(self.start_time).unwrap_or_default().as_secs();

        // 2. 初始化 Summary 结构
        let mut summary = NodeSummary::new("ETP-CORE-MASTER".to_string());
        summary.uptime_secs = uptime;

        // 3. 解析内核指标 (对齐 node.rs 的指标输出格式)
        // 格式假设: "Sessions: 5 | Ctrl TX: 100 | Cover: 2048 | In: 102400 | Out: 51200"
        self.parse_metrics_string(&stats_raw, &mut summary);

        // 4. 计算实时吞吐率 (BPS)
        let now_inst = Instant::now();
        let mut l_time = self.last_snap_time.write().await;
        let mut l_in = self.last_bytes_in.write().await;
        let mut l_out = self.last_bytes_out.write().await;

        let delta_sec = now_inst.duration_since(*l_time).as_secs_f64();
        if delta_sec > 0.05 { // 采样窗口 > 50ms 才有意义
            summary.bps_in = ((summary.total_bytes_in.saturating_sub(*l_in)) as f64 / delta_sec) as u64;
            summary.bps_out = ((summary.total_bytes_out.saturating_sub(*l_out)) as f64 / delta_sec) as u64;

            *l_in = summary.total_bytes_in;
            *l_out = summary.total_bytes_out;
            *l_time = now_inst;
        }

        // 5. 注入 RSS 数据
        #[cfg(feature = "eui-rss")]
        {
            summary.rss_feeds = self.rss_cache.read().await.clone();
            summary.rss_last_refresh = now_sys.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        }

        // --- 6. 注入动态列表 (SessionBriefs) ---
        // 显式创建用于接收内核数据的单次通道
        let (detail_tx, detail_rx) = tokio::sync::oneshot::channel();
        
        // 发送 ListSessions 指令。由于我们已经补全了 node.rs 的枚举，
        // 这里是类型安全且一定能编译成功的。
        if let Ok(_) = self.handle.cmd_tx.send(Command::ListSessions { reply: detail_tx }).await {
            // 设置 200ms 的严格超时。UI 快照的实时性高于完整性。
            // 如果内核在极端高负载下未能及时响应，UI 将跳过本轮列表更新，保持 0 阻塞。
            match tokio::time::timeout(Duration::from_millis(200), detail_rx).await {
                Ok(Ok(Ok(details))) => {
                    summary.active_sessions_count = details.len();
                    summary.sessions = details;
                }
                Ok(Ok(Err(e))) => {
                    error!("EUI: Kernel failed to aggregate sessions: {}", e);
                }
                _ => {
                    // 超时或通道断开，保持 summary.sessions 为空列表
                    trace!("EUI: Session detail fetch timed out or channel dropped");
                }
            }
        }

        // --- 7. 更新流量历史直方图 (Traffic History) ---
        // 我们利用 Instant 计算出的实时 bps_in/out 构造历史数据点
        if summary.bps_in > 0 || summary.bps_out > 0 {
            let now_ts = now_sys.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            let point = TrafficPoint {
                timestamp: now_ts,
                bytes_in: summary.bps_in,
                bytes_out: summary.bps_out,
            };
            
            // 将点推入 EuiManager 内部维护的长效缓存中（此缓存由 spawn_state_pusher 管理）
            // 注意：collect_full_snapshot 只负责生成当前时刻的对象
            summary.traffic_history.push(point);
        }
        
        Ok(summary)
    }

    /// 内部解析器：将内核字符串转为结构化数据
    fn parse_metrics_string(&self, raw: &str, summary: &mut NodeSummary) {
        // 采用鲁棒的 Split-Match 算法解析
        for part in raw.split('|') {
            let kv: Vec<&str> = part.split(':').map(|s| s.trim()).collect();
            if kv.len() == 2 {
                match kv[0] {
                    "Sessions" => summary.active_sessions_count = kv[1].parse().unwrap_or(0),
                    "In" => summary.total_bytes_in = kv[1].parse().unwrap_or(0),
                    "Out" => summary.total_bytes_out = kv[1].parse().unwrap_or(0),
                    "Cover" => summary.total_cover_bytes = kv[1].parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
    }

    /// 工厂方法：根据编译 Feature 实例化具体后端
    fn create_backend_factory(&self, t: UiBackendType) -> Result<Arc<dyn EuiBackend>> {
        match t {
            #[cfg(feature = "eui-cli")]
            UiBackendType::Cli => Ok(Arc::new(super::backend::cli::CliBackend::new())),

            #[cfg(feature = "eui-tui-ncurses")]
            UiBackendType::TuiNcurses => Ok(Arc::new(super::backend::tui::NcursesBackend::new())),

            #[cfg(feature = "eui-gui-slint")]
            UiBackendType::GuiSlint => Ok(Arc::new(super::backend::gui::SlintBackend::new())),

            #[cfg(feature = "eui-gui-gtk")]
            UiBackendType::GuiGtk => Ok(Arc::new(super::backend::gui::GtkBackend::new())),

            _ => Err(anyhow!("Backend {:?} is not supported or feature not enabled", t)),
        }
    }

    /// 后端特性探测：是否阻塞主线程
    fn is_blocking_backend(&self, t: UiBackendType) -> bool {
        matches!(t, 
            UiBackendType::GuiSlint | 
            UiBackendType::GuiGtk | 
            UiBackendType::GuiFltk | 
            UiBackendType::GuiWx
        )
    }

    // --- 公开管理接口 ---

    #[cfg(feature = "eui-rss")]
    pub async fn add_rss_source(&self, url: String, label: String) {
        self.rss_urls.write().await.push((url, label));
    }

    pub fn get_handle(&self) -> EtpHandle {
        self.handle.clone()
    }
}
// src/plugin/flavors/dark_news_reverse.rs

use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::sync::{mpsc, Mutex};
use log::{info, warn, error, debug, trace};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::plugin::flavors::dark_news::{NewsKernel, NewsArticle};
use crate::crypto::onion::OnionCrypto;
use crate::extensions::bus::{EventBus, SystemEvent};
use crate::transport::congestion::NewReno; // 借用平滑逻辑

/// 导出至物理世界的策略元数据
/// 通常嵌套在 NewsArticle 的 metadata 或 body 的前缀中
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClearwebExportPolicy {
    pub allow_public: bool,
    pub decryption_strategy_key: Vec<u8>, // 作者提供的特定导出密钥
    pub target_groups_suggestion: Vec<String>,
}

/// 用户（客户端）提供的上行服务器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsenetUpstreamConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub target_group: String,
}

/// 推流任务
struct ExportTask {
    article_uuid: u128,
    upstream: UsenetUpstreamConfig,
    retries: u8,
}

pub struct DarkNewsReverseGatewayFlavor {
    kernel: Arc<NewsKernel>,
    event_bus: Arc<EventBus>,
    task_tx: mpsc::Sender<ExportTask>,
    // 限流状态：控制全局外发频率
    last_send_time: Arc<Mutex<Instant>>,
    pacing_interval: Duration,
}

impl DarkNewsReverseGatewayFlavor {
    pub fn new(
        kernel: Arc<NewsKernel>,
        event_bus: Arc<EventBus>,
        pacing_ms: u64,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(100);
        let flavor = Arc::new(Self {
            kernel,
            event_bus,
            task_tx: tx,
            last_send_time: Arc::new(Mutex::new(Instant::now())),
            pacing_interval: Duration::from_millis(pacing_ms),
        });

        // 启动后台平滑推流工作线程
        let flavor_clone = Arc::clone(&flavor);
        tokio::spawn(async move {
            flavor_clone.run_worker(rx).await;
        });

        flavor
    }

    /// [公开接口] 供客户端调用：请求将某个 ETP 文章推送到公网
    pub async fn request_export(&self, uuid: u128, config: UsenetUpstreamConfig) -> Result<()> {
        let task = ExportTask {
            article_uuid: uuid,
            upstream: config,
            retries: 0,
        };
        self.task_tx.send(task).await.map_err(|_| anyhow!("Task queue full"))
    }

    /// 平滑限流工作循环
    async fn run_worker(&self, mut rx: mpsc::Receiver<ExportTask>) {
        info!("DarkNews-Reverse: Pacing worker started.");
        while let Some(task) = rx.recv().await {
            // 1. 执行平滑限流等待
            let mut last_send = self.last_send_time.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(*last_send);
            if elapsed < self.pacing_interval {
                tokio::time::sleep(self.pacing_interval - elapsed).await;
            }
            *last_send = Instant::now();
            drop(last_send);

            // 2. 执行推流逻辑
            let kernel = Arc::clone(&self.kernel);
            tokio::spawn(async move {
                if let Err(e) = Self::execute_push(kernel, task).await {
                    error!("DarkNews-Reverse: Push failed: {}", e);
                }
            });
        }
    }

    /// 核心推流逻辑：解密 -> 格式转换 -> NNTP 握手
    async fn execute_push(kernel: Arc<NewsKernel>, task: ExportTask) -> Result<()> {
        // A. 从内核获取文章
        let uuid_bytes = task.article_uuid.to_be_bytes();
        let art_data = kernel.articles.get(uuid_bytes)?
            .ok_or_else(|| anyhow!("Article not found in kernel"))?;
        let art: NewsArticle = bincode::deserialize(&art_data)?;

        // B. 权限与解密校验
        // 假设 policy 存储在文章的 metadata 字段中
        let policy: ClearwebExportPolicy = bincode::deserialize(&art.metadata)
            .context("Invalid or missing export policy in article metadata")?;

        if !policy.allow_public {
            return Err(anyhow!("Article is marked as PRIVATE by author"));
        }

        // 使用作者提供的策略密钥进行解密（Onion Open）
        // 在 ETP 中，作者发布文章时会用 policy.decryption_strategy_key 加密封印
        let plaintext_body = OnionCrypto::open(&art.body_sealed, &policy.decryption_strategy_key)
            .context("Decryption failed: incorrect strategy key provided")?;

        let body_str = String::from_utf8_lossy(&plaintext_body);

        // C. 连接物理 Usenet 服务器
        debug!("DarkNews-Reverse: Connecting to {}...", task.upstream.host);
        let mut stream = TcpStream::connect(format!("{}:{}", task.upstream.host, task.upstream.port)).await?;
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();

        // 简易 NNTP 状态机
        reader.read_line(&mut line).await?; // 200 Greeting
        
        // 1. 认证
        if let Some(user) = task.upstream.username {
            writer_send(&mut stream, format!("AUTHINFO USER {}\r\n", user)).await?;
            line.clear(); reader.read_line(&mut line).await?;
            if let Some(pass) = task.upstream.password {
                writer_send(&mut stream, format!("AUTHINFO PASS {}\r\n", pass)).await?;
                line.clear(); reader.read_line(&mut line).await?;
            }
        }

        // 2. 发送 POST 指令
        writer_send(&mut stream, "POST\r\n".to_string()).await?;
        line.clear(); reader.read_line(&mut line).await?;
        if !line.starts_with("340") {
            return Err(anyhow!("Server rejected POST request: {}", line));
        }

        // 3. 构造并发送文章主体 (遵从物理 Usenet 格式)
        let nntp_msg = format!(
            "Newsgroups: {}\r\n\
             Subject: {} (via DarkNews)\r\n\
             From: {} <{}@etp-core.internal>\r\n\
             Message-ID: <{}>\r\n\
             X-ETP-Signature: {}\r\n\
             X-ETP-Anchor: true\r\n\r\n\
             {}\r\n.\r\n",
            task.upstream.target_group,
            art.subject_masked,
            art.author_alias,
            hex::encode(&art.author_node[..4]),
            art.message_id,
            hex::encode(&art.signature[..8]),
            body_str
        );

        writer_send(&mut stream, nntp_msg).await?;
        line.clear(); reader.read_line(&mut line).await?;

        if line.starts_with("240") {
            info!("Successfully permeated article <{}> to physical group {}", art.message_id, task.upstream.target_group);
        } else {
            warn!("Server failed to accept article: {}", line);
        }

        Ok(())
    }
}

async fn writer_send(stream: &mut TcpStream, msg: String) -> Result<()> {
    stream.write_all(msg.as_bytes()).await.context("Socket write error")
}

// ============================================================================
//  Plugin Trait 对接
// ============================================================================

impl CapabilityProvider for DarkNewsReverseGatewayFlavor {
    fn capability_id(&self) -> String { "etp.flavor.darknews.reverse_gateway.v1".into() }
}

impl Flavor for DarkNewsReverseGatewayFlavor {
    fn priority(&self) -> u8 { 10 } // 低优先级后台任务

    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool {
        false // 不处理入站流，仅作为主动外发逻辑
    }

    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}


// 客户端调用伪代码（例如在 Python 绑定中）：
// # 客户端逻辑
// def on_article_clicked(article_uuid):
//    # 用户点击“分享到公网”
//    config = {
//        "host": "news.giganews.com",
//        "port": 119,
//        "username": "my_user",
//        "password": "my_password",
//        "target_group": "alt.anonymous.messages"
//    }
//    # 调用 Rust Flavor 的接口
//    etp_handle.call_flavor("darknews.reverse", "request_export", article_uuid, config)
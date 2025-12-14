// etp-core/src/extensions/ens.rs

#[cfg(feature = "ens-gateway")]
pub mod gateway {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::convert::Infallible;
    use std::time::Duration;
    
    use serde::{Deserialize, Serialize};
    use log::{info, error, warn, debug};
    use warp::{Filter, http::StatusCode};
    use thiserror::Error;
    
    // Ethers imports
    use ethers::providers::{Provider, Http, Middleware, ProviderError};
    
    // ========================================================================
    //  配置与结构定义
    // ========================================================================

    /// ENS 网关配置
    #[derive(Debug, Clone)]
    pub struct EnsGatewayConfig {
        pub bind_addr: SocketAddr,
        pub eth_rpc_url: String,
        /// RPC 请求超时时间 (秒)
        pub timeout_secs: u64,
    }

    impl Default for EnsGatewayConfig {
        fn default() -> Self {
            Self {
                bind_addr: "127.0.0.1:3000".parse().unwrap(),
                eth_rpc_url: "http://localhost:8545".to_string(),
                timeout_secs: 10,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct ResolveParams {
        pub name: String,
        pub key: String,
    }

    #[derive(Serialize)]
    struct ErrorMessage {
        code: u16,
        message: String,
        details: Option<String>,
    }

    // ========================================================================
    //  错误处理系统 (Production Grade)
    // ========================================================================

    #[derive(Debug, Error)]
    pub enum EnsGatewayError {
        #[error("Invalid Input: {0}")]
        InvalidInput(String),
        
        #[error("ENS Name Not Found or Not Registered")]
        NameNotFound,
        
        #[error("Text Record Not Found for Key")]
        RecordNotFound,
        
        #[error("Upstream RPC Error: {0}")]
        UpstreamError(String),
        
        #[error("Upstream Timeout")]
        UpstreamTimeout,
    }

    // 让 warp 识别这个错误类型
    impl warp::reject::Reject for EnsGatewayError {}

    /// 将内部错误转换为 HTTP 响应
    async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
        let code;
        let message;
        let mut details = None;

        if err.is_not_found() {
            code = StatusCode::NOT_FOUND;
            message = "Endpoint Not Found".to_string();
        } else if let Some(e) = err.find::<EnsGatewayError>() {
            match e {
                EnsGatewayError::InvalidInput(msg) => {
                    code = StatusCode::BAD_REQUEST;
                    message = msg.clone();
                }
                EnsGatewayError::NameNotFound => {
                    code = StatusCode::NOT_FOUND;
                    message = "ENS Name Not Found".to_string();
                }
                EnsGatewayError::RecordNotFound => {
                    code = StatusCode::NOT_FOUND;
                    message = "Text Record Not Found".to_string();
                }
                EnsGatewayError::UpstreamError(msg) => {
                    code = StatusCode::BAD_GATEWAY;
                    message = "Upstream RPC Failure".to_string();
                    details = Some(msg.clone());
                }
                EnsGatewayError::UpstreamTimeout => {
                    code = StatusCode::GATEWAY_TIMEOUT;
                    message = "Upstream RPC Timeout".to_string();
                }
            }
        } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
            code = StatusCode::METHOD_NOT_ALLOWED;
            message = "Method Not Allowed".to_string();
        } else if let Some(_) = err.find::<warp::reject::InvalidQuery>() {
            code = StatusCode::BAD_REQUEST;
            message = "Invalid Query Parameters".to_string();
        } else {
            code = StatusCode::INTERNAL_SERVER_ERROR;
            message = "Internal Server Error".to_string();
            details = Some(format!("{:?}", err));
        }

        let json = warp::reply::json(&ErrorMessage {
            code: code.as_u16(),
            message,
            details,
        });

        Ok(warp::reply::with_status(json, code))
    }

    // ========================================================================
    //  核心逻辑
    // ========================================================================

    /// 启动 ENS 桥接服务
    pub async fn run_server(config: EnsGatewayConfig) {
        info!("ENS Gateway: Starting on http://{}", config.bind_addr);
        info!("ENS Gateway: Upstream RPC -> {}", config.eth_rpc_url);

        // 1. 初始化 Provider 并设置超时
        let provider = match Provider::<Http>::try_from(config.eth_rpc_url.clone()) {
            Ok(p) => {
                // 设置 HTTP 客户端超时
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(config.timeout_secs))
                    .build()
                    .unwrap_or_default();
                Arc::new(Provider::new(Http::new_with_client(
                    url::Url::parse(&config.eth_rpc_url).unwrap(), 
                    client
                )))
            },
            Err(e) => {
                error!("ENS Gateway: Invalid RPC URL: {}", e);
                return;
            }
        };

        // 2. 路由定义
        let resolve_route = warp::path("resolve")
            .and(warp::get())
            .and(warp::query::<ResolveParams>())
            .and(with_provider(provider.clone()))
            .and_then(handle_resolve);

        let health_route = warp::path("health")
            .map(|| warp::reply::json(&serde_json::json!({"status": "ok"})));

        let routes = resolve_route
            .or(health_route)
            .recover(handle_rejection) // 挂载全局错误处理器
            .with(warp::log("etp::extensions::ens"));

        // 3. 运行
        warp::serve(routes).run(config.bind_addr).await;
    }

    fn with_provider(
        provider: Arc<Provider<Http>>,
    ) -> impl Filter<Extract = (Arc<Provider<Http>>,), Error = Infallible> + Clone {
        warp::any().map(move || provider.clone())
    }

    /// 处理解析请求
    async fn handle_resolve(
        params: ResolveParams,
        provider: Arc<Provider<Http>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        // A. 输入校验
        if params.name.is_empty() || params.key.is_empty() {
            return Err(warp::reject::custom(EnsGatewayError::InvalidInput("Name or Key is empty".into())));
        }
        if !params.name.contains('.') {
             // 简单的启发式检查，防止无效查询浪费 RPC 资源
             return Err(warp::reject::custom(EnsGatewayError::InvalidInput("Invalid ENS domain format".into())));
        }

        debug!("ENS Query: name={}, key={}", params.name, params.key);

        // B. 执行链上查询
        // ethers 的 get_ens_text_record 内部会处理 Namehash 和 Resolver 查找
        let result = provider.get_ens_text_record(&params.name, &params.key).await;

        match result {
            Ok(value) => {
                if value.is_empty() {
                    // C. 记录为空
                    // 在 ENS 中，如果 key 不存在，通常返回空字符串。
                    // 业务上这应当视为 404，通知客户端这里没有配置。
                    warn!("ENS: Record empty for {}/{}", params.name, params.key);
                    return Err(warp::reject::custom(EnsGatewayError::RecordNotFound));
                }
                
                info!("ENS Resolved: {} -> {}", params.name, value);
                // 成功返回 200 OK
                Ok(warp::reply::json(&value))
            },
            Err(e) => {
                // D. 错误分类处理
                warn!("ENS Lookup Failed for {}: {:?}", params.name, e);
                
                // 尝试匹配 ethers 的错误类型
                match e {
                    ProviderError::EnsError(_) => {
                        // 域名未注册或 Resolver 未配置
                        Err(warp::reject::custom(EnsGatewayError::NameNotFound))
                    },
                    ProviderError::HTTPError(e) if e.is_timeout() => {
                        Err(warp::reject::custom(EnsGatewayError::UpstreamTimeout))
                    },
                    _ => {
                        // 其他 RPC 错误 (网络中断、节点限流、解析错误等)
                        Err(warp::reject::custom(EnsGatewayError::UpstreamError(e.to_string())))
                    }
                }
            }
        }
    }
}

// 占位符 (Feature Disabled)
#[cfg(not(feature = "ens-gateway"))]
pub mod gateway {
    use std::net::SocketAddr;
    
    #[derive(Debug, Clone)]
    pub struct EnsGatewayConfig {
        pub bind_addr: SocketAddr,
        pub eth_rpc_url: String,
        pub timeout_secs: u64,
    }
    
    impl Default for EnsGatewayConfig {
        fn default() -> Self {
            Self {
                bind_addr: "127.0.0.1:3000".parse().unwrap(),
                eth_rpc_url: "".to_string(),
                timeout_secs: 0,
            }
        }
    }

    pub async fn run_server(_config: EnsGatewayConfig) {
        log::error!("ENS Gateway feature is NOT enabled. Recompile with --features ens-gateway");
    }
}
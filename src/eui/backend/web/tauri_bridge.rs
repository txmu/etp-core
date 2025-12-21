// src/eui/backend/web/tauri_bridge.rs

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::net::TcpStream;
use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use serde_json::json;
use log::{info, warn, error, debug, trace};

use crate::network::node::EtpHandle;
use crate::eui::{EuiCommand, bridge::BackendBridgeExt};
use crate::eui::state::NodeSummary;
use super::jsonrpc::{JsonRpcRequest, JsonRpcNotification, JsonRpcResponse};

pub struct WebBridgeManager {
    /// 活跃的 Web 订阅者 (TxChannel)
    subscribers: Arc<RwLock<Vec<mpsc::UnboundedSender<Message>>>>,
    /// 安全访问令牌 (用于首包 Auth)
    access_token: String,
}

impl WebBridgeManager {
    pub fn new(token: &str) -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(Vec::new())),
            access_token: token.to_string(),
        }
    }

    /// 广播状态到所有连接的 GUI/Web 前端
    pub async fn broadcast_snapshot(&self, snap: NodeSummary) {
        let payload = match serde_json::to_value(&snap) {
            Ok(v) => v,
            Err(e) => { error!("WebBridge: Serialization fail: {}", e); return; }
        };
        
        let notify = JsonRpcNotification::new("etp_snap_update", payload);
        let text = serde_json::to_string(&notify).unwrap_or_default();
        let msg = Message::Text(text);

        let mut subs = self.subscribers.write().await;
        subs.retain(|tx| tx.send(msg.clone()).is_ok());
    }

    /// 停机通知：在物理断开前通知前端清理资源
    pub async fn notify_halt(&self, reason: &str) {
        let notify = JsonRpcNotification::new("system_halt", json!({ "reason": reason }));
        let text = serde_json::to_string(&notify).unwrap_or_default();
        let msg = Message::Text(text);

        let mut subs = self.subscribers.write().await;
        for tx in subs.iter() {
            let _ = tx.send(msg.clone());
        }
        subs.clear();
    }

    /// 处理单个 WebSocket 会话逻辑
    pub async fn handle_session(&self, stream: TcpStream, handle: EtpHandle) -> Result<(), anyhow::Error> {
        let ws_stream = accept_async(stream).await?;
        let (mut ws_tx, mut ws_rx) = ws_stream.split();
        
        let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();
        
        // 1. 鉴权挑战 (Authentication Challenge)
        // 客户端必须在 5 秒内发送正确的 Auth Token
        let auth_timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(auth_timeout);

        let mut authenticated = false;
        loop {
            tokio::select! {
                Some(msg) = ws_rx.next() => {
                    if let Ok(Message::Text(t)) = msg {
                        if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&t) {
                            if req.method == "auth" {
                                if let Some(token) = req.params.and_then(|p| p.as_str()) {
                                    if token == self.access_token {
                                        authenticated = true;
                                        let resp = json!({"jsonrpc": "2.0", "result": "welcome", "id": req.id});
                                        let _ = ws_tx.send(Message::Text(resp.to_string())).await;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    return Err(anyhow::anyhow!("Unauthorized access attempt"));
                }
                _ = &mut auth_timeout => {
                    return Err(anyhow::anyhow!("Auth handshake timeout"));
                }
            }
        }

        if !authenticated { return Ok(()); }
        
        // 2. 进入正式通信逻辑
        self.subscribers.write().await.push(internal_tx);
        let bridge = Arc::new(handle.bridge());

        loop {
            tokio::select! {
                // 向 UI 发送数据 (状态更新)
                Some(out_msg) = internal_rx.recv() => {
                    if ws_tx.send(out_msg).await.is_err() { break; }
                }
                // 处理 UI 的指令 (RPC)
                Some(in_res) = ws_rx.next() => {
                    match in_res {
                        Ok(Message::Text(t)) => {
                            if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&t) {
                                let b = Arc::clone(&bridge);
                                tokio::spawn(async move {
                                    if let Err(e) = Self::route_rpc(req, b).await {
                                        error!("WebBridge: RPC route error: {}", e);
                                    }
                                });
                            }
                        },
                        Ok(Message::Ping(p)) => { let _ = ws_tx.send(Message::Pong(p)).await; }
                        _ => break,
                    }
                }
            }
        }
        Ok(())
    }

    /// 将 JSON-RPC 指令精准路由至内核桥接器
    async fn route_rpc(req: JsonRpcRequest, bridge: Arc<crate::eui::bridge::UiCommandBridge>) -> Result<()> {
        let cmd = match req.method.as_str() {
            "node.shutdown" => EuiCommand::ShutdownNode,
            "peer.disconnect" => {
                let addr = req.params.and_then(|p| p.as_str()).ok_or(anyhow::anyhow!("Param required"))?;
                EuiCommand::DisconnectPeer(addr.to_string())
            },
            "anonymity.toggle_cover" => {
                let on = req.params.and_then(|p| p.as_bool()).unwrap_or(false);
                EuiCommand::ToggleCoverTraffic(on)
            },
            // --- 核心业务：DarkNews 渗透接口 ---
            "darknews.permeate" => {
                let p = req.params.ok_or(anyhow::anyhow!("Config required"))?;
                EuiCommand::DarkNewsPermeate {
                    uuid: p["uuid"].as_u64().unwrap_or(0) as u128, // 简化处理
                    host: p["host"].as_str().unwrap_or("").to_string(),
                    port: p["port"].as_u64().unwrap_or(119) as u16,
                    group: p["group"].as_str().unwrap_or("alt.general").to_string(),
                    decryption_key: hex::decode(p["key"].as_str().unwrap_or("")).unwrap_or_default(),
                }
            },
            _ => return Err(anyhow::anyhow!("Method not found: {}", req.method)),
        };

        bridge.dispatch(cmd).await
    }
}
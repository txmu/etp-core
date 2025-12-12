// etp-core/src/plugin/flavors/http_gateway.rs

use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::Result;
use log::{info, error};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::plugin::{Flavor, FlavorContext, CapabilityProvider};
use crate::plugin::flavors::tns::TnsFlavor;
use crate::plugin::flavors::fileshare::FileShareFlavor;

pub struct HttpGatewayFlavor {
    port: u16,
    tns: Arc<TnsFlavor>,
    fs: Arc<FileShareFlavor>,
}

impl HttpGatewayFlavor {
    pub fn new(port: u16, tns: Arc<TnsFlavor>, fs: Arc<FileShareFlavor>) -> Arc<Self> {
        let flavor = Arc::new(Self { port, tns, fs });
        flavor.start_server();
        flavor
    }

    fn start_server(&self) {
        let port = self.port;
        let tns = self.tns.clone();
        // let fs = self.fs.clone();

        tokio::spawn(async move {
            let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
                Ok(l) => l,
                Err(e) => {
                    error!("HTTP Gateway bind failed: {}", e);
                    return;
                }
            };
            info!("HTTP Gateway listening on http://127.0.0.1:{}", port);

            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                
                let tns = tns.clone();
                
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    // Minimal HTTP Parser
                    let first_line = req_str.lines().next().unwrap_or("");
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    
                    if parts.len() >= 2 && parts[0] == "GET" {
                        let path = parts[1];
                        let response = if path.starts_with("/tns/") {
                            let name = &path[5..];
                            match tns.resolve(name).await {
                                Ok(record) => {
                                    format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{}\",\"target\":\"{:?}\"}}", 
                                        record.name, hex::encode(record.target_id)
                                    )
                                },
                                Err(e) => {
                                    format!("HTTP/1.1 404 Not Found\r\n\r\nError: {}", e)
                                }
                            }
                        } else if path.starts_with("/fs/") {
                            // let hash = &path[4..];
                            // TODO: Implement file streaming from FileShareFlavor
                            "HTTP/1.1 501 Not Implemented\r\n\r\nFile streaming coming soon".to_string()
                        } else {
                            "HTTP/1.1 404 Not Found\r\n\r\nUnknown Endpoint".to_string()
                        };
                        
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                });
            }
        });
    }
}

impl CapabilityProvider for HttpGatewayFlavor {
    fn capability_id(&self) -> String { "etp.flavor.gateway.v1".into() }
}

impl Flavor for HttpGatewayFlavor {
    fn on_stream_data(&self, _ctx: FlavorContext, _data: &[u8]) -> bool {
        false // Gateway 仅作为本地接口，不处理 ETP 网络包
    }
    fn on_connection_open(&self, _peer: SocketAddr) {}
    fn on_connection_close(&self, _peer: SocketAddr) {}
}
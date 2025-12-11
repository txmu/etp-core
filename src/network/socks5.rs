use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use std::net::SocketAddr;
use anyhow::Result;
use log::{info, error, debug};

/// SOCKS5 代理服务器
/// 监听本地 TCP 端口，将流量转发给 ETP 网络
pub struct Socks5Server {
    listen_addr: String,
    // 发送数据给 ETP 节点的通道 (TargetAddr, Data)
    // MVP 简化：SOCKS5 收到数据后，需要知道发给谁。
    // 这里我们假设这是 Client 端，所有的 SOCKS5 流量都发给预设的 Server (Exit Node)。
    etp_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    exit_node: SocketAddr,
}

impl Socks5Server {
    pub fn new(listen_addr: String, etp_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>, exit_node: SocketAddr) -> Self {
        Self {
            listen_addr,
            etp_tx,
            exit_node,
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("SOCKS5 Proxy listening on {}", self.listen_addr);

        loop {
            let (socket, _) = listener.accept().await?;
            let etp_tx = self.etp_tx.clone();
            let exit_node = self.exit_node;

            tokio::spawn(async move {
                if let Err(e) = handle_socks5_connection(socket, etp_tx, exit_node).await {
                    debug!("SOCKS5 connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_socks5_connection(
    mut socket: TcpStream, 
    etp_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    exit_node: SocketAddr
) -> Result<()> {
    // 1. 握手 (Handshake)
    // Client -> Server: [VER, NMETHODS, METHODS...]
    let mut buf = [0u8; 256];
    let n = socket.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid SOCKS version"));
    }
    // 无需认证，直接回 [0x05, 0x00]
    socket.write_all(&[0x05, 0x00]).await?;

    // 2. 请求 (Request)
    // Client -> Server: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    let n = socket.read(&mut buf).await?;
    if n < 4 || buf[1] != 0x01 { // CMD: 0x01 = CONNECT
        return Err(anyhow::anyhow!("Unsupported SOCKS command"));
    }

    // MVP: 我们暂时忽略解析目标地址，默认全部转发给 Exit Node
    // 在完整的实现中，我们需要把 DST.ADDR 封装进 ETP 的 Header 中告诉 Exit Node 去连谁。
    // 这里为了演示“隧道通了”，我们直接回 Success。

    // Server -> Client: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    // 0x00 = Success, 0x01 = IPv4, 0.0.0.0:0
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // 3. 数据传输 (Tunneling)
    // 简单的 TCP -> ETP 转发
    // 注意：目前是单向的演示 (TCP -> ETP)，因为 ETP 回来的数据怎么路由回这个 TCP socket 需要 Stream ID 管理。
    // 在 MVP 中，我们演示“浏览器能发包出去”。
    
    let mut buffer = [0u8; 4096];
    loop {
        let n = socket.read(&mut buffer).await?;
        if n == 0 { break; }
        
        // 封装并发给 ETP 核心
        let data = buffer[..n].to_vec();
        etp_tx.send((exit_node, data)).await?;
    }

    Ok(())
}
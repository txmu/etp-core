// etp-core/examples/chat.rs

use clap::{Parser, Subcommand};
use etp_core::network::node::{EtpEngine, NodeConfig};
use etp_core::crypto::noise::KeyPair;
use etp_core::transport::shaper::SecurityProfile;
use etp_core::wire::packet::{FakeTlsObfuscator, EntropyObfuscator};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(long, default_value = "0.0.0.0:8000")]
        listen: String,
    },
    Client {
        #[arg(long, default_value = "0.0.0.0:8001")]
        listen: String,
        #[arg(long)]
        connect: String,
        #[arg(long)]
        server_pub: String,
        #[arg(long)]
        paranoid: bool,
        #[arg(long)]
        fake_tls: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let my_keys = KeyPair::generate();
    println!("My Public Key (Hex): {}", hex::encode(&my_keys.public));

    match cli.mode {
        Mode::Server { listen } => {
            let config = NodeConfig {
                bind_addr: listen,
                keypair: my_keys,
                profile: SecurityProfile::Turbo,
                bootstrap_peers: vec![],
            };
            // 默认 Server 使用 FakeTLS 解包能力 (如果客户端发 FakeTLS)
            // 生产环境应自适应
            let (engine, handle, mut rx) = EtpEngine::new(config, Arc::new(FakeTlsObfuscator)).await?;
            tokio::spawn(async move { engine.run().await.unwrap(); });

            println!("Server running. Echoing messages...");
            while let Some((src, data)) = rx.recv().await {
                println!("[{}] Data len: {}", src, data.len());
                // Echo back
                let _ = handle.send_data(src, data).await;
            }
        }
        Mode::Client { listen, connect, server_pub, paranoid, fake_tls } => {
            let profile = if paranoid { 
                SecurityProfile::Paranoid { interval_ms: 50, target_size: 1350 } 
            } else { SecurityProfile::Turbo };

            let config = NodeConfig {
                bind_addr: listen,
                keypair: my_keys,
                profile,
                bootstrap_peers: vec![],
            };

            let obfuscator = if fake_tls {
                Arc::new(FakeTlsObfuscator)
            } else {
                Arc::new(EntropyObfuscator)
            };

            let (engine, handle, mut rx) = EtpEngine::new(config, obfuscator).await?;
            let target_addr: SocketAddr = connect.parse()?;
            let remote_pub_bytes = hex::decode(server_pub)?;

            tokio::spawn(async move { engine.run().await.unwrap(); });

            // 1. 发起握手
            handle.connect(target_addr, remote_pub_bytes).await?;
            println!("Handshake initiated...");

            // 2. 启动 SOCKS5 Listener
            let socks_handle = handle.clone();
            tokio::spawn(async move {
                let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();
                println!("SOCKS5 Proxy listening on 127.0.0.1:1080");
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let sender = socks_handle.clone();
                    tokio::spawn(async move {
                        // Minimal SOCKS5
                        let mut buf = [0u8; 256];
                        if socket.read(&mut buf).await.unwrap() < 2 { return; }
                        socket.write_all(&[0x05, 0x00]).await.unwrap(); // No Auth
                        
                        if socket.read(&mut buf).await.unwrap() < 4 { return; }
                        // Respond Success
                        socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await.unwrap();

                        // Forward Loop
                        let mut buf = [0u8; 4096];
                        loop {
                            let n = match socket.read(&mut buf).await { Ok(n) if n > 0 => n, _ => break };
                            let _ = sender.send_data(target_addr, buf[..n].to_vec()).await;
                        }
                    });
                }
            });

            // 3. 打印接收数据 (从 Server 回传)
            while let Some((src, data)) = rx.recv().await {
                println!("[From {}] Received {} bytes (Tunnel response)", src, data.len());
            }
        }
    }
    Ok(())
}
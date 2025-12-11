// etp-core/src/network/tests_socks5.rs

use super::socks5::Socks5Server;
use tokio::sync::mpsc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::test]
async fn test_socks5_handshake() {
    // 1. 启动 Mock SOCKS5 Server
    let (tx, mut rx) = mpsc::channel(100);
    let exit_node: SocketAddr = "1.1.1.1:80".parse().unwrap();
    let server = Socks5Server::new("127.0.0.1:9999".to_string(), tx, exit_node);
    
    tokio::spawn(async move {
        server.run().await.unwrap();
    });

    // 等待启动
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 2. 模拟 SOCKS5 Client
    let mut stream = TcpStream::connect("127.0.0.1:9999").await.unwrap();

    // 发送握手: Version 5, 1 Method, NoAuth(0)
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    // 读取响应: Version 5, Method NoAuth(0)
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);

    // 发送 Connect 请求 (模拟连接 Google:80)
    // Ver 5, Cmd 1(Connect), Rsv 0, Atyp 1(IPv4), 8.8.8.8, Port 80
    let req = [0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0, 80];
    stream.write_all(&req).await.unwrap();

    // 读取响应 (应为 Success 0x00)
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00);

    // 3. 发送数据
    stream.write_all(b"Hello ETP Proxy").await.unwrap();

    // 4. 验证 ETP 通道是否收到数据
    if let Some((target, data)) = rx.recv().await {
        assert_eq!(target, exit_node);
        assert_eq!(data, b"Hello ETP Proxy");
    } else {
        panic!("Did not receive forwarded data");
    }
}
// etp-core/src/extensions/adapter.rs

use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf};
use parking_lot::Mutex;
use anyhow::{Result, anyhow};

/// 共享状态，包含数据缓冲和通知机制
struct SharedState {
    ingress_buffer: BytesMut,
    egress_buffer: BytesMut,
    /// 当 ingress_buffer 有数据写入时唤醒 Reader
    read_waker: Option<Waker>,
    /// 当 egress_buffer 被消费（有空间）时唤醒 Writer (简化起见暂不限流，故此处主要用于flush)
    write_waker: Option<Waker>,
    /// 标记流是否已关闭
    closed: bool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            ingress_buffer: BytesMut::with_capacity(8192),
            egress_buffer: BytesMut::with_capacity(8192),
            read_waker: None,
            write_waker: None,
            closed: false,
        }
    }
}

/// 虚拟流句柄，实现了 AsyncRead + AsyncWrite
/// 用于将外部协议库（如 rustls, quinn）挂载到 ETP Dialect 上
pub struct ProtocolStream {
    state: Arc<Mutex<SharedState>>,
}

impl ProtocolStream {
    pub fn new() -> (Self, StreamController) {
        let state = Arc::new(Mutex::new(SharedState::new()));
        (
            Self { state: state.clone() },
            StreamController { state }
        )
    }
}

impl AsyncRead for ProtocolStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut guard = self.state.lock();

        if !guard.ingress_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), guard.ingress_buffer.len());
            let data = guard.ingress_buffer.split_to(len);
            buf.put_slice(&data);
            Poll::Ready(Ok(()))
        } else if guard.closed {
            // EOF
            Poll::Ready(Ok(()))
        } else {
            // 无数据，注册 Waker
            guard.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl AsyncWrite for ProtocolStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut guard = self.state.lock();
        if guard.closed {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Stream closed")));
        }
        guard.egress_buffer.extend_from_slice(buf);
        // 通知控制器有数据要发送
        if let Some(waker) = guard.write_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut guard = self.state.lock();
        guard.closed = true;
        // 唤醒可能在等待的对端
        if let Some(waker) = guard.write_waker.take() { waker.wake(); }
        if let Some(waker) = guard.read_waker.take() { waker.wake(); }
        Poll::Ready(Ok(()))
    }
}

/// 控制器：用于 Dialect 内部操作数据的读写
/// 这是 "Dialect" 和 "Protocol Library" 之间的桥梁
pub struct StreamController {
    state: Arc<Mutex<SharedState>>,
}

impl StreamController {
    /// 将网络收到的数据写入流的输入缓冲（供外部库读取）
    /// 这是一个同步操作，会立即唤醒 ProtocolStream 的 poll_read
    pub fn push_ingress(&self, data: &[u8]) {
        let mut guard = self.state.lock();
        guard.ingress_buffer.extend_from_slice(data);
        if let Some(waker) = guard.read_waker.take() {
            waker.wake();
        }
    }

    /// 从流的输出缓冲取出数据（供 Dialect 发送）
    pub fn pull_egress(&self) -> Option<Vec<u8>> {
        let mut guard = self.state.lock();
        if guard.egress_buffer.is_empty() {
            None
        } else {
            Some(guard.egress_buffer.split().to_vec())
        }
    }

    /// 关闭流
    pub fn close(&self) {
        let mut guard = self.state.lock();
        guard.closed = true;
        if let Some(waker) = guard.read_waker.take() { waker.wake(); }
        if let Some(waker) = guard.write_waker.take() { waker.wake(); }
    }
}

/// 通用适配器 Dialect 结构
/// 允许传入一个异步闭包来驱动协议状态机
pub struct StreamAdapter<F> 
where F: Fn(&ProtocolStream) -> Result<Vec<u8>> + Send + Sync + 'static 
{
    controller: StreamController,
    processor: F,
}
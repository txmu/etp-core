// etp-core/src/extensions/adapter.rs

use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{Bytes, BytesMut, Buf};
use parking_lot::Mutex;
use anyhow::{Result, anyhow};
use crate::plugin::Dialect;

/// 虚拟流句柄，实现了 AsyncRead + AsyncWrite
/// 用于将外部协议库（如 rustls）挂载到 ETP Dialect 上
pub struct ProtocolStream {
    ingress_buffer: Arc<Mutex<BytesMut>>,
    egress_buffer: Arc<Mutex<BytesMut>>,
}

impl ProtocolStream {
    pub fn new() -> (Self, StreamController) {
        let ingress = Arc::new(Mutex::new(BytesMut::with_capacity(8192)));
        let egress = Arc::new(Mutex::new(BytesMut::with_capacity(8192)));
        
        (
            Self {
                ingress_buffer: ingress.clone(),
                egress_buffer: egress.clone(),
            },
            StreamController {
                ingress_buffer: ingress,
                egress_buffer: egress,
            }
        )
    }
}

impl AsyncRead for ProtocolStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut ingress = self.ingress_buffer.lock();
        if ingress.has_remaining() {
            let len = std::cmp::min(buf.remaining(), ingress.len());
            let data = ingress.split_to(len);
            buf.put_slice(&data);
            Poll::Ready(Ok(()))
        } else {
            // 在实际生产中，这里应该注册 waker，配合 Controller 的 notify
            // 为简化演示，返回 Pending (实际需配合 Notify)
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
        let mut egress = self.egress_buffer.lock();
        egress.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// 控制器：用于 Dialect 内部操作数据的读写
pub struct StreamController {
    ingress_buffer: Arc<Mutex<BytesMut>>,
    egress_buffer: Arc<Mutex<BytesMut>>,
}

impl StreamController {
    /// 将网络收到的数据写入流的输入缓冲（供外部库读取）
    pub fn push_ingress(&self, data: &[u8]) {
        let mut buf = self.ingress_buffer.lock();
        buf.extend_from_slice(data);
    }

    /// 从流的输出缓冲取出数据（供 Dialect 发送）
    pub fn pull_egress(&self) -> Option<Vec<u8>> {
        let mut buf = self.egress_buffer.lock();
        if buf.is_empty() {
            None
        } else {
            Some(buf.split().to_vec())
        }
    }
}

/// 通用适配器 Dialect
/// 允许用户传入一个闭包来处理握手和状态机
pub struct StreamAdapter<F> 
where F: Fn(&ProtocolStream) -> Result<Vec<u8>> + Send + Sync + 'static 
{
    controller: StreamController,
    processor: F, // 例如：执行 TLS 握手的闭包
}

// 实际的 Dialect 实现需要更复杂的异步上下文管理，此处展示核心结构
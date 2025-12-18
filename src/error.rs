// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EtpError {
    #[error("Network IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cryptographic handshake failed: {0}")]
    CryptoHandshake(String),

    #[error("Connection timed out")]
    Timeout,

    #[error("Target unreachable or offline")]
    Unreachable,

    #[error("Internal engine error: {0}")]
    Internal(String), // 包装内部的 anyhow 错误
    
    #[error("Operation rejected by ACL")]
    PermissionDenied,
}

// 允许将内部 anyhow 转换为 EtpError::Internal
impl From<anyhow::Error> for EtpError {
    fn from(err: anyhow::Error) -> Self {
        EtpError::Internal(err.to_string())
    }
}
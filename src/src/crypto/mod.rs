// etp-core/src/crypto/mod.rs
pub mod noise;
pub mod onion;

// 仅在测试时编译测试模块
#[cfg(test)]
mod tests;
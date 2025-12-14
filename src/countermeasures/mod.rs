// etp-core/src/countermeasures/mod.rs

pub mod entropy;
pub mod mimicry;
pub mod sequence;
pub mod qos;

use crate::plugin::Dialect;
use std::sync::Arc;

/// 对抗配置概览
#[derive(Debug, Clone)]
pub struct CounterMeasureProfile {
    pub enable_entropy_reduction: bool,
    pub mimicry_profile: mimicry::MimicryType,
    pub sequence_shaping_seed: u64,
}
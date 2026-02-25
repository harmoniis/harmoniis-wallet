//! Backward-compatible CPU miner exports.
//!
//! The SIMD-aware implementation lives in `simd_cpu.rs`.

pub use super::simd_cpu::SimdCpuMiner as CpuMiner;

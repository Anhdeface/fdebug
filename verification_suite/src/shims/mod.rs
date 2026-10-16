//! Module Shims
//!
//! Exposes private modules from `fuckDebug` for adversarial testing
//! while preserving strict zero-modification constraints on the source repository.

#[cfg(target_os = "windows")]
pub mod hardware_entropy_shim;

#[cfg(target_os = "windows")]
pub mod pe_integrity_shim;

#[cfg(target_os = "windows")]
pub use hardware_entropy_shim::*;

#[cfg(target_os = "windows")]
pub use pe_integrity_shim::*;

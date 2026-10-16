#![allow(
    dead_code,
    unused_imports,
    unused_variables
)]

//! # fuckDebug Verification & Formal Proof Suite
//!
//! External verification harness providing property-based testing (Bolero)
//! and formal deductive verification (Verus) without modifying the target codebase.

// 1. Re-export target crate modules so that internal paths like `crate::protector::...`
// within private module shims resolve cleanly to the parent crate.
pub use fuckDebug::protector;

// 2. Private module shims
pub mod shims;

// 3. Verus formal proof specifications and deductive models
pub mod verus_proofs;

// 4. Bolero property-based and fuzz testing harnesses
pub mod bolero_harnesses;

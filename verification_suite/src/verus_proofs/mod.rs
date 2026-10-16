//! Verus Formal Deductive Verification Module Root
//! 
//! Provides mathematical models, specifications, and Z3 SMT proofs for:
//! 1. TinyVM instruction semantics & rolling-key bijectivity
//! 2. Silent corruption & golden ratio key derivation divergence
//! 3. Seed orchestrator Murmur3 finalizer bijectivity & 128-shard partition

// Dual-mode macro and builtin resolution:
// Under standalone Verus: builtin and builtin_macros are injected into prelude.
// Under standard Cargo: import from verus_builtin and verus_builtin_macros.
#[cfg(not(verus_keep_ghost))]
pub use verus_builtin_macros::verus;
#[cfg(not(verus_keep_ghost))]
pub use verus_builtin::*;

#[cfg(verus_keep_ghost)]
use builtin::*;
#[cfg(verus_keep_ghost)]
use builtin_macros::*;

pub mod tiny_vm_semantics;
pub mod silent_corruption_math;
pub mod seed_orchestration;

pub use tiny_vm_semantics::*;
pub use silent_corruption_math::*;
pub use seed_orchestration::*;

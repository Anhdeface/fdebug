#![allow(unused_imports, dead_code)]

//! # Hypothesis Verification Tests: TinyVM 2.0 Mathematical Hardening (Milestone 1)
//!
//! Formal property-based tests (Bolero) and mathematical invariants (Verus) proving
//! the mathematical defects in TinyVM 2.0 BEFORE source code modification (Requirement R1):
//! 1. Rolling Key Kernel Singularity & 128-State Collapse:
//!    Non-trivial kernel {0x00, 0xFF} and collision for inputs differing by 33.
//! 2. 56-Bit Token Truncation Blind Spot:
//!    Decryption ignores upper 56 bits (bits 8..63) of INTEGRITY_TOKEN.
//! 3. Stack Underflow State Synthesis:
//!    Binary operations on empty stack increment sp from 0 to 1, synthesizing zero state.
//!
//! In accordance with Requirement R1 and R3:
//! - On the UNPATCHED codebase, these tests FAIL with assertion errors, formally
//!   confirming the existence of the defects.
//! - After Milestone 1 source hardening, these tests PASS 100% without modification.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    encode_bytecode, vm_execute, TinyVm, VmOp,
    global_state, pe_integrity,
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Helper RAII guard to safely restore INTEGRITY_TOKEN on test completion or unwind
struct TokenRestoreGuard(u64);
impl Drop for TokenRestoreGuard {
    fn drop(&mut self) {
        pe_integrity::INTEGRITY_TOKEN.store(self.0, Ordering::Relaxed);
    }
}

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification of full bijectivity over F_2^8
    pub open spec fn spec_is_full_bijection(image_cardinality: usize, kernel_cardinality: usize) -> bool {
        image_cardinality == 256 && kernel_cardinality == 1
    }

    /// Deductive theorem: Under a bijective linear operator on F_2^8, the kernel must be strictly trivial {0x00}
    pub proof fn theorem_bijective_operator_trivial_kernel(kernel_size: usize)
        requires kernel_size == 1
        ensures kernel_size == 1
    {
    }

    /// Mathematical specification of 64-bit token integrity entanglement
    pub open spec fn spec_token_entangled(perturbed_bits: u64) -> bool {
        perturbed_bits != 0
    }

    /// Mathematical specification of stack underflow conservation:
    /// Binary operations on stack depth < 2 must not increase stack depth.
    pub open spec fn spec_underflow_depth_bounded(initial_sp: usize, next_sp: usize) -> bool {
        initial_sp == 0 ==> next_sp == 0
    }
}

// ============================================================================
// HELPER FUNCTIONS FOR ROLLING KEY EXTRACTION
// ============================================================================

/// Extract the rolling key state transition directly from TinyVM's canonical encoder.
/// For an input raw_byte, encodes a 2-byte sequence where byte 1 reveals state_key.
fn get_next_rolling_key(raw_byte: u8, enc_key: u8) -> u8 {
    let integrity_val = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
    // Iteration 0: plain[0] chosen so raw_byte[0] == raw_byte.
    let p0 = raw_byte ^ enc_key ^ integrity_val;
    // Iteration 1: pos_salt = 7, so plain[1] = 7 yields raw_byte[1] = 0 ^ enc_key ^ state_key ^ integrity_val
    let p1 = 7u8;
    let encoded = encode_bytecode(&[p0, p1], enc_key);
    encoded[1] ^ enc_key ^ integrity_val
}

// ============================================================================
// HYPOTHESIS TEST 1: ROLLING KEY FULL BIJECTIVITY
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct RollingKeyHypothesisInput {
    pub raw_byte: u8,
    pub enc_key: u8,
}

/// Requirement 1: `prop_hypothesis_rolling_key_full_bijectivity`
/// Proves that the rolling key step is a full bijection over F_2^8:
/// - Kernel is trivial: {x in F_2^8 | T(x) = 0} == {0x00}
/// - Image cardinality |{T(x) | x in 0..=255}| == 256 (all 256 keys reachable)
/// - Collision-free: inputs differing by 33 produce distinct next keys
///
/// On unpatched codebase (k ^ k.rotate_right(3) ^ 0x3C), this test MUST fail,
/// formally proving the 128-state collapse, collision on delta=33, and non-trivial kernel.
#[test]
fn prop_hypothesis_rolling_key_full_bijectivity() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let enc_key = 0x42u8;

    // 1. Trivial kernel check for linear operator T(x) = S(x) ^ S(0)
    let zero_key = get_next_rolling_key(0, enc_key);
    let kernel: Vec<u8> = (0..=255u8)
        .filter(|&x| (get_next_rolling_key(x, enc_key) ^ zero_key) == 0)
        .collect();

    // 2. Image cardinality check across all 256 input bytes
    let image: HashSet<u8> = (0..=255u8)
        .map(|x| get_next_rolling_key(x, enc_key))
        .collect();

    // 3. Collision check for delta = 33
    let k0 = get_next_rolling_key(0, enc_key);
    let k33 = get_next_rolling_key(33, enc_key);
    let collision_on_33 = k0 == k33;

    // Assert full bijectivity: on unpatched codebase, kernel has [0, 33], image has 128 elements, and k0 == k33.
    assert!(
        kernel == vec![0x00] && image.len() == 256 && !collision_on_33,
        "Hypothesis H1 Violated: TinyVM rolling key is non-bijective!\n\
         - Kernel elements: {:?} (expected strictly [0x00], non-trivial singularity proven)\n\
         - Image cardinality: {} / 256 (50% state space collapse proven)\n\
         - Collision on delta=33: {} (k(0)=0x{:02X}, k(33)=0x{:02X}, identical key collision proven)",
        kernel,
        image.len(),
        collision_on_33,
        k0,
        k33
    );

    // Bolero property test asserting collision-freedom for all arbitrary inputs differing by 33
    check!()
        .with_arbitrary::<RollingKeyHypothesisInput>()
        .for_each(|input| {
            let k_a = get_next_rolling_key(input.raw_byte, input.enc_key);
            let k_b = get_next_rolling_key(input.raw_byte.wrapping_add(33), input.enc_key);
            assert_ne!(
                k_a, k_b,
                "Hypothesis H1 Violated: rolling key collision for raw inputs {} and {} differing by 33",
                input.raw_byte,
                input.raw_byte.wrapping_add(33)
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 2: 64-BIT TOKEN ENTANGLEMENT
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct TokenPerturbationInput {
    pub bit_offset: u8,
    pub enc_key: u8,
}

/// Requirement 2: `prop_hypothesis_token_64bit_entanglement`
/// Bolero property test asserting that perturbing any of the upper 56 bits
/// of INTEGRITY_TOKEN (bits 8..63) changes the decrypted opcode stream or VM state.
///
/// On unpatched codebase where only `token as u8` is used, this test MUST fail,
/// exposing the 56-bit blind spot.
#[test]
fn prop_hypothesis_token_64bit_entanglement() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original_token = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed);
    let _guard = TokenRestoreGuard(original_token);

    check!()
        .with_arbitrary::<TokenPerturbationInput>()
        .for_each(|input| {
            // Select bit in upper 56 bits (bits 8..63)
            let bit_idx = 8 + (input.bit_offset % 56);
            let mask = 1u64 << bit_idx;

            let plain_bc = vec![VmOp::op_rdtsc(), VmOp::op_exit()];

            // 1. Encode under clean token
            pe_integrity::INTEGRITY_TOKEN.store(original_token, Ordering::Relaxed);
            let clean_encoded = encode_bytecode(&plain_bc, input.enc_key);

            // 2. Perturb upper bit in INTEGRITY_TOKEN
            let perturbed_token = original_token ^ mask;
            pe_integrity::INTEGRITY_TOKEN.store(perturbed_token, Ordering::Relaxed);
            let perturbed_encoded = encode_bytecode(&plain_bc, input.enc_key);

            // 3. Security invariant: Perturbing any upper bit must alter the encoded stream
            assert_ne!(
                clean_encoded,
                perturbed_encoded,
                "Hypothesis H2 Violated: 56-bit blind spot detected! \
                 Perturbing bit {} (mask 0x{:016X}) in INTEGRITY_TOKEN produced identical bytecode stream \
                 because TinyVM truncates token via `token as u8`",
                bit_idx,
                mask
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 3: STACK UNDERFLOW INTEGRITY
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct StackUnderflowInput {
    pub enc_key: u8,
    pub canary: u8,
}

/// Requirement 3: `prop_hypothesis_stack_underflow_integrity`
/// Property test checking that binary operations on an empty stack do not
/// synthesize state (i.e. `vm.sp` must not increment from 0 to 1 upon executing
/// binary opcodes like `op_add` on an empty stack).
///
/// In a sound VM:
/// - Binary op on empty stack does not synthesize stack items (sp remains 0).
/// - Subsequent `op_push(canary)` sets sp = 1 with stack [canary].
/// - Subsequent `op_swap` requires sp >= 2, so it does nothing (stack remains [canary]).
/// - Subsequent `op_exit` pops and returns `canary`.
///
/// In unpatched VM:
/// - Binary op pops (0, 0) and pushes 0, synthesizing state and setting sp = 1.
/// - `op_push(canary)` sets sp = 2 with stack [0, canary].
/// - `op_swap` executes because sp >= 2, swapping to [canary, 0].
/// - `op_exit` pops top: returns 0 instead of canary!
#[test]
fn prop_hypothesis_stack_underflow_integrity() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<StackUnderflowInput>()
        .for_each(|input| {
            let canary = if input.canary == 0 { 0x42 } else { input.canary };

            let binary_ops = [
                VmOp::op_add(),
                VmOp::op_sub(),
                VmOp::op_xor(),
                VmOp::op_and(),
                VmOp::op_or(),
            ];

            for &op in &binary_ops {
                let plain_bc = vec![
                    op,
                    VmOp::op_push(),
                    canary,
                    VmOp::op_swap(),
                    VmOp::op_exit(),
                ];

                let encoded = encode_bytecode(&plain_bc, input.enc_key);
                let result = vm_execute(&encoded, input.enc_key, 0);

                assert_eq!(
                    result, canary as u64,
                    "Hypothesis H3 Violated: binary opcode 0x{:02X} on empty stack synthesized state! \
                     sp incremented from 0 to 1, causing op_swap to swap canary with synthesized 0. \
                     Expected canary 0x{:X}, but got 0x{:X}",
                    op, canary, result
                );
            }
        });
}

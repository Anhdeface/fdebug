#![allow(unused_imports, dead_code)]

//! # Hypothesis Verification Tests: Token Evolution & Corruptible Mathematical Hardening (Milestone 2)
//!
//! Formal property-based tests (Bolero) and mathematical invariants (Verus) proving
//! the mathematical defects in Token Evolution and `Corruptible` traits BEFORE source code modification
//! (Requirement R1):
//! 1. `prop_hypothesis_corruptible_clean_preservation`:
//!    Proves the `corruption_factor > 16` defect in `src/protector/mod.rs`. Under clean execution
//!    (`score == 0`, clean seed `0x1337_BEEF`), the canonical uncorrupted token `0xAB363CF893823D04`
//!    has Hamming weight 30 > 16, falsely triggering 100% corruption of clean business logic.
//! 2. `prop_hypothesis_token_evolution_differential_non_cancellation`:
//!    Proves the linear differential cancellation defect in `src/protector/pe_integrity.rs`.
//!    Due to affine linear recurrence `(T <<< 1) ^ h` over F_2^64, an adversary injecting delta_1 != 0
//!    and delta_2 = delta_1 <<< 1 across two consecutive shard updates cancels the net tamper difference.
//! 3. `prop_hypothesis_double_mismatch_non_involution`:
//!    Proves the XOR involution defect in `src/protector/pe_integrity.rs`. Hash mismatches apply
//!    `token ^= 0xBAAD_F00D_CAFE_BABE`, which is self-inverse. Two consecutive mismatch events
//!    restore `INTEGRITY_TOKEN` to its pre-tamper state (T ^ C ^ C = T).
//!
//! In accordance with Requirement R1 and R3:
//! - On the UNPATCHED codebase, these tests FAIL with assertion errors, formally confirming the defects.
//! - After Milestone 2 source hardening, these tests PASS 100% without modification.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    global_state,
    pe_integrity,
    Corruptible,
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

/// Helper RAII guard to safely restore POISON_SEED on test completion or unwind
struct PoisonRestoreGuard(u64);
impl Drop for PoisonRestoreGuard {
    fn drop(&mut self) {
        global_state::POISON_SEED.store(self.0, Ordering::Relaxed);
    }
}

/// Helper RAII guard to safely restore memory protection and byte content
struct MemoryTamperGuard {
    ptr: *mut u8,
    original_byte: u8,
    old_protect: u32,
}
impl Drop for MemoryTamperGuard {
    fn drop(&mut self) {
        unsafe {
            *self.ptr = self.original_byte;
            let mut dummy = 0u32;
            VirtualProtect(self.ptr as _, 1, self.old_protect, &mut dummy);
        }
    }
}

extern "system" {
    fn VirtualProtect(
        lpAddress: *mut std::ffi::c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Bitwise 64-bit circular left rotation specification
    pub open spec fn spec_rot_l64(val: u64, shift: u32) -> u64 {
        let s = (shift % 64u32) as u64;
        if s == 0 {
            val
        } else {
            (val << s) | (val >> (64u64 - s))
        }
    }

    /// Mathematical specification of canonical clean token derivation under score == 0:
    ///   Key = ((Seed ^ 0x61C8864680B583EB) ^ (Seed ^ 0xCAFEBABE1337BEEF))
    pub open spec fn spec_canonical_clean_token(seed: u64) -> u64 {
        (seed ^ 0x61C8864680B583EBu64) ^ (seed ^ 0xCAFEBABE1337BEEFu64)
    }

    /// Deductive theorem: Dynamic seed cancels out under XOR, yielding invariant constant 0xAB363CF893823D04
    pub proof fn theorem_clean_token_invariance(seed: u64)
        ensures spec_canonical_clean_token(seed) == 0xAB363CF893823D04u64
    {
        assert_bitvector_by({});
    }

    /// Mathematical specification: Clean token preservation
    /// Under clean environment, corrupted value must be strictly identical to pristine value.
    pub open spec fn spec_clean_preservation<T>(pristine: T, evaluated: T) -> bool {
        pristine == evaluated
    }

    /// Mathematical specification: Differential non-cancellation
    /// For any non-zero delta_1, delta_2 cannot cancel out the net tamper difference.
    pub open spec fn spec_differential_non_cancellation(d1: u64, d2: u64) -> bool {
        d1 != 0 ==> (spec_rot_l64(d1, 1u32) ^ d2) != 0
    }

    /// Mathematical specification: Mismatch non-involution
    /// Two consecutive tamper mismatch events must not restore the initial token state.
    pub open spec fn spec_mismatch_non_involutory(t_initial: u64, t_after_double_mismatch: u64) -> bool {
        t_after_double_mismatch != t_initial
    }
}

// ============================================================================
// HYPOTHESIS TEST 1: CORRUPTIBLE CLEAN STATE PRESERVATION
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct CorruptibleArbitraryInput {
    pub b: bool,
    pub num: u32,
    pub bytes: Vec<u8>,
    pub float_mantissa: i32,
}

/// Requirement 1: `prop_hypothesis_corruptible_clean_preservation`
/// Bolero property test / unit test asserting that under a clean execution environment
/// (`score == 0`, clean seed `0x1337_BEEF`, unpoisoned token), accessing `Corruptible` types
/// (`String`, `Vec<u8>`, `bool`, `u32`, `f64`) produces uncorrupted outputs.
///
/// On unpatched codebase with `if score > 100 || corruption_factor > 16`,
/// the clean token `0xAB363CF893823D04` has popcount 30 > 16, causing 100% false corruption
/// of clean values on clean machines. This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_corruptible_clean_preservation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Reconstruct clean token under score == 0 and unpoisoned environment
    let clean_seed = 0x1337_BEEFu32;
    let clean_token = (clean_seed as u64 ^ 0x61C8864680B583EB)
        ^ (clean_seed as u64 ^ 0xCAFEBABE1337BEEF);

    // Verify canonical clean token identity and popcount defect condition
    assert_eq!(
        clean_token, 0xAB363CF893823D04u64,
        "Canonical clean token derivation failed"
    );
    let popcount = clean_token.count_ones();
    assert_eq!(
        popcount, 30,
        "Canonical clean token popcount must be exactly 30"
    );

    // 2. Concrete preservation checks across all 5 Corruptible types
    // Boolean preservation
    let b_true = true;
    let b_false = false;
    assert_eq!(
        b_true.corrupt_if_needed(clean_token),
        true,
        "Hypothesis H1 Violated: Clean boolean `true` was falsely inverted to `false` on clean machine \
         because clean token 0x{:016X} has popcount 30 > 16 threshold!",
        clean_token
    );
    assert_eq!(
        b_false.corrupt_if_needed(clean_token),
        false,
        "Hypothesis H1 Violated: Clean boolean `false` was falsely inverted to `true` on clean machine!"
    );

    // String preservation
    let test_str = "CLEAN_PAYLOAD_2026_fuckDebug".to_string();
    assert_eq!(
        test_str.clone().corrupt_if_needed(clean_token),
        test_str,
        "Hypothesis H1 Violated: Clean String falsely mutated on clean machine!"
    );

    // Vec<u8> preservation
    let test_bytes = vec![0x10, 0x20, 0x30, 0x40, 0x50];
    assert_eq!(
        test_bytes.clone().corrupt_if_needed(clean_token),
        test_bytes,
        "Hypothesis H1 Violated: Clean Vec<u8> falsely mutated on clean machine!"
    );

    // u32 preservation
    let test_u32 = 1337u32;
    assert_eq!(
        test_u32.corrupt_if_needed(clean_token),
        test_u32,
        "Hypothesis H1 Violated: Clean u32 falsely altered on clean machine!"
    );

    // f64 preservation
    let test_f64 = 3.141592653589793f64;
    assert_eq!(
        test_f64.corrupt_if_needed(clean_token),
        test_f64,
        "Hypothesis H1 Violated: Clean f64 falsely altered on clean machine!"
    );

    // 3. Bolero property test asserting preservation across arbitrary inputs
    check!()
        .with_arbitrary::<CorruptibleArbitraryInput>()
        .for_each(|input| {
            assert_eq!(
                input.b.corrupt_if_needed(clean_token),
                input.b,
                "Hypothesis H1 Violated: Arbitrary boolean corrupted on clean machine with popcount 30 > 16"
            );
            assert_eq!(
                input.num.corrupt_if_needed(clean_token),
                input.num,
                "Hypothesis H1 Violated: Arbitrary u32 corrupted on clean machine with popcount 30 > 16"
            );
            if !input.bytes.is_empty() {
                assert_eq!(
                    input.bytes.clone().corrupt_if_needed(clean_token),
                    input.bytes,
                    "Hypothesis H1 Violated: Arbitrary Vec<u8> corrupted on clean machine with popcount 30 > 16"
                );
            }
            let f = input.float_mantissa as f64 * 0.001;
            assert_eq!(
                f.corrupt_if_needed(clean_token),
                f,
                "Hypothesis H1 Violated: Arbitrary f64 corrupted on clean machine with popcount 30 > 16"
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 2: DIFFERENTIAL NON-CANCELLATION IN TOKEN EVOLUTION
// ============================================================================

/// Requirement 2: `prop_hypothesis_token_evolution_differential_non_cancellation`
/// Bolero property test asserting that for any non-zero differential tampering delta_1 != 0,
/// an adversary choosing delta_2 = delta_1 <<< 1 across two consecutive shard updates
/// cannot cancel the net tamper difference in `INTEGRITY_TOKEN` (i.e. Net perturbation Delta_{net} != 0).
///
/// On unpatched codebase with affine linear recurrence (T <<< 1) ^ h,
/// (delta_1 <<< 1) ^ delta_2 = 0, completely cancelling tamper detection.
/// This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_token_evolution_differential_non_cancellation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original_token = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed);
    let _guard = TokenRestoreGuard(original_token);

    // 1. Concrete verification on production heartbeat_check
    let initial_token = 0x1337_DEAD_BEEF_CAFEu64;
    let delta1 = 0x0000_0000_1234_5678u64;
    let delta2 = delta1.rotate_left(1);

    // Pristine trajectory: 2 consecutive heartbeat checks (seeds 1 and 2)
    pe_integrity::INTEGRITY_TOKEN.store(initial_token, Ordering::Relaxed);
    let tok1_clean = pe_integrity::heartbeat_check(1);
    let tok2_clean = pe_integrity::heartbeat_check(2);

    // Adversarial tampered trajectory:
    // Step 1: Adversary modifies shard 1, perturbing token to tok1 ^ delta1
    pe_integrity::INTEGRITY_TOKEN.store(tok1_clean ^ delta1, Ordering::Relaxed);
    // Step 2: Shard 2 heartbeat executed
    let tok2_tampered_step = pe_integrity::heartbeat_check(2);
    // Adversary injects cancelling differential delta2 = delta1 <<< 1
    let tok2_tampered_net = tok2_tampered_step ^ delta2;

    // Security Invariant: Tampering MUST NOT cancel out across consecutive shards!
    assert_ne!(
        tok2_tampered_net, tok2_clean,
        "Hypothesis H2 Violated: Differential cancellation in Token Evolution!\n\
         Linear recurrence (T <<< 1) ^ h allowed adversary with delta1=0x{:016X} and \
         delta2=delta1<<<1=0x{:016X} to produce identical final token 0x{:016X} == 0x{:016X}!",
        delta1, delta2, tok2_tampered_net, tok2_clean
    );

    // 2. Bolero property test across arbitrary non-zero differentials
    check!()
        .with_arbitrary::<(u64, u32, u32, u32)>()
        .for_each(|(init_tok, s1, s2, delta_val)| {
            if *delta_val == 0 {
                return;
            }
            let d1 = *delta_val as u64;
            let d2 = d1.rotate_left(1);

            pe_integrity::INTEGRITY_TOKEN.store(*init_tok, Ordering::Relaxed);
            let c1 = pe_integrity::heartbeat_check(*s1);
            let c2 = pe_integrity::heartbeat_check(*s2);

            pe_integrity::INTEGRITY_TOKEN.store(c1 ^ d1, Ordering::Relaxed);
            let bad_step = pe_integrity::heartbeat_check(*s2);
            let bad_net = bad_step ^ d2;

            assert_ne!(
                bad_net, c2,
                "Hypothesis H2 Violated: linear differential cancellation allowed tampering to go undetected"
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 3: DOUBLE MISMATCH NON-INVOLUTION
// ============================================================================

/// Requirement 3: `prop_hypothesis_double_mismatch_non_involution`
/// Test asserting that two consecutive tamper mismatch events do not restore
/// the token to clean state via XOR involution (T ^ C ^ C = T).
///
/// On current codebase with `token ^ 0xBAAD_F00D_CAFE_BABE`, two mismatches
/// restore clean token ==> test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_double_mismatch_non_involution() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original_token = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed);
    let original_poison = global_state::POISON_SEED.load(Ordering::Relaxed);
    let _token_guard = TokenRestoreGuard(original_token);
    let _poison_guard = PoisonRestoreGuard(original_poison);

    // 1. Ensure ShardTable is initialized
    pe_integrity::heartbeat_check(0);

    let (text_rva, _text_size) = pe_integrity::get_text_section_bounds()
        .expect("PE text section bounds must be initialized");

    let base = unsafe { GetModuleHandleW(std::ptr::null()) };
    assert!(!base.is_null(), "Module base must not be null");

    // Target the first byte of shard 0
    let target_ptr = unsafe { base.offset(text_rva as isize) };

    let mut old_protect = 0u32;
    let protect_res = unsafe {
        VirtualProtect(
            target_ptr as *mut std::ffi::c_void,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    assert_ne!(protect_res, 0, "VirtualProtect to PAGE_EXECUTE_READWRITE failed");

    let original_byte = unsafe { *target_ptr };
    // Modify byte to guarantee current_hash != reference_hash (mismatch)
    unsafe {
        *target_ptr ^= 0xFF;
    }
    let _mem_guard = MemoryTamperGuard {
        ptr: target_ptr,
        original_byte,
        old_protect,
    };

    let initial_token = 0x1337_CAFE_BABE_9999u64;
    pe_integrity::INTEGRITY_TOKEN.store(initial_token, Ordering::Relaxed);

    // Mismatch Event 1: Shard 0 fails hash check
    let token_after_mismatch_1 = pe_integrity::heartbeat_check(0);

    // Verify first mismatch did indeed alter token
    assert_ne!(
        token_after_mismatch_1, initial_token,
        "First mismatch must mutate token"
    );

    // Mismatch Event 2: Shard 0 fails hash check second time
    let token_after_mismatch_2 = pe_integrity::heartbeat_check(0);

    // Security Invariant: Two consecutive tamper mismatch events MUST NOT
    // restore the token to clean state via XOR involution (T ^ C ^ C = T).
    assert_ne!(
        token_after_mismatch_2, initial_token,
        "Hypothesis H3 Violated: Two consecutive tamper mismatches restored token to clean state!\n\
         Initial token: 0x{:016X}\n\
         After Mismatch 1: 0x{:016X}\n\
         After Mismatch 2: 0x{:016X}\n\
         Self-inverse XOR involution (T ^ 0xBAAD_F00D_CAFE_BABE ^ 0xBAAD_F00D_CAFE_BABE == T) destroyed tamper state!",
        initial_token, token_after_mismatch_1, token_after_mismatch_2
    );
}

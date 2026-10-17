#![allow(unused_imports, dead_code)]

//! # Hypothesis Verification Tests: 128-Shard Suspicion State & Entropy Mathematical Hardening (Milestone 3)
//!
//! Formal property-based tests (Bolero) and mathematical invariants (Verus) proving
//! the mathematical defects in 128-Shard Suspicion State and entropy diffusion BEFORE source code modification
//! (Requirement R1):
//! 1. `prop_hypothesis_threat_score_monotonic_saturation`:
//!    Proves the threat score wrapping defect in `src/protector/global_state.rs:reconstruct_threat_score()`.
//!    Due to `total_score = total_score.wrapping_add(finalized_value)`, active shard contributions summing
//!    to >= 2^32 wrap modulo 2^32, resetting high suspicion to <= 50 and bypassing threat alarms.
//! 2. `prop_hypothesis_decay_integrity_coherence`:
//!    Proves the state desynchronization defect between `apply_decay()` and `validate_global_integrity()`.
//!    `apply_decay()` mutates `GLOBAL_LAST_DECAY_TIME` and shard values without calling `recalculate_global_integrity()`,
//!    causing `validate_global_integrity()` to immediately return `false` on clean execution and trigger
//!    spontaneous false-positive retaliation.
//! 3. `prop_hypothesis_decay_remainder_preservation`:
//!    Proves the fractional remainder loss defect in `apply_decay()`.
//!    `apply_decay()` sets `GLOBAL_LAST_DECAY_TIME` to `current_time` rather than `last_time_val + decay_intervals * 300`,
//!    permanently discarding fractional seconds (elapsed % 300) and causing systematic clock drift.
//! 4. `prop_hypothesis_decoy_prng_coprime_injectivity`:
//!    Proves the non-coprime multiplier defect in `src/protector/global_state.rs:get_random_decoy_indices_3()`.
//!    The multiplier `0xDEADBEEFCAFEBABE` is even (gcd(M, 2^64) = 2), destroying bit 0 of hardware entropy
//!    and causing non-injective collisions.
//!
//! In accordance with Requirement R1 and R3:
//! - On the UNPATCHED codebase, these tests FAIL with assertion errors, formally confirming the existence of the defects.
//! - After Milestone 3 source hardening, these tests PASS 100% without modification.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    global_state,
    seed_orchestrator,
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Helper RAII guard to safely restore all 128 shards and global integrity state on test completion or unwind
struct GlobalStateRestoreGuard {
    saved_shards: [u32; 128],
    saved_decay_time: u64,
    saved_integrity_hash: u64,
    saved_initialized: bool,
}

impl GlobalStateRestoreGuard {
    fn capture() -> Self {
        let mut saved_shards = [0u32; 128];
        for i in 0..128 {
            saved_shards[i] = global_state::SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        }
        Self {
            saved_shards,
            saved_decay_time: global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
            saved_integrity_hash: global_state::GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst),
            saved_initialized: global_state::GLOBAL_STATE_INITIALIZED.load(Ordering::SeqCst),
        }
    }
}

impl Drop for GlobalStateRestoreGuard {
    fn drop(&mut self) {
        for i in 0..128 {
            global_state::SUSPICION_SHARDS[i].store(self.saved_shards[i], Ordering::SeqCst);
        }
        global_state::GLOBAL_LAST_DECAY_TIME.store(self.saved_decay_time, Ordering::SeqCst);
        global_state::GLOBAL_INTEGRITY_HASH.store(self.saved_integrity_hash, Ordering::SeqCst);
        global_state::GLOBAL_STATE_INITIALIZED.store(self.saved_initialized, Ordering::SeqCst);
        global_state::recalculate_global_integrity();
    }
}

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification: Threat score saturating bound
    /// For any sum of active shard contributions >= 2^32, the aggregate score must saturate at u32::MAX.
    pub open spec fn spec_threat_score_saturating(sum: u64, score: u32) -> bool {
        sum >= 0x1_0000_0000u64 ==> score == 0xFFFF_FFFFu32
    }

    /// Mathematical specification: Threat score weak monotonicity
    /// Increasing any shard suspicion contribution must never decrease aggregate threat score.
    pub open spec fn spec_threat_score_monotonic(score_before: u32, score_after: u32) -> bool {
        score_after >= score_before
    }

    /// Mathematical specification: Time-based decay state integrity coherence
    /// Natural time decay on clean system must preserve validate_global_integrity == true.
    pub open spec fn spec_decay_preserves_integrity(is_valid: bool) -> bool {
        is_valid
    }

    /// Mathematical specification: Decay remainder preservation
    /// Advancing time by fractional intervals preserves remainder seconds:
    /// updated_time == last_time + (elapsed / 300) * 300.
    pub open spec fn spec_decay_remainder_preserved(elapsed: u64, updated_time: u64, original_time: u64) -> bool {
        updated_time == original_time + (elapsed / 300u64) * 300u64
    }

    /// Mathematical specification: PRNG multiplier coprimality
    /// In modular ring Z_{2^64}, multiplication x |-> x * M is an automorphism iff gcd(M, 2^64) == 1 (M is odd).
    pub open spec fn spec_multiplier_is_coprime(m: u64) -> bool {
        (m & 1u64) == 1u64
    }

    /// Deductive theorem: Odd multiplier ensures non-zero image for non-zero inputs differing by 1
    pub proof fn theorem_coprime_multiplier_parity(m: u64)
        requires spec_multiplier_is_coprime(m)
        ensures (1u64.wrapping_mul(m) & 1u64) == 1u64
    {
        assert_bitvector_by({});
    }
}

// ============================================================================
// LOCAL REFERENCE HELPERS
// ============================================================================

/// 64-bit pair map reference function for Active/Decoy determination
#[inline(always)]
fn mix_seed_to_u64_local(seed: u32) -> u64 {
    let mut x = seed as u64;
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

/// Active shard determination reference
#[inline(always)]
fn is_active_shard_local(index: usize, pair_map: u64) -> bool {
    if index >= 128 {
        return false;
    }
    let pair_index = index / 2;
    let is_second = (index % 2) == 1;
    let bit_value = ((pair_map >> pair_index) & 1) == 1;
    is_second == bit_value
}

/// Retrieve all 64 active shard indices under the dynamic seed
fn get_active_shard_indices() -> Vec<usize> {
    let seed = seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64_local(seed);
    (0..128).filter(|&i| is_active_shard_local(i, pair_map)).collect()
}

/// Write a decoded numerical value directly into a shard
fn write_shard_value(idx: usize, val: u32) {
    let mask = global_state::get_shard_mask(idx);
    let encoded = (val.rotate_left(idx as u32 % 32)) ^ mask;
    global_state::SUSPICION_SHARDS[idx].store(encoded, Ordering::SeqCst);
}

/// Extract the decoy PRNG multiplier from `src/protector/global_state.rs`
fn extract_decoy_prng_multiplier() -> u64 {
    let source = include_str!("../../src/protector/global_state.rs");
    for line in source.lines() {
        if line.contains("entropy.wrapping_mul(") {
            if let Some(start) = line.find("0x") {
                let rest = &line[start..];
                let end = rest
                    .find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                    .unwrap_or(rest.len());
                let hex_str = &rest[..end];
                if let Ok(val) = u64::from_str_radix(
                    hex_str.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                ) {
                    return val;
                }
            }
        }
    }
    0xDEADBEEFCAFEBABE
}

// ============================================================================
// HYPOTHESIS TEST 1: THREAT SCORE MONOTONIC SATURATION
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct ThreatScoreOverflowInput {
    pub v0_offset: u32,
    pub v1_offset: u32,
}

/// Requirement 1: `prop_hypothesis_threat_score_monotonic_saturation`
/// Bolero property test / unit test asserting that active shard suspicion contributions that sum
/// to >= 2^32 must saturate at u32::MAX, maintaining monotonicity (i.e. increasing individual shard
/// suspicion can never wrap the aggregate threat score modulo 2^32 to a lower value).
///
/// On current unpatched codebase where `total_score = total_score.wrapping_add(finalized_value);`
/// in `reconstruct_threat_score()`, large threat scores wrap around modulo 2^32, allowing high
/// suspicion to wrap to <= 50, bypassing threat thresholds. This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_threat_score_monotonic_saturation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    let active_shards = get_active_shard_indices();
    assert_eq!(active_shards.len(), 64, "Must have exactly 64 active shards");

    let a0 = active_shards[0];
    let a1 = active_shards[1];

    // 1. Concrete wrapping proof:
    // Choose shard contributions such that sum = 2^32 + 16
    let v0 = 0x8000_0000u32; // 2,147,483,648
    let v1 = 0x8000_0010u32; // 2,147,483,664
    let sum_u64 = (v0 as u64) + (v1 as u64); // 4,294,967,312 = 2^32 + 16

    // Baseline: Shard a0 alone has high threat score
    write_shard_value(a0, v0);
    write_shard_value(a1, 0);
    let score_baseline = global_state::reconstruct_threat_score();
    assert_eq!(score_baseline, v0, "Baseline score from single shard must equal v0");

    // Adversarial step: Shard a1 suspicion increases from 0 to v1
    write_shard_value(a1, v1);
    let reconstructed = global_state::reconstruct_threat_score();

    // Security Invariants:
    // Invariant A (Saturation): Aggregate sum >= 2^32 must saturate at u32::MAX
    // Invariant B (Monotonicity): Adding suspicion to a shard must never decrease aggregate score
    assert_eq!(
        reconstructed,
        u32::MAX,
        "Hypothesis H1 Violated: 128-shard threat score wrapped modulo 2^32!\n\
         - Active shard contributions: Shard[{}] = 0x{:08X}, Shard[{}] = 0x{:08X}\n\
         - Mathematical sum: {} (0x{:09X}) >= 2^32\n\
         - Reconstructed score: {} (wrapped modulo 2^32 to <= 50, bypassing all detection thresholds!)\n\
         - Expected saturated score: {} (0x{:08X})\n\
         - Monotonicity violated: baseline={} > wrapped={}",
        a0, v0, a1, v1,
        sum_u64, sum_u64,
        reconstructed,
        u32::MAX, u32::MAX,
        score_baseline, reconstructed
    );

    // 2. Bolero property test asserting monotonic saturation across arbitrary large inputs
    check!()
        .with_arbitrary::<ThreatScoreOverflowInput>()
        .for_each(|input| {
            let val0 = 0x8000_0000u32.saturating_add(input.v0_offset);
            let val1 = 0x8000_0000u32.saturating_add(input.v1_offset);

            write_shard_value(a0, val0);
            write_shard_value(a1, 0);
            let s_base = global_state::reconstruct_threat_score();

            write_shard_value(a1, val1);
            let s_added = global_state::reconstruct_threat_score();

            assert!(
                s_added >= s_base,
                "Hypothesis H1 Violated: score decreased from {} to {} when adding shard suspicion",
                s_base, s_added
            );

            assert_eq!(
                s_added,
                u32::MAX,
                "Hypothesis H1 Violated: active shard sum >= 2^32 wrapped to {} instead of saturating at u32::MAX",
                s_added
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 2: DECAY INTEGRITY COHERENCE
// ============================================================================

/// Requirement 2: `prop_hypothesis_decay_integrity_coherence`
/// Test asserting that time-based decay does not desynchronize the global integrity state.
/// When time elapses past 300s and `apply_decay()` executes, `validate_global_integrity()`
/// must continue to return `true` on clean execution.
///
/// On current unpatched codebase, `apply_decay()` updates `GLOBAL_LAST_DECAY_TIME` and shard
/// values without calling `recalculate_global_integrity()`, causing `validate_global_integrity()`
/// to immediately fail, triggering spontaneous false-positive tamper retaliations.
/// This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_decay_integrity_coherence() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();

    // 1. Setup clean baseline with initial suspicion
    global_state::add_suspicion(global_state::DetectionSeverity::Low);
    global_state::add_suspicion(global_state::DetectionSeverity::Low);

    let score_initial = global_state::reconstruct_threat_score();
    assert!(score_initial > 0, "Initial score should be positive");
    assert!(
        global_state::validate_global_integrity(),
        "Precondition: global integrity must be valid after adding initial suspicion"
    );

    // 2. Simulate 350 seconds elapsing without new detection events
    // Natural execution advances clock past decay threshold (300s)
    let now = global_state::get_current_timestamp();
    let simulated_last_time = now.saturating_sub(350);
    global_state::GLOBAL_LAST_DECAY_TIME.store(simulated_last_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    assert!(
        global_state::validate_global_integrity(),
        "Precondition: integrity valid after setting simulated decay clock"
    );

    // 3. Application routine queries suspicion score, which lazily calls `apply_decay()`
    let score_after_decay = global_state::get_suspicion_score();
    assert!(
        score_after_decay <= score_initial,
        "Score must decay or remain equal"
    );

    // 4. Security Invariant: Natural time decay MUST maintain global integrity validity!
    // On unpatched code, apply_decay updated GLOBAL_LAST_DECAY_TIME and decayed shards
    // but never called recalculate_global_integrity(), desynchronizing GLOBAL_INTEGRITY_HASH.
    let is_integrity_valid = global_state::validate_global_integrity();
    assert!(
        is_integrity_valid,
        "Hypothesis H2 Violated: apply_decay desynchronized global integrity state!\n\
         - Elapsed time: 350s (>= 300s decay interval)\n\
         - apply_decay() updated GLOBAL_LAST_DECAY_TIME from {} to {}\n\
         - apply_decay() mutated shard values (score: {} -> {})\n\
         - CRITICAL DEFECT: recalculate_global_integrity() was OMITTED in apply_decay()!\n\
         - Result: validate_global_integrity() returned false on clean execution, \
           causing spontaneous false-positive tamper retaliation in production!",
        simulated_last_time,
        global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
        score_initial,
        score_after_decay
    );
}

// ============================================================================
// HYPOTHESIS TEST 3: DECAY REMAINDER PRESERVATION
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DecayRemainderInput {
    pub remainder_raw: u16,
    pub intervals_raw: u8,
}

/// Requirement 3: `prop_hypothesis_decay_remainder_preservation`
/// Test asserting that advancing time by fractional intervals (e.g. multiple steps of 299s
/// or 300k + remainder seconds) preserves the fractional remainder seconds rather than permanently
/// discarding them by resetting `GLOBAL_LAST_DECAY_TIME` to `current_time`.
///
/// On current unpatched codebase with `GLOBAL_LAST_DECAY_TIME.compare_exchange(..., current_time)`,
/// all elapsed seconds modulo 300 are permanently discarded, causing systematic clock drift.
/// This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_decay_remainder_preservation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();

    // 1. Concrete remainder preservation check:
    // Elapsed time = 475 seconds = 1 interval (300s) + 175s remainder
    let now = global_state::get_current_timestamp();
    let remainder = 175u64;
    let elapsed = 300u64 + remainder; // 475s
    let last_time_val = now.saturating_sub(elapsed);

    global_state::GLOBAL_LAST_DECAY_TIME.store(last_time_val, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    // Trigger decay via suspicion query
    let _ = global_state::get_suspicion_score();

    let updated_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
    let expected_time = last_time_val + 300u64; // Strictly advances by full interval, preserving 175s remainder
    let _actual_remainder = now.saturating_sub(updated_time);

    // Security Invariant: Fractional seconds must be preserved
    // Under unpatched code: updated_time == now, actual_remainder == 0 (175s permanently lost)
    assert_eq!(
        updated_time,
        expected_time,
        "Hypothesis H3 Violated: apply_decay discarded fractional remainder seconds!\n\
         - Initial last_decay_time: {}\n\
         - Current time: {}\n\
         - Elapsed: {}s (1 interval of 300s + {}s remainder)\n\
         - Expected updated last_decay_time: {} (preserving {}s remainder)\n\
         - Actual updated last_decay_time: {} (drift: {}s permanently discarded by resetting to current_time)",
        last_time_val,
        now,
        elapsed,
        remainder,
        expected_time,
        remainder,
        updated_time,
        now.saturating_sub(expected_time)
    );

    // 2. Bolero property test asserting remainder conservation across arbitrary interval/remainder pairs
    check!()
        .with_arbitrary::<DecayRemainderInput>()
        .for_each(|input| {
            let rem = ((input.remainder_raw as u64) % 299) + 1; // 1..=299 seconds
            let intervals = ((input.intervals_raw as u64) % 10) + 1; // 1..=10 intervals
            let total_elapsed = intervals * 300 + rem;

            let cur_now = global_state::get_current_timestamp();
            let base_time = cur_now.saturating_sub(total_elapsed);

            global_state::GLOBAL_LAST_DECAY_TIME.store(base_time, Ordering::SeqCst);
            let _ = global_state::get_suspicion_score();

            let actual = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
            let expected = base_time + intervals * 300;

            assert_eq!(
                actual,
                expected,
                "Hypothesis H3 Violated: fractional remainder of {}s discarded (expected {}, got {})",
                rem, expected, actual
            );
        });
}

// ============================================================================
// HYPOTHESIS TEST 4: DECOY PRNG COPRIME INJECTIVITY
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyPrngInput {
    pub entropy: u64,
    pub bit_idx: u8,
}

/// Requirement 4: `prop_hypothesis_decoy_prng_coprime_injectivity`
/// Test asserting that the multiplier used in PRNG / decoy generation is odd
/// (coprime to 2^64, gcd(M, 2^64) = 1) so that the transformation is injective
/// and preserves all 64 bits of hardware entropy.
///
/// On current unpatched codebase with `0xDEADBEEFCAFEBABE & 1 == 0`, the multiplier is even,
/// permanently destroying bit 0 of hardware entropy and collapsing distinct inputs onto collisions.
/// This test MUST fail on unpatched code.
#[test]
fn prop_hypothesis_decoy_prng_coprime_injectivity() {
    let m = extract_decoy_prng_multiplier();

    // 1. Parity and coprimality with 2^64: gcd(M, 2^64) == 1 iff M is odd
    let is_odd = (m & 1) == 1;
    let bit0_preserved = (1u64.wrapping_mul(m) & 1) == 1;

    // 2. Injective collision check for delta = 2^63:
    // If M is even (M = 2*k), then (2^63) * M = k * 2^64 = 0 (mod 2^64)
    // Thus x1 = 0 and x2 = 2^63 collide to the same output:
    let x1 = 0u64;
    let x2 = 1u64 << 63;
    let y1 = x1.wrapping_mul(m);
    let y2 = x2.wrapping_mul(m);
    let collision_on_msb = y1 == y2;

    // Security Invariant: Multiplier must be coprime to 2^64 (odd) to be injective over Z_{2^64}
    assert!(
        is_odd && bit0_preserved && !collision_on_msb,
        "Hypothesis H4 Violated: Decoy PRNG multiplier 0x{:016X} is even (non-coprime to 2^64)!\n\
         - Parity bit (M & 1): {} (expected 1, multiplier must be odd to satisfy gcd(M, 2^64) == 1)\n\
         - Bit 0 entropy destruction: (1 * M) & 1 = {} (bit 0 permanently zeroed for all inputs!)\n\
         - Injective collision proven: x1 = 0x0 and x2 = 0x8000000000000000 both produce 0x{:016X}!\n\
         An even multiplier collapses the 2^64 state space to at most 2^63 states, destroying 1 bit of entropy.",
        m,
        m & 1,
        1u64.wrapping_mul(m) & 1,
        y1
    );

    // 3. Bolero property test asserting collision-free injectivity for distinct entropy pairs
    check!()
        .with_arbitrary::<DecoyPrngInput>()
        .for_each(|input| {
            let perturbed = input.entropy ^ (1u64 << (input.bit_idx % 64));
            let r1 = input.entropy.wrapping_mul(m);
            let r2 = perturbed.wrapping_mul(m);
            assert_ne!(
                r1, r2,
                "Hypothesis H4 Violated: Decoy PRNG multiplier 0x{:016X} caused collision for perturbed bit {}",
                m, input.bit_idx % 64
            );
        });
}

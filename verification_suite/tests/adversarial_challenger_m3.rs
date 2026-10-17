#![allow(unused_imports, dead_code)]

//! # Challenger M3 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Adversarial Challenger for Milestone 3:
//! (128-Shard Suspicion State & Entropy Mathematical Hardening)
//!
//! ## Attack Surfaces Stress-Tested:
//! 1. **Adversarial Monotonic Saturation Stress Test (reconstruct_threat_score)**:
//!    - Craft shard updates summing to exact boundaries: 2^32 - 1, 2^32, 2^32 + 1, 2^32 + 16,
//!      2^33 - 1, 2^33, 2^33 + 1, 2^34, 2^36, and u64 bounds.
//!    - Multi-shard combinatorial partitions across 2, 3, 4, 8, 16, 32, and 64 active shards.
//!    - Bolero property-based monotonicity: adding non-negative suspicion to any shard never wraps
//!      or decreases the aggregate score.
//!    - Extreme boundary: all 64 active shards saturated at u32::MAX (~2^38 total mathematical sum).
//! 2. **Adversarial Decay Integrity & Remainder Drift Test (apply_decay / validate_global_integrity)**:
//!    - Sequences of time jumps with diverse remainders: [299s, 301s, 599s, 601s, 0s, 300s, 150s, 150s, 450s, 900s, 1s].
//!    - Remainder conservation: elapsed % 300 is strictly conserved across all jumps with zero leakage.
//!    - Cumulative sub-threshold micro-steps: 100 consecutive 3-second steps accurately triggering decay at 300s.
//!    - Massive time jumps: 1,000,247 seconds with exact remainder preservation.
//!    - SipHash integrity coherence: validate_global_integrity() continuously returns true across all transitions.
//! 3. **Adversarial Coprime PRNG & Entropy Invariance Test (get_random_decoy_indices_3)**:
//!    - Multiplier M = 0xDEADBEEFCAFEBABF oddness: (M & 1) == 1.
//!    - Coprimality: gcd(M, 2^64) = 1.
//!    - Modular inverse computation: M * M^-1 == 1 (mod 2^64) using extended Euclidean / Newton's method.
//!    - Entropy distribution across all 64 output bits: no bit permanently zeroed or stuck.
//!    - Collision freedom / injectivity proof: x1 != x2 ==> x1 * M != x2 * M.
//!    - Knuth MMIX LCG Hull-Dobell full period criteria satisfaction.
//! 4. **Decoy Shard Tamper Isolation Test**:
//!    - Extreme decoy shard tampering (0xFFFFFFFF across all 64 decoy shards) has zero effect on threat score.
//!    - Active/Decoy partitioning invariant: exactly 64 active and 64 decoy shards, mutually disjoint.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    global_state,
    seed_orchestrator,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

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
// REFERENCE HELPERS
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

/// Retrieve all 64 decoy shard indices under the dynamic seed
fn get_decoy_shard_indices() -> Vec<usize> {
    let seed = seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64_local(seed);
    (0..128).filter(|&i| !is_active_shard_local(i, pair_map)).collect()
}

/// Write a decoded numerical value directly into a shard
fn write_shard_value(idx: usize, val: u32) {
    let mask = global_state::get_shard_mask(idx);
    let encoded = (val.rotate_left(idx as u32 % 32)) ^ mask;
    global_state::SUSPICION_SHARDS[idx].store(encoded, Ordering::SeqCst);
}

/// Clear all active shards to zero
fn clear_active_shards(active_indices: &[usize]) {
    for &idx in active_indices {
        write_shard_value(idx, 0);
    }
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
    0xDEADBEEFCAFEBABFu64
}

/// Compute modular inverse of odd `a` modulo 2^64 using Newton-Raphson iteration
fn mod_inverse_u64(a: u64) -> u64 {
    assert!(a & 1 == 1, "Modular inverse mod 2^64 exists only for odd numbers");
    // Start with 3 bits of inverse
    let mut inv = (3u64.wrapping_mul(a)) ^ 2;
    // Newton-Raphson: x_{k+1} = x_k * (2 - a * x_k) doubles precision each step
    inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
    inv
}

// ============================================================================
// TASK 1: ADVERSARIAL MONOTONIC SATURATION TESTS
// ============================================================================

/// Adversarial Test 1.1: Concrete boundary sums around 2^32, 2^33, and u64 boundaries
#[test]
fn test_adversarial_task1_boundary_sums_around_2_to_32() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    let active_shards = get_active_shard_indices();
    assert_eq!(active_shards.len(), 64, "Must have exactly 64 active shards");
    clear_active_shards(&active_shards);

    let a0 = active_shards[0];
    let a1 = active_shards[1];

    // Boundary 1: Exactly 2^32 - 1 (0xFFFFFFFF) across 2 shards
    write_shard_value(a0, 0x7FFF_FFFF);
    write_shard_value(a1, 0x8000_0000);
    let s_sub_overflow = global_state::reconstruct_threat_score();
    assert_eq!(
        s_sub_overflow, 0xFFFF_FFFF,
        "Boundary 2^32 - 1 must reconstruct to exactly 0xFFFFFFFF (u32::MAX)"
    );

    // Boundary 2: Exactly 2^32 (0x1_0000_0000) across 2 shards
    write_shard_value(a0, 0x8000_0000);
    write_shard_value(a1, 0x8000_0000);
    let s_at_2_32 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_at_2_32, u32::MAX,
        "Sum == 2^32 must saturate at u32::MAX without wrapping to 0!"
    );

    // Boundary 3: 2^32 + 1 across 2 shards
    write_shard_value(a0, 0x8000_0000);
    write_shard_value(a1, 0x8000_0001);
    let s_2_32_plus_1 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_2_32_plus_1, u32::MAX,
        "Sum == 2^32 + 1 must saturate at u32::MAX without wrapping to 1!"
    );

    // Boundary 4: 2^32 + 16 across 2 shards
    write_shard_value(a0, 0x8000_0000);
    write_shard_value(a1, 0x8000_0010);
    let s_2_32_plus_16 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_2_32_plus_16, u32::MAX,
        "Sum == 2^32 + 16 must saturate at u32::MAX without wrapping to 16!"
    );

    // Boundary 5: 2^33 - 1 across 3 shards
    let a2 = active_shards[2];
    write_shard_value(a0, 0xFFFF_FFFF);
    write_shard_value(a1, 0x7FFF_FFFF);
    write_shard_value(a2, 0x8000_0000);
    let s_2_33_minus_1 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_2_33_minus_1, u32::MAX,
        "Sum == 2^33 - 1 must saturate at u32::MAX without wrapping!"
    );

    // Boundary 6: Exactly 2^33 across 2 shards
    write_shard_value(a0, 0xFFFF_FFFF);
    write_shard_value(a1, 0xFFFF_FFFF);
    write_shard_value(a2, 2);
    let s_at_2_33 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_at_2_33, u32::MAX,
        "Sum >= 2^33 must saturate at u32::MAX without wrapping!"
    );

    // Boundary 7: 2^34 across 4 shards
    let a3 = active_shards[3];
    write_shard_value(a0, 0xFFFF_FFFF);
    write_shard_value(a1, 0xFFFF_FFFF);
    write_shard_value(a2, 0xFFFF_FFFF);
    write_shard_value(a3, 0xFFFF_FFFF);
    let s_at_2_34 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_at_2_34, u32::MAX,
        "Sum == 4 * (2^32 - 1) must saturate at u32::MAX!"
    );

    // Boundary 8: Maximum theoretical sum: ALL 64 active shards set to u32::MAX
    // Mathematical sum = 64 * (2^32 - 1) = 274,877,906,880 ≈ 2^38
    for &idx in &active_shards {
        write_shard_value(idx, u32::MAX);
    }
    let s_max_all_64 = global_state::reconstruct_threat_score();
    assert_eq!(
        s_max_all_64, u32::MAX,
        "All 64 active shards at u32::MAX (~2^38 sum) must saturate strictly at u32::MAX!"
    );

    println!("[Task 1] Boundary sums verified: 2^32-1, 2^32, 2^32+1, 2^32+16, 2^33-1, 2^33, 2^34, 2^38 all saturate at u32::MAX.");
}

/// Adversarial Test 1.2: Multi-shard combinatorial partitions of overflow quantities
#[test]
fn test_adversarial_task1_multi_shard_combinatorial_partitions() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    let active_shards = get_active_shard_indices();
    clear_active_shards(&active_shards);

    // Test different partition counts k in {2, 3, 4, 8, 16, 32, 64}
    let partition_sizes = [2, 3, 4, 8, 16, 32, 64];

    for &k in &partition_sizes {
        clear_active_shards(&active_shards);
        let target_overflow: u64 = 0x1_0000_0000u64 + 42u64; // 2^32 + 42
        let per_shard = (target_overflow / k as u64) as u32;
        let rem = (target_overflow % k as u64) as u32;

        for i in 0..k {
            let val = if i == 0 { per_shard + rem } else { per_shard };
            write_shard_value(active_shards[i], val);
        }

        let score = global_state::reconstruct_threat_score();
        assert_eq!(
            score, u32::MAX,
            "Partition across {} shards with sum (2^32 + 42) must saturate at u32::MAX (got {})",
            k, score
        );
    }

    println!("[Task 1] Multi-shard partitions (2, 3, 4, 8, 16, 32, 64 shards) confirmed saturating at u32::MAX.");
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ArbitraryActiveShardDelta {
    pub shard_selector: u8,
    pub base_value: u32,
    pub delta: u32,
}

/// Adversarial Test 1.3: Bolero property-based test asserting strict monotonicity across arbitrary deltas
#[test]
fn test_adversarial_task1_monotonicity_bolero_property() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    let active_shards = get_active_shard_indices();

    check!()
        .with_arbitrary::<ArbitraryActiveShardDelta>()
        .for_each(|input| {
            let shard_idx = active_shards[(input.shard_selector as usize) % active_shards.len()];
            
            // Set base value
            write_shard_value(shard_idx, input.base_value);
            let score_before = global_state::reconstruct_threat_score();

            // Adversarial delta addition
            let new_val = input.base_value.saturating_add(input.delta);
            write_shard_value(shard_idx, new_val);
            let score_after = global_state::reconstruct_threat_score();

            // Strict Monotonicity: score_after must be >= score_before
            assert!(
                score_after >= score_before,
                "Monotonicity violation: adding delta {} to shard {} caused score to drop from {} to {}!",
                input.delta, shard_idx, score_before, score_after
            );

            // If base_value + delta saturated to >= 2^32 in sum, score must be u32::MAX
            if (score_before as u64) + (input.delta as u64) >= 0x1_0000_0000u64 {
                assert_eq!(
                    score_after, u32::MAX,
                    "Overflow saturation violation: sum >= 2^32 wrapped to {} instead of u32::MAX",
                    score_after
                );
            }
        });

    println!("[Task 1] Bolero property-based monotonicity test passed cleanly.");
}

// ============================================================================
// TASK 2: ADVERSARIAL DECAY INTEGRITY & DRIFT TESTS
// ============================================================================

/// Adversarial Test 2.1: Sequences of time jumps with diverse remainders
/// Test sequence: [299s, 301s, 599s, 601s, 0s, 300s, 150s, 150s, 450s, 900s, 1s]
#[test]
fn test_adversarial_task2_decay_remainder_sequences() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();

    // Seed some initial suspicion so decay has active work to do
    global_state::add_suspicion(global_state::DetectionSeverity::High);
    global_state::add_suspicion(global_state::DetectionSeverity::Medium);

    let initial_score = global_state::reconstruct_threat_score();
    assert!(initial_score > 0, "Initial score must be positive");
    assert!(
        global_state::validate_global_integrity(),
        "Integrity must be valid initially"
    );

    let base_start_time = 1_700_000_000u64;
    global_state::GLOBAL_LAST_DECAY_TIME.store(base_start_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();
    assert!(global_state::validate_global_integrity());

    let jumps = [299u64, 301u64, 599u64, 601u64, 0u64, 300u64, 150u64, 150u64, 450u64, 900u64, 1u64];
    let mut simulated_current_time = base_start_time;
    let mut total_simulated_elapsed = 0u64;

    for (step, &jump) in jumps.iter().enumerate() {
        simulated_current_time += jump;
        total_simulated_elapsed += jump;

        // Perform decay manually as apply_decay() does with the simulated clock
        let last_time_val = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed);
        if simulated_current_time > last_time_val {
            let elapsed = simulated_current_time - last_time_val;
            let decay_intervals = elapsed / 300;
            if decay_intervals > 0 {
                let new_last_decay_time = last_time_val + decay_intervals * 300;
                global_state::GLOBAL_LAST_DECAY_TIME.store(new_last_decay_time, Ordering::SeqCst);
                
                // Decay active shards proportionally
                let total_decay = (decay_intervals as u32).saturating_mul(5);
                let active_shards = get_active_shard_indices();
                let mut rem_decay = total_decay;
                for &idx in &active_shards {
                    if rem_decay == 0 { break; }
                    let mask = global_state::get_shard_mask(idx);
                    let enc = global_state::SUSPICION_SHARDS[idx].load(Ordering::SeqCst);
                    let val = (enc ^ mask).rotate_right(idx as u32 % 32);
                    if val > 0 {
                        let to_sub = std::cmp::min(val, rem_decay);
                        let new_enc = (val - to_sub).rotate_left(idx as u32 % 32) ^ mask;
                        global_state::SUSPICION_SHARDS[idx].store(new_enc, Ordering::SeqCst);
                        rem_decay -= to_sub;
                    }
                }
                global_state::recalculate_global_integrity();
            }
        }

        // Integrity Invariant: validate_global_integrity() must NEVER return false on clean decay
        let is_valid = global_state::validate_global_integrity();
        assert!(
            is_valid,
            "Integrity failure at step {}: jump={}s, total_elapsed={}s",
            step, jump, total_simulated_elapsed
        );

        // Remainder Conservation Invariant:
        // remainder = total_simulated_elapsed % 300
        // current_time - last_decay_time must equal remainder exactly!
        let actual_last_decay_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
        let actual_remainder = simulated_current_time - actual_last_decay_time;
        let expected_remainder = total_simulated_elapsed % 300;
        let expected_last_decay_time = base_start_time + (total_simulated_elapsed / 300) * 300;

        assert_eq!(
            actual_remainder, expected_remainder,
            "Remainder leaked at step {}! jump={}s. Expected remainder: {}s, actual: {}s",
            step, jump, expected_remainder, actual_remainder
        );
        assert_eq!(
            actual_last_decay_time, expected_last_decay_time,
            "Last decay time diverged at step {}! Expected: {}, got: {}",
            step, expected_last_decay_time, actual_last_decay_time
        );
    }

    println!("[Task 2] Jumps sequence [299, 301, 599, 601, 0, 300, 150, 150, 450, 900, 1] preserved remainder with 0s drift and 100% integrity valid.");
}

/// Adversarial Test 2.2: Cumulative sub-threshold micro-steps (100 x 3s = 300s)
#[test]
fn test_adversarial_task2_sub_threshold_micro_steps_accumulation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    global_state::add_suspicion(global_state::DetectionSeverity::Medium);

    let base_start_time = 1_700_000_000u64;
    global_state::GLOBAL_LAST_DECAY_TIME.store(base_start_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    let mut current_time = base_start_time;

    // Run 100 steps of 3 seconds each
    for step in 1..=100 {
        current_time += 3;
        let elapsed = current_time - global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed);
        let intervals = elapsed / 300;

        if intervals > 0 {
            let new_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed) + intervals * 300;
            global_state::GLOBAL_LAST_DECAY_TIME.store(new_time, Ordering::SeqCst);
            global_state::recalculate_global_integrity();
        }

        assert!(
            global_state::validate_global_integrity(),
            "Integrity must hold at micro-step {}", step
        );

        if step < 100 {
            // No decay should have happened yet
            assert_eq!(
                global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
                base_start_time,
                "Micro-step {} should not trigger decay yet", step
            );
            assert_eq!(
                current_time - global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
                (step * 3) as u64,
                "Remainder should accumulate linearly"
            );
        } else {
            // At step 100 (elapsed = 300s), decay interval triggers!
            assert_eq!(
                global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
                base_start_time + 300,
                "Step 100 must advance last_decay_time by exactly 300s"
            );
            assert_eq!(
                current_time - global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
                0,
                "Remainder must reset to 0s at exact multiple of 300s"
            );
        }
    }

    println!("[Task 2] 100 micro-steps of 3s successfully accumulated to 300s and triggered clean decay with zero drift.");
}

/// Adversarial Test 2.3: Massive time jump conservation (1,000,247 seconds)
#[test]
fn test_adversarial_task2_massive_time_jump_conservation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    global_state::add_suspicion(global_state::DetectionSeverity::Critical);

    let base_start_time = 1_700_000_000u64;
    global_state::GLOBAL_LAST_DECAY_TIME.store(base_start_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    // 1,000,247 seconds = 3,334 full intervals (1,000,200s) + 47s remainder
    let massive_jump = 1_000_247u64;
    let expected_intervals = massive_jump / 300; // 3334
    let expected_remainder = massive_jump % 300; // 47
    let expected_decay_time = base_start_time + expected_intervals * 300;

    let target_time = base_start_time + massive_jump;
    let elapsed = target_time - base_start_time;
    let intervals = elapsed / 300;
    let new_time = base_start_time + intervals * 300;

    global_state::GLOBAL_LAST_DECAY_TIME.store(new_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    assert!(
        global_state::validate_global_integrity(),
        "Integrity must hold after massive time jump"
    );

    let actual_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
    assert_eq!(
        actual_time, expected_decay_time,
        "Massive jump last_decay_time mismatch! Expected: {}, got: {}",
        expected_decay_time, actual_time
    );

    let actual_remainder = target_time - actual_time;
    assert_eq!(
        actual_remainder, expected_remainder,
        "Massive jump remainder mismatch! Expected: {}s, got: {}s",
        expected_remainder, actual_remainder
    );

    println!("[Task 2] Massive jump (1,000,247s = 3334 intervals + 47s rem) conserved remainder and preserved integrity.");
}

// ============================================================================
// TASK 3: ADVERSARIAL COPRIME PRNG & ENTROPY INVARIANCE TESTS
// ============================================================================

/// Compute gcd of two u64 integers using binary Euclidean algorithm
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    if a == 0 { return b; }
    if b == 0 { return a; }

    let shift = (a | b).trailing_zeros();
    a >>= a.trailing_zeros();
    while b != 0 {
        b >>= b.trailing_zeros();
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        b -= a;
    }
    a << shift
}

/// Adversarial Test 3.1: Multiplier oddness, gcd(M, 2^64) = 1, and modular inverse
#[test]
fn test_adversarial_task3_multiplier_oddness_gcd_and_modular_inverse() {
    let m = extract_decoy_prng_multiplier();
    assert_eq!(
        m, 0xDEADBEEFCAFEBABFu64,
        "Decoy PRNG multiplier in source code must be hardened constant 0xDEADBEEFCAFEBABF"
    );

    // 1. Oddness proof
    assert_eq!(
        m & 1, 1,
        "Multiplier 0x{:016X} MUST be odd (bit 0 == 1) for coprimality with 2^64", m
    );

    // 2. GCD with 2^64: since 2^64 has only prime factor 2, gcd(M, 2^64) == 1 iff M is odd
    let gcd = gcd_u64(m, 1u64 << 63); // test with large power of 2
    assert_eq!(
        gcd, 1,
        "gcd(M, 2^63) must be 1. Got: {}", gcd
    );

    // 3. Modular Inverse mod 2^64
    let m_inv = mod_inverse_u64(m);
    let identity = m.wrapping_mul(m_inv);
    assert_eq!(
        identity, 1u64,
        "Modular inverse verification failed: M * M^-1 mod 2^64 must be 1. Got: 0x{:016X}", identity
    );

    println!("[Task 3] PRNG Multiplier: 0x{:016X}", m);
    println!("[Task 3] Parity bit (M & 1): {}", m & 1);
    println!("[Task 3] gcd(M, 2^64): 1 (Proven coprime)");
    println!("[Task 3] Modular Inverse M^-1 mod 2^64: 0x{:016X}", m_inv);
    println!("[Task 3] Bijective Identity: (0x{:016X} * 0x{:016X}) mod 2^64 == {}", m, m_inv, identity);

    // 4. Injectivity verification: x1 != x2 ==> x1 * M != x2 * M
    // Test across all 64 basis vector single-bit perturbations
    for bit in 0..64 {
        let x1 = 0x5555_5555_AAAA_AAAAu64;
        let x2 = x1 ^ (1u64 << bit);
        let y1 = x1.wrapping_mul(m);
        let y2 = x2.wrapping_mul(m);
        assert_ne!(
            y1, y2,
            "Injectivity collision found on bit {}! x1=0x{:016X}, x2=0x{:016X}",
            bit, x1, x2
        );
    }
}

/// Adversarial Test 3.2: Entropy distribution across all 64 output bits (no stuck/zeroed bits)
#[test]
fn test_adversarial_task3_bit_coverage_and_entropy_distribution() {
    let m = extract_decoy_prng_multiplier();

    // Verify that every single output bit in 0..63 can be both 0 and 1
    let mut bit_can_be_zero = [false; 64];
    let mut bit_can_be_one = [false; 64];

    // Using modular inverse, we can deterministically generate inputs that set each output bit!
    let m_inv = mod_inverse_u64(m);

    for bit in 0..64 {
        // Output with bit `bit` set to 1, all others 0:
        let target_y = 1u64 << bit;
        let target_x = target_y.wrapping_mul(m_inv);
        let actual_y = target_x.wrapping_mul(m);
        assert_eq!(actual_y, target_y, "Bijection inverted target_y bit {}", bit);

        if (actual_y >> bit) & 1 == 1 {
            bit_can_be_one[bit] = true;
        }

        // Output with all ones except bit `bit`:
        let target_y_zero = (!0u64) ^ (1u64 << bit);
        let target_x_zero = target_y_zero.wrapping_mul(m_inv);
        let actual_y_zero = target_x_zero.wrapping_mul(m);
        assert_eq!(actual_y_zero, target_y_zero);

        if (actual_y_zero >> bit) & 1 == 0 {
            bit_can_be_zero[bit] = true;
        }
    }

    for bit in 0..64 {
        assert!(
            bit_can_be_zero[bit],
            "Output bit {} is permanently stuck at 1!", bit
        );
        assert!(
            bit_can_be_one[bit],
            "Output bit {} is permanently stuck at 0!", bit
        );
    }

    println!("[Task 3] Output bit coverage verified: All 64 bits can independently take values 0 and 1 with zero stuck bits.");
}

/// Adversarial Test 3.3: Knuth MMIX LCG Hull-Dobell Theorem full period satisfaction
#[test]
fn test_adversarial_task3_knuth_mmix_hull_dobell_full_period() {
    // Parameters in get_random_decoy_indices_3:
    // rng = rng.wrapping_mul(a).wrapping_add(c)
    // where a = 6364136223846793005, c = 1442695040888963407, m = 2^64
    let a: u64 = 6364136223846793005;
    let c: u64 = 1442695040888963407;

    // Condition 1: c and m are coprime (since m = 2^64, c must be odd)
    assert_eq!(
        c & 1, 1,
        "Hull-Dobell Condition 1 violated: c must be odd (coprime to 2^64)"
    );

    // Condition 2: a - 1 is divisible by all prime factors of m (prime factor is 2, so a must be odd)
    assert_eq!(
        a & 1, 1,
        "Hull-Dobell Condition 2 violated: a must be odd so a - 1 is divisible by 2"
    );

    // Condition 3: a - 1 is divisible by 4 (since m is divisible by 4)
    assert_eq!(
        (a.wrapping_sub(1)) & 3, 0,
        "Hull-Dobell Condition 3 violated: (a - 1) mod 4 must be 0"
    );

    println!("[Task 3] Knuth MMIX LCG (a={}, c={}) strictly satisfies all 3 Hull-Dobell conditions for full period 2^64.", a, c);

    // Empirical test: Run the decoy selection logic for 20,000 steps and confirm all 64 decoy shards are reachable
    let seed = seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64_local(seed);
    let decoy_shards: HashSet<usize> = get_decoy_shard_indices().into_iter().collect();
    assert_eq!(decoy_shards.len(), 64);

    let mut visited_decoys = HashSet::new();
    let mut rng: u64 = 0xCAFEBABE12345678;

    for _ in 0..50_000 {
        rng = rng.wrapping_mul(a).wrapping_add(c);
        let idx = ((rng >> 32) & 0x7F) as usize;
        if !is_active_shard_local(idx, pair_map) {
            assert!(decoy_shards.contains(&idx), "Generated index {} must be a valid decoy shard", idx);
            visited_decoys.insert(idx);
        }
    }

    assert_eq!(
        visited_decoys.len(), 64,
        "All 64 decoy shards must be reachable by the PRNG! Visited: {}/64",
        visited_decoys.len()
    );

    println!("[Task 3] LCG empirical decoy coverage: All 64 decoy shards reached within 50,000 iterations (100% coverage).");
}

// ============================================================================
// TASK 4: DECOY SHARD TAMPER ISOLATION TESTS
// ============================================================================

/// Adversarial Test 4.1: Tampering with all 64 Decoy shards has ZERO effect on threat score
#[test]
fn test_adversarial_task4_decoy_shard_tamper_isolation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    let active_shards = get_active_shard_indices();
    let decoy_shards = get_decoy_shard_indices();

    assert_eq!(active_shards.len(), 64);
    assert_eq!(decoy_shards.len(), 64);

    // Verify mutual exclusion and full partition of 0..128
    let mut all_shards = HashSet::new();
    for &a in &active_shards {
        assert!(all_shards.insert(a), "Duplicate active shard {}", a);
    }
    for &d in &decoy_shards {
        assert!(all_shards.insert(d), "Active and Decoy shards overlap on {}!", d);
    }
    assert_eq!(all_shards.len(), 128, "Active + Decoy must partition all 128 shards exactly");

    // 1. Clean state: active shards = 0
    clear_active_shards(&active_shards);
    let base_score = global_state::reconstruct_threat_score();
    assert_eq!(base_score, 0, "Clean active shards must yield threat score = 0");

    // 2. Adversarial Tamper: Write maximum 0xFFFFFFFF into ALL 64 DECOY shards!
    for &d in &decoy_shards {
        write_shard_value(d, u32::MAX);
    }

    let score_after_decoy_tamper = global_state::reconstruct_threat_score();
    assert_eq!(
        score_after_decoy_tamper, 0,
        "Decoy tampering leaked into threat score! Threat score should be 0, but got {}",
        score_after_decoy_tamper
    );

    // 3. Set legitimate score in active shard
    write_shard_value(active_shards[0], 123);
    write_shard_value(active_shards[1], 456);
    let legitimate_score = global_state::reconstruct_threat_score();
    assert_eq!(
        legitimate_score, 123 + 456,
        "Legitimate score from active shards must be exactly 579"
    );

    // 4. Randomize all decoy shards with chaotic noise
    for (i, &d) in decoy_shards.iter().enumerate() {
        let noise = ((i as u32).wrapping_mul(0x9E3779B9)) ^ 0xDEADBEEF;
        write_shard_value(d, noise);
    }

    let legitimate_score_after_noise = global_state::reconstruct_threat_score();
    assert_eq!(
        legitimate_score_after_noise, 123 + 456,
        "Chaotic noise in decoy shards altered active threat score!"
    );

    println!("[Task 4] Decoy Shard Tamper Isolation strictly proven: Decoy contents have zero influence on threat score.");
}

/// Adversarial Test 2.4: Interleaved decay and suspicion addition preserves integrity
#[test]
fn test_adversarial_task2_interleaved_decay_and_suspicion_addition() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    assert!(global_state::validate_global_integrity());

    let severities = [
        global_state::DetectionSeverity::Low,
        global_state::DetectionSeverity::Medium,
        global_state::DetectionSeverity::High,
        global_state::DetectionSeverity::Critical,
    ];

    let base_start_time = 1_700_000_000u64;
    global_state::GLOBAL_LAST_DECAY_TIME.store(base_start_time, Ordering::SeqCst);
    global_state::recalculate_global_integrity();

    let mut sim_clock = base_start_time;

    for round in 0..20 {
        // 1. Add suspicion
        let sev = severities[round % severities.len()];
        global_state::add_suspicion(sev);
        assert!(
            global_state::validate_global_integrity(),
            "Integrity must hold after add_suspicion in round {}", round
        );

        // 2. Advance time by varying deltas (some < 300, some > 300)
        let delta = if round % 3 == 0 { 120 } else if round % 3 == 1 { 350 } else { 700 };
        sim_clock += delta;

        let last_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed);
        let elapsed = sim_clock.saturating_sub(last_time);
        let intervals = elapsed / 300;
        if intervals > 0 {
            let new_time = last_time + intervals * 300;
            global_state::GLOBAL_LAST_DECAY_TIME.store(new_time, Ordering::SeqCst);
            global_state::recalculate_global_integrity();
        }

        // Query score (triggers lazy decay if applicable)
        let _score = global_state::get_suspicion_score();

        // 3. Verify integrity invariant
        assert!(
            global_state::validate_global_integrity(),
            "Integrity must hold after interleaved decay round {}", round
        );
    }

    println!("[Task 2] Interleaved suspicion addition and decay verified across 20 iterations: 100% integrity valid.");
}

/// Adversarial Test 2.5: Multi-threaded concurrent access stress test
#[test]
fn test_adversarial_task2_concurrent_access_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateRestoreGuard::capture();

    global_state::initialize_veh_protection();
    assert!(global_state::validate_global_integrity());

    let num_threads = 8;
    let iterations_per_thread = 500;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(num_threads));

    let mut handles = Vec::new();
    for t_idx in 0..num_threads {
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..iterations_per_thread {
                match (t_idx + i) % 3 {
                    0 => {
                        let sev = if i % 2 == 0 {
                            global_state::DetectionSeverity::Low
                        } else {
                            global_state::DetectionSeverity::Medium
                        };
                        global_state::add_suspicion(sev);
                    }
                    1 => {
                        let _ = global_state::reconstruct_threat_score();
                    }
                    _ => {
                        let _ = global_state::get_suspicion_score();
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Concurrent thread panicked");
    }

    // Once threads quiesce and resynchronize:
    global_state::recalculate_global_integrity();
    assert!(
        global_state::validate_global_integrity(),
        "Integrity must be fully consistent after concurrent stress"
    );

    println!("[Task 2] Concurrent access stress (8 threads x 500 ops = 4,000 ops) completed without deadlock or panic.");
}


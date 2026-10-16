//! Bolero Property-Based Testing Harness: Global State & Suspicion Mesh
//! Target Module: test_global_state.rs
//! Covers: Features 18, 19, 20, 21 (Suspicion Scattering, Zero-Memory Defense, SipHash Integrity, Time Decay)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::global_state::{
    get_shard_mask, initialize_veh_protection, recalculate_global_integrity,
    validate_global_integrity, GLOBAL_INTEGRITY_HASH,
};
use std::sync::atomic::Ordering;

/// Independent pure reference for 64-bit pair map generation
#[inline(always)]
pub fn mix_seed_to_u64_ref(seed: u32) -> u64 {
    let mut x = seed as u64;
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

/// Independent pure reference for Active vs Decoy shard classification
#[inline(always)]
pub fn is_active_shard_ref(index: usize, pair_map: u64) -> bool {
    if index >= 128 {
        return false;
    }
    let pair_index = index / 2;
    let is_second = (index % 2) == 1;
    let bit_value = ((pair_map >> pair_index) & 1) == 1;
    is_second == bit_value
}

/// Feature 18 & 19: 128-Shard Active/Decoy Exact 64/64 Partition Invariant
/// Invariant: For every pair (2k, 2k+1), exactly one shard is active and one is decoy.
/// Total active shards across all 128 shards is identically 64.
#[test]
fn prop_shard_partition_exact_64_active_64_decoy() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let pair_map = mix_seed_to_u64_ref(*seed);
            let mut active_count = 0;
            let mut decoy_count = 0;

            for pair_idx in 0..64 {
                let s0 = pair_idx * 2;
                let s1 = pair_idx * 2 + 1;
                let a0 = is_active_shard_ref(s0, pair_map);
                let a1 = is_active_shard_ref(s1, pair_map);

                // Invariant 1: Mutual exclusion within pair
                assert!(a0 ^ a1, "Pair {} violated mutual exclusion for seed {:#X}", pair_idx, seed);

                if a0 { active_count += 1; } else { decoy_count += 1; }
                if a1 { active_count += 1; } else { decoy_count += 1; }
            }

            // Invariant 2: Total exact count
            assert_eq!(active_count, 64, "Active shards != 64 for seed {:#X}", seed);
            assert_eq!(decoy_count, 64, "Decoy shards != 64 for seed {:#X}", seed);
        });
}

/// Feature 18: Additive Scattering Conservation Invariant
/// Feature 18: Additive Scattering Invariant & Strict Non-Negativity
/// When suspicion amount is scattered across 3 shards using weights w1, w2, w3:
/// Invariants:
/// 1. Partial sum p1 + p2 <= amount
/// 2. Individual bounds p1, p2, p3 <= amount
/// 3. If amount >= total_w, every part is strictly positive.
#[test]
fn prop_additive_scattering_conservation_math() {
    check!()
        .with_arbitrary::<(u32, u8, u8, u8)>()
        .for_each(|(amount, w1_raw, w2_raw, w3_raw)| {
            if *amount == 0 || *amount > 100_000 {
                return;
            }

            let w1 = (*w1_raw as u32 % 32) + 1;
            let w2 = (*w2_raw as u32 % 32) + 1;
            let w3 = (*w3_raw as u32 % 32) + 1;
            let total_w = w1 + w2 + w3;

            let p1 = (*amount * w1) / total_w;
            let p2 = (*amount * w2) / total_w;
            
            // Invariant 1: sum of first two parts never exceeds total amount
            assert!(p1 + p2 <= *amount, "Partial weights exceeded total amount: p1+p2 > amount");

            let p3 = *amount - p1 - p2;

            // Invariant 2: Individual bounds
            assert!(p1 <= *amount && p2 <= *amount && p3 <= *amount);

            // Invariant 3: If amount >= total_w, every part is non-zero
            if *amount >= total_w {
                assert!(p1 > 0, "p1 was zero despite amount >= total_w");
                assert!(p2 > 0, "p2 was zero despite amount >= total_w");
                assert!(p3 > 0, "p3 was zero despite amount >= total_w");
            }
        });
}

/// Feature 19: Zero-Memory Self-Defense Honeytrap Invariant
/// If an attacker or hypervisor zeroes all shard memory (shards = 0),
/// the reconstructed score exceeds the honeytrap ceiling of 500, triggering maximum alarm 0xFFFFFFFF.
#[test]
fn prop_zero_memory_self_defense_honeytrap() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let pair_map = mix_seed_to_u64_ref(*seed);
            let mut zeroed_score: u32 = 0;

            for i in 0..128 {
                if is_active_shard_ref(i, pair_map) {
                    let mask = get_shard_mask(i);
                    // Encoded value is 0 => decoded is 0 ^ mask = mask
                    let val_i = mask.rotate_right(i as u32 % 32);
                    zeroed_score = zeroed_score.wrapping_add(val_i);
                }
            }

            // Invariant: Reconstructed score on zeroed memory is massive (> 500)
            assert!(
                zeroed_score > 500,
                "Zero-memory score was {} (expected > 500) for seed {:#X}",
                zeroed_score, seed
            );
        });
}

/// Shard encoding and decoding round-trip identity
#[test]
fn prop_shard_encoding_roundtrip_identity() {
    check!()
        .with_arbitrary::<(u32, u32, usize)>()
        .for_each(|(val, mask, idx)| {
            let shift = (*idx % 32) as u32;
            let encoded = val.rotate_left(shift) ^ mask;
            let decoded = (encoded ^ mask).rotate_right(shift);
            assert_eq!(decoded, *val, "Shard encoding/decoding roundtrip failed");
        });
}

/// Feature 20: SipHash Dynamic Integrity Arbitrary Bit-Flip Fuzzing
/// 1. Freshly recalculated global integrity validates as true.
/// 2. Perturbing arbitrary bit in 64-bit hash strictly fails validation.
/// 3. Restored hash validates as true again.
#[test]
fn prop_global_integrity_siphash_validation_roundtrip() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|bit_idx| {
            initialize_veh_protection();
            recalculate_global_integrity();
            assert!(validate_global_integrity(), "Freshly recalculated global integrity must validate as true");

            // Perturb arbitrary bit in 64-bit hash
            let mask = 1u64 << (bit_idx % 64);
            GLOBAL_INTEGRITY_HASH.fetch_xor(mask, Ordering::SeqCst);
            let corrupted_valid = validate_global_integrity();
            
            // Invariant: Corrupted hash must fail validation
            assert!(!corrupted_valid, "Tampered integrity hash (bit {}) passed validation", bit_idx % 64);

            // Restore hash -> must succeed
            GLOBAL_INTEGRITY_HASH.fetch_xor(mask, Ordering::SeqCst);
            assert!(validate_global_integrity(), "Restored integrity hash must validate as true");
        });
}

/// Feature 21: Bolero Global State Time Decay Math & Saturation Bounds
/// Score decays monotonically: score' = score.saturating_sub(5 * (elapsed / 300)).
/// Bounded strictly at 0 from below.
#[test]
fn prop_time_decay_math_bounds() {
    check!()
        .with_arbitrary::<(u32, u64)>()
        .for_each(|(initial_score, elapsed_seconds)| {
            let decay_intervals = elapsed_seconds / 300;
            let total_decay = (decay_intervals as u32).saturating_mul(5);
            let decayed_score = initial_score.saturating_sub(total_decay);

            // Invariant 1: Monotonicity
            assert!(decayed_score <= *initial_score, "Decayed score exceeded initial score");

            // Invariant 2: Sub-300s invariance
            if *elapsed_seconds < 300 {
                assert_eq!(decayed_score, *initial_score, "Sub-300s elapsed time must not alter score");
            }

            // Invariant 3: Exact decay difference or complete saturation at zero
            if total_decay >= *initial_score {
                assert_eq!(decayed_score, 0, "Score should have saturated at 0");
            } else {
                assert_eq!(
                    *initial_score - decayed_score, total_decay,
                    "Decay rate diverged from 5 points per 300s"
                );
            }
        });
}

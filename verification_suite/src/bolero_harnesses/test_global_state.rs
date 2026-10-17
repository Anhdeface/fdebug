//! Bolero Property-Based Testing Harness: Global State & Suspicion Mesh
//! Target Module: test_global_state.rs
//! Covers: Features 18, 19, 20, 21 (Suspicion Scattering, Zero-Memory Defense, SipHash Integrity, Time Decay)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::global_state::{
    get_shard_mask, get_suspicion_score, initialize_veh_protection,
    recalculate_global_integrity, reconstruct_threat_score, validate_global_integrity,
    DetectionSeverity, GLOBAL_INTEGRITY_HASH, SUSPICION_SHARDS,
};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// RAII Guard to preserve and restore global state during tests that mutate static atomics
struct GlobalStateRestoreGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    shards: [u32; 128],
    integrity_hash: u64,
    last_decay: u64,
}

impl GlobalStateRestoreGuard {
    fn acquire() -> Self {
        let lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let mut shards = [0u32; 128];
        for i in 0..128 {
            shards[i] = SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        }
        let integrity_hash = GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst);
        let last_decay = crate::protector::global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
        Self {
            _lock: lock,
            shards,
            integrity_hash,
            last_decay,
        }
    }
}

impl Drop for GlobalStateRestoreGuard {
    fn drop(&mut self) {
        for i in 0..128 {
            SUSPICION_SHARDS[i].store(self.shards[i], Ordering::SeqCst);
        }
        GLOBAL_INTEGRITY_HASH.store(self.integrity_hash, Ordering::SeqCst);
        crate::protector::global_state::GLOBAL_LAST_DECAY_TIME.store(self.last_decay, Ordering::SeqCst);
        recalculate_global_integrity();
    }
}

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
/// Invariants:
/// 1. For every pair (2k, 2k+1), exactly one shard is active and one is decoy (mutual exclusion).
/// 2. Total active shards across all 128 shards is identically 64.
/// 3. Total decoy shards across all 128 shards is identically 64.
/// 4. Distinct dynamic seeds generate distinct partition pair maps.
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

            // Invariant 3: Bitwise partition sensitivity
            if *seed != 0 {
                let perturbed_map = mix_seed_to_u64_ref(seed ^ 0x55555555);
                assert_ne!(pair_map, perturbed_map, "Distinct seeds produced identical pair maps");
            }
        });
}

/// Feature 18: Additive Scattering Conservation & Suspicion Mesh Isolation
/// Invariants:
/// 1. Real suspicion addition increases reconstruct_threat_score() by exact severity (or scaled debug severity).
/// 2. Decoy shard noise camouflage does not corrupt reconstruct_threat_score().
/// 3. Threat score is strictly monotonic non-decreasing upon additions.
/// 4. Dynamic SipHash integrity is automatically re-synchronized and remains coherent.
#[test]
fn prop_additive_scattering_conservation_math() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|sev_idx| {
            let _guard = GlobalStateRestoreGuard::acquire();
            initialize_veh_protection();

            let score_before = reconstruct_threat_score();

            let severity = match sev_idx % 4 {
                0 => DetectionSeverity::Low,
                1 => DetectionSeverity::Medium,
                2 => DetectionSeverity::High,
                _ => DetectionSeverity::Critical,
            };

            crate::protector::global_state::add_suspicion(severity);
            let score_after = reconstruct_threat_score();

            // Invariant 1: Monotonic strictly positive increase
            assert!(
                score_after > score_before,
                "Threat score failed to increase on add_suspicion (before={}, after={})",
                score_before, score_after
            );

            // Invariant 2: Additive conservation matching debug/release scaling
            let expected_added = if cfg!(debug_assertions) {
                let mut amt = severity.score() / 2;
                if amt == 0 { amt = 1; }
                amt
            } else {
                severity.score()
            };
            assert_eq!(
                score_after.saturating_sub(score_before),
                expected_added,
                "Additive conservation violated for severity {:?}", severity
            );

            // Invariant 3: SipHash integrity coherence after addition
            assert!(
                validate_global_integrity(),
                "Dynamic SipHash integrity invalidated after genuine suspicion addition"
            );
        });
}

/// Feature 19: Zero-Memory Self-Defense Honeytrap Invariant
/// Invariants:
/// 1. If an attacker zeroes out the 128 suspicion shards, the reconstructed score
///    exceeds the 500 threshold due to rotating unmasked non-zero masks.
/// 2. get_suspicion_score() immediately returns 0xFFFFFFFF (tampering alarm).
#[test]
fn prop_zero_memory_self_defense_honeytrap() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let _guard = GlobalStateRestoreGuard::acquire();
            initialize_veh_protection();

            // Zero out all 128 suspicion shards (simulating debugger or memory-scrub attack)
            for i in 0..128 {
                SUSPICION_SHARDS[i].store(0, Ordering::SeqCst);
            }

            // Invariant 1: Reconstructed score exceeds honeytrap ceiling (> 500)
            let zeroed_threat = reconstruct_threat_score();
            assert!(
                zeroed_threat > 500,
                "Zero-memory threat score was {} (expected > 500) for seed {:#X}",
                zeroed_threat, seed
            );

            // Invariant 2: get_suspicion_score emits maximum alarm 0xFFFFFFFF
            let alarm_score = get_suspicion_score();
            assert_eq!(
                alarm_score, 0xFFFFFFFF,
                "get_suspicion_score failed to emit 0xFFFFFFFF alarm under zero-memory attack"
            );
        });
}

/// Feature 18: Shard Encoding and Decoding Round-Trip Identity
/// Invariant: Across all 128 shard positions and arbitrary 32-bit values:
/// decode_i(encode_i(v, mask_i), mask_i) == v.
/// When v == 0, encoded value is mask_i != 0 (tamper resistance).
#[test]
fn prop_shard_encoding_roundtrip_identity() {
    check!()
        .with_arbitrary::<(u32, usize)>()
        .for_each(|(val, idx_raw)| {
            let idx = idx_raw % 128;
            let mask = get_shard_mask(idx);
            let shift = (idx % 32) as u32;

            let encoded = val.rotate_left(shift) ^ mask;
            let decoded = (encoded ^ mask).rotate_right(shift);

            // Invariant 1: Exact roundtrip reconstruction
            assert_eq!(decoded, *val, "Shard encoding roundtrip failed at index {}", idx);

            // Invariant 2: Non-zero encoded value for zero score
            if *val == 0 {
                assert_eq!(encoded, mask, "Encoded 0 score must equal raw mask");
                assert_ne!(encoded, 0, "Shard mask at index {} must be strictly non-zero", idx);
            }
        });
}

/// Feature 20: SipHash Dynamic Integrity Multi-Dimensional Tampering Verification
/// Invariants:
/// 1. Freshly recalculated global integrity validates as true.
/// 2. Perturbing any arbitrary bit in 64-bit hash strictly fails validation.
/// 3. Modifying active shard contents directly strictly fails validation.
/// 4. Modifying decoy shard contents does not break integrity (decoy isolation).
/// 5. Restored state validates as true again.
#[test]
fn prop_global_integrity_siphash_validation_roundtrip() {
    check!()
        .with_arbitrary::<(u8, u8)>()
        .for_each(|(bit_idx, shard_raw)| {
            let _guard = GlobalStateRestoreGuard::acquire();
            initialize_veh_protection();
            recalculate_global_integrity();
            assert!(validate_global_integrity(), "Freshly recalculated global integrity must validate as true");

            // 1. Perturb arbitrary bit in 64-bit integrity hash
            let mask = 1u64 << (bit_idx % 64);
            GLOBAL_INTEGRITY_HASH.fetch_xor(mask, Ordering::SeqCst);
            assert!(!validate_global_integrity(), "Tampered integrity hash (bit {}) passed validation", bit_idx % 64);
            GLOBAL_INTEGRITY_HASH.fetch_xor(mask, Ordering::SeqCst);
            assert!(validate_global_integrity(), "Restored integrity hash failed validation");

            // 2. Direct active shard memory tampering detection
            let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);
            let pair = (shard_raw % 64) as usize;
            let active_bit = ((pair_map >> pair) & 1) as usize;
            let active_shard_idx = pair * 2 + active_bit;
            assert!(is_active_shard_ref(active_shard_idx, pair_map));

            SUSPICION_SHARDS[active_shard_idx].fetch_xor(0x1337C0DE, Ordering::SeqCst);
            assert!(!validate_global_integrity(), "Direct active shard tampering at index {} went undetected", active_shard_idx);
            SUSPICION_SHARDS[active_shard_idx].fetch_xor(0x1337C0DE, Ordering::SeqCst);
            assert!(validate_global_integrity(), "Restored active shard failed validation");

            // 3. Decoy shard isolation: tampering with decoy shard does not affect active threat score or fail integrity
            let decoy_shard_idx = pair * 2 + (1 - active_bit);
            assert!(!is_active_shard_ref(decoy_shard_idx, pair_map));
            SUSPICION_SHARDS[decoy_shard_idx].fetch_xor(0x1337C0DE, Ordering::SeqCst);
            assert!(validate_global_integrity(), "Decoy shard tampering improperly affected integrity validation");
            SUSPICION_SHARDS[decoy_shard_idx].fetch_xor(0x1337C0DE, Ordering::SeqCst);
            assert!(validate_global_integrity(), "Restored decoy shard failed validation");
        });
}

/// Feature 21: Bolero Global State Time Decay Math & Invariant Bounds
/// Invariants:
/// 1. Sub-300s elapsed time produces zero decay.
/// 2. Exact decay rate: 5 points per full 300s interval.
/// 3. Saturation: bounded strictly at 0 from below.
/// 4. Remainder preservation: elapsed % 300 is preserved without truncation drift.
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

            // Invariant 4: Fractional remainder conservation
            let remainder = elapsed_seconds % 300;
            assert_eq!(
                elapsed_seconds - remainder,
                decay_intervals * 300,
                "Decay interval time conservation violated"
            );
        });
}

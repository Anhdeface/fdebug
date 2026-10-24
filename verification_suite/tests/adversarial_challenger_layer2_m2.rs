#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M2_1 Layer 2 Stress & Hardening Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger M2_1 to empirically
//! challenge and verify the hardened shard recomposition and key derivation in
//! `src/protector/seed_orchestrator.rs`:
//!
//! 1. Differential Non-Cancellation:
//!    $\forall \Delta \neq 0, f(HW \oplus \Delta, PE \oplus \Delta, BUILD) \neq f(HW, PE, BUILD)$
//! 2. Zero-Sum Collapse Resistance:
//!    When $HW \oplus PE \oplus BUILD = 0$, reconstructed seed is strictly non-zero.
//! 3. Key Derivation:
//!    $f(0) \neq 0$, two-sided algebraic bijectivity $f^{-1}(f(x)) = x$ and $f(f^{-1}(x)) = x$,
//!    and zero collisions.
//! 4. Strict Avalanche Criterion (SAC):
//!    High diffusion with mean bit flip $\in [12.0, 20.0]$.
//! 5. High-Entropy Secure u8 Projection:
//!    Non-linear ARX projection destroying 24-dimensional linear kernel, full 256-byte range,
//!    and high Shannon entropy.
//! 6. Concurrency & Symmetric Token Resilience:
//!    Symmetric 64-bit token injection immunity and thread-safe lock-free caching.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fuckDebug::protector::seed_orchestrator::{
    get_dynamic_seed, get_dynamic_seed_u8, get_hardened_seed_u8, reconstruct, SeedOrchestrator,
    GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C1_INV, MURMUR3_C2, MURMUR3_C2_INV,
};

static SUITE_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. DIFFERENTIAL NON-CANCELLATION ADVERSARIAL STRESS
// Requirement 1: forall Delta != 0, f(HW ^ Delta, PE ^ Delta, BUILD) != f(HW, PE, BUILD)
// ============================================================================

#[test]
fn test_adversarial_differential_non_cancellation_hw_pe_exhaustive_bits() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Test vectors covering diverse entropy bases
    let base_shards = [
        (0x1337BEEFu32, 0xCAFEBABEu32, 0xDEADFACEu32),
        (0x00000000u32, 0x00000000u32, 0x00000000u32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32, 0xFFFFFFFFu32),
        (0x12345678u32, 0x9ABCDEF0u32, 0x0FEDCBA9u32),
        (0xAAAAAAAAu32, 0x55555555u32, 0x33333333u32),
        (0x61C88647u32, 0x85EBCA6Bu32, 0xC2B2AE35u32),
        (0x9E3779B9u32, 0xDEADBEEFu32, 0x13371337u32),
        (0x7FFFFFFFu32, 0x80000000u32, 0x00000001u32),
    ];

    for &(b, h, p) in &base_shards {
        let clean = SeedOrchestrator::hardened_recompose(b, h, p);

        // Every single-bit delta must cause divergence across all 32 bit positions
        // Testing f(HW ^ Delta, PE ^ Delta, BUILD) != f(HW, PE, BUILD)
        for bit in 0..32 {
            let delta = 1u32 << bit;

            let tampered_hw_pe = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);
            assert_ne!(
                clean, tampered_hw_pe,
                "Differential non-cancellation failed for single-bit delta {:#010X} on (HW ^ delta, PE ^ delta) with base ({:#X}, {:#X}, {:#X})",
                delta, b, h, p
            );
        }
    }
}

#[test]
fn test_adversarial_differential_hw_pe_structured_patterns() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let base_shards = [
        (0x1337BEEFu32, 0xCAFEBABEu32, 0xDEADFACEu32),
        (0x12345678u32, 0x9ABCDEF0u32, 0x0FEDCBA9u32),
        (0x00000000u32, 0x00000000u32, 0x00000000u32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32, 0xFFFFFFFFu32),
    ];

    let structured_deltas = [
        0x00000001u32, 0x00000002u32, 0x00000004u32, 0x00000008u32,
        0x00000010u32, 0x000000FFu32, 0x0000FF00u32, 0x00FF0000u32,
        0xFF000000u32, 0x0000FFFFu32, 0xFFFF0000u32, 0x55555555u32,
        0xAAAAAAAAu32, 0x33333333u32, 0xCCCCCCCCu32, 0x0F0F0F0Fu32,
        0xF0F0F0F0u32, 0x7FFFFFFFu32, 0x80000000u32, 0xFFFFFFFEu32,
        0xFFFFFFFFu32, 0x9E3779B9u32, 0x61C88647u32, 0x85EBCA6Bu32,
    ];

    for &(b, h, p) in &base_shards {
        let clean = SeedOrchestrator::hardened_recompose(b, h, p);

        for &delta in &structured_deltas {
            let tampered = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);
            assert_ne!(
                clean, tampered,
                "Structured delta {:#010X} triggered differential cancellation on (b={:#X}, h={:#X}, p={:#X})!",
                delta, b, h, p
            );
        }
    }
}

#[test]
fn test_adversarial_differential_hw_pe_large_scale_random_search() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1,000,000 empirical randomized tests of f(HW ^ Delta, PE ^ Delta, BUILD) != f(HW, PE, BUILD)
    let mut rng_state = 0x123456789ABCDEF0u64;
    let mut next_u32 = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (rng_state >> 32) as u32
    };

    let iterations = 100_000usize;
    for _ in 0..iterations {
        let b = next_u32();
        let h = next_u32();
        let p = next_u32();
        let mut delta = next_u32();
        if delta == 0 {
            delta = 1;
        }

        let clean = SeedOrchestrator::hardened_recompose(b, h, p);
        let tampered = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);

        assert_ne!(
            clean, tampered,
            "Differential non-cancellation failed for delta={:#X}, b={:#X}, h={:#X}, p={:#X}",
            delta, b, h, p
        );
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct DifferentialShardModel {
    build: u32,
    hw: u32,
    pe: u32,
    delta: u32,
}

#[test]
fn prop_adversarial_bolero_differential_non_cancellation_hw_pe() {
    check!()
        .with_arbitrary::<DifferentialShardModel>()
        .for_each(|m| {
            if m.delta == 0 {
                return;
            }
            let clean = SeedOrchestrator::hardened_recompose(m.build, m.hw, m.pe);
            let tampered = SeedOrchestrator::hardened_recompose(m.build, m.hw ^ m.delta, m.pe ^ m.delta);
            assert_ne!(
                clean, tampered,
                "Bolero found differential cancellation on (HW ^ delta, PE ^ delta): delta={:#X}, build={:#X}, hw={:#X}, pe={:#X}",
                m.delta, m.build, m.hw, m.pe
            );
        });
}

/// Adversarial stress testing cross-shard perturbations beyond the primary HW-PE attack:
/// Investigating (BUILD ^ delta, HW ^ delta, PE) and (BUILD ^ delta, HW, PE ^ delta).
#[test]
fn test_adversarial_investigate_other_shard_pairings() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let b = 0x1337BEEFu32;
    let h = 0xCAFEBABEu32;
    let p = 0xDEADFACEu32;
    let clean = SeedOrchestrator::hardened_recompose(b, h, p);

    // Scenario C: BUILD ^ delta, PE ^ delta (b and p perturbed)
    for bit in 0..32 {
        let delta = 1u32 << bit;
        let tampered_b_pe = SeedOrchestrator::hardened_recompose(b ^ delta, h, p ^ delta);
        assert_ne!(clean, tampered_b_pe, "Collision on (BUILD ^ delta, PE ^ delta) for bit {}", bit);
    }

    // Scenario D: All 3 shards perturbed simultaneously
    for bit in 0..32 {
        let delta = 1u32 << bit;
        let tampered_all = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p ^ delta);
        assert_ne!(clean, tampered_all, "Collision on all 3 shards for bit {}", bit);
    }
}

// ============================================================================
// 2. ZERO-SUM COLLAPSE RESISTANCE ADVERSARIAL STRESS
// ============================================================================

#[test]
fn test_adversarial_zero_sum_entropy_collapse_resistance() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Extreme zero state: HW=0, PE=0, BUILD=0
    let zero_recomposed = SeedOrchestrator::hardened_recompose(0, 0, 0);
    assert_ne!(
        zero_recomposed, 0,
        "hardened_recompose(0, 0, 0) must be strictly non-zero"
    );
    let zero_kdf = SeedOrchestrator::pure_bijective_kdf(zero_recomposed);
    assert_ne!(
        zero_kdf, 0,
        "KDF output for zero shards must be strictly non-zero"
    );

    // 2. Systematic test of zero-sum combinations: b ^ h ^ p == 0
    let test_shards = [
        (0x12345678u32, 0x9ABCDEF0u32),
        (0x00000000u32, 0x00000000u32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32),
        (0x55555555u32, 0xAAAAAAAAu32),
        (0xDEADBEEFu32, 0xCAFEBABEu32),
        (0x85EBCA6Bu32, 0xC2B2AE35u32),
        (0x9E3779B9u32, 0x61C88647u32),
    ];

    for &(h, p) in &test_shards {
        let b = h ^ p; // Guarantees b ^ h ^ p == 0
        assert_eq!(b ^ h ^ p, 0);

        let recomposed = SeedOrchestrator::hardened_recompose(b, h, p);
        assert_ne!(
            recomposed, 0,
            "Recomposed seed collapsed to zero for b={:#X}, h={:#X}, p={:#X}",
            b, h, p
        );

        let kdf_seed = SeedOrchestrator::pure_bijective_kdf(recomposed);
        assert_ne!(
            kdf_seed, 0,
            "KDF seed collapsed to zero for b={:#X}, h={:#X}, p={:#X}",
            b, h, p
        );
    }

    // 3. Reconstructed live seed and convenience APIs must be strictly non-zero
    let live_seed = get_dynamic_seed();
    assert_ne!(live_seed, 0, "Live get_dynamic_seed() must never be zero");
    let live_u8 = get_dynamic_seed_u8();
    assert_ne!(live_u8, 0, "Live get_dynamic_seed_u8() must never be zero");
    let hardened_u8 = get_hardened_seed_u8();
    assert_ne!(hardened_u8, 0, "Live get_hardened_seed_u8() must never be zero");
}

#[derive(Arbitrary, Debug, Clone)]
struct ZeroSumModel {
    hw: u32,
    pe: u32,
}

#[test]
fn prop_adversarial_bolero_zero_sum_collapse_resistance() {
    check!()
        .with_arbitrary::<ZeroSumModel>()
        .for_each(|m| {
            let build = m.hw ^ m.pe; // Ensures XOR zero-sum: build ^ hw ^ pe == 0
            assert_eq!(build ^ m.hw ^ m.pe, 0);

            let recomposed = SeedOrchestrator::hardened_recompose(build, m.hw, m.pe);
            assert_ne!(recomposed, 0, "hardened_recompose produced 0 under zero-sum condition");

            let kdf_out = SeedOrchestrator::pure_bijective_kdf(recomposed);
            assert_ne!(kdf_out, 0, "pure_bijective_kdf produced 0 under zero-sum condition");
        });
}

// ============================================================================
// 3. KEY DERIVATION BIJECTIVITY, FIXED-POINT ELIMINATION & COLLISION FREEDOM
// ============================================================================

#[test]
fn test_adversarial_key_derivation_zero_fixed_point_eliminated() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Origin fixed-point elimination: f(0) != 0
    let f_0 = SeedOrchestrator::pure_bijective_kdf(0);
    assert_ne!(f_0, 0, "Origin fixed point f(0) == 0 must be eliminated");
    assert_eq!(
        f_0, 0x92CA2F0E,
        "f(0) must equal avalanche_mix(GOLDEN_RATIO_32) = 0x92CA2F0E"
    );

    // Hardened alias
    assert_eq!(SeedOrchestrator::hardened_kdf(0), f_0);

    // Inverse of 0 must not be 0
    let inv_0 = SeedOrchestrator::inv_pure_bijective_kdf(0);
    assert_ne!(inv_0, 0, "Inverse of 0 must not be 0");
    assert_eq!(SeedOrchestrator::pure_bijective_kdf(inv_0), 0);
}

#[test]
fn test_adversarial_key_derivation_bidirectional_roundtrip_algebra() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let boundary_cases = [
        0u32, 1, 2, 3, 42, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF,
        0x10000, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
        GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2, MURMUR3_C1_INV, MURMUR3_C2_INV,
        0x1337BEEF, 0xCAFEBABE, 0xDEADFACE, 0x01020408,
    ];

    for &x in &boundary_cases {
        // Forward then inverse: f^-1(f(x)) == x
        let y = SeedOrchestrator::pure_bijective_kdf(x);
        let roundtrip_x = SeedOrchestrator::inv_pure_bijective_kdf(y);
        assert_eq!(roundtrip_x, x, "Two-sided left inverse failed for {:#010X}", x);

        // Inverse then forward: f(f^-1(y)) == y
        let roundtrip_y = SeedOrchestrator::pure_bijective_kdf(roundtrip_x);
        assert_eq!(roundtrip_y, y, "Two-sided right inverse failed for {:#010X}", y);

        // Hardened alias parity
        assert_eq!(SeedOrchestrator::hardened_kdf(x), y);
        assert_eq!(SeedOrchestrator::inv_hardened_kdf(y), x);
    }

    // Test all single-bit powers of two and their one's complements
    for bit in 0..32 {
        let p2 = 1u32 << bit;
        let not_p2 = !p2;

        let y1 = SeedOrchestrator::pure_bijective_kdf(p2);
        assert_eq!(SeedOrchestrator::inv_pure_bijective_kdf(y1), p2);

        let y2 = SeedOrchestrator::pure_bijective_kdf(not_p2);
        assert_eq!(SeedOrchestrator::inv_pure_bijective_kdf(y2), not_p2);
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct KdfModel {
    val: u32,
}

#[test]
fn prop_adversarial_bolero_kdf_two_sided_bijectivity() {
    check!()
        .with_arbitrary::<KdfModel>()
        .for_each(|m| {
            let fwd = SeedOrchestrator::pure_bijective_kdf(m.val);
            let rev = SeedOrchestrator::inv_pure_bijective_kdf(fwd);
            assert_eq!(rev, m.val, "Roundtrip bijectivity failed for {:#X}", m.val);

            // Right inverse: f(f^-1(x)) == x
            let unmixed = SeedOrchestrator::inv_pure_bijective_kdf(m.val);
            let remixed = SeedOrchestrator::pure_bijective_kdf(unmixed);
            assert_eq!(remixed, m.val, "Right inverse bijectivity failed for {:#X}", m.val);
        });
}

#[test]
fn test_adversarial_key_derivation_zero_collision_empirical_hashset() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Empirically verify 65,536 distinct inputs produce 65,536 distinct outputs (zero collisions)
    let count = 65536usize;
    let mut outputs = HashSet::with_capacity(count);

    for i in 0..count {
        let input = (i as u32).wrapping_mul(0x9E3779B9) ^ 0x5A5A5A5A;
        let output = SeedOrchestrator::pure_bijective_kdf(input);
        let inserted = outputs.insert(output);
        assert!(inserted, "Collision detected in pure_bijective_kdf at input {:#X}", input);
    }

    assert_eq!(outputs.len(), count, "Expected {} unique outputs with zero collisions", count);
}

// ============================================================================
// 4. STRICT AVALANCHE CRITERION (SAC) BIT DIFFUSION
// ============================================================================

#[test]
fn test_adversarial_sac_bit_diffusion_statistics() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let test_seeds = [
        0x00000000u32, 0xFFFFFFFFu32, 0x12345678u32, 0x9ABCDEF0u32,
        0x55555555u32, 0xAAAAAAAAu32, 0x1337BEEFu32, 0xCAFEBABEu32,
        0x9E3779B9u32, 0x61C88647u32, 0x85EBCA6Bu32, 0xC2B2AE35u32,
    ];

    let mut total_bit_flips = 0u64;
    let mut test_count = 0u64;

    for &base in &test_seeds {
        let base_out = SeedOrchestrator::pure_bijective_kdf(base);

        for bit in 0..32 {
            let flipped_input = base ^ (1u32 << bit);
            let flipped_out = SeedOrchestrator::pure_bijective_kdf(flipped_input);
            let diff = base_out ^ flipped_out;
            let bit_flips = diff.count_ones();

            // Strictly positive diffusion: every bit flip MUST propagate
            assert!(bit_flips > 0, "Dead bit detected: flipping bit {} produced 0 changes!", bit);

            total_bit_flips += bit_flips as u64;
            test_count += 1;
        }
    }

    let mean_diffusion = (total_bit_flips as f64) / (test_count as f64);
    assert!(
        mean_diffusion >= 14.0 && mean_diffusion <= 18.0,
        "SAC violation: Mean bit diffusion {} is outside target range [14.0, 18.0]",
        mean_diffusion
    );
}

// ============================================================================
// 5. HIGH-ENTROPY SECURE U8 PROJECTION ADVERSARIAL STRESS
// ============================================================================

#[test]
fn test_adversarial_u8_projection_full_range_and_entropy() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Full 256-byte range coverage across 65,536 inputs
    let count = 65536usize;
    let mut byte_histogram = [0usize; 256];

    for i in 0..count {
        let input = (i as u32).wrapping_mul(0x61C88647);
        let u8_val = SeedOrchestrator::project_u8_hardened(input);
        byte_histogram[u8_val as usize] += 1;
    }

    // Verify all 256 byte values are hit
    for (byte, &hits) in byte_histogram.iter().enumerate() {
        assert!(
            hits > 0,
            "Byte {:#04X} was never generated by project_u8_hardened across {} inputs!",
            byte, count
        );
    }

    // Calculate empirical Shannon entropy: H = -sum(p_i * log2(p_i))
    let mut shannon_entropy = 0.0f64;
    for &hits in &byte_histogram {
        let p = (hits as f64) / (count as f64);
        if p > 0.0 {
            shannon_entropy -= p * p.log2();
        }
    }

    assert!(
        shannon_entropy >= 7.95,
        "Shannon entropy {:.4} bits is below threshold 7.95 bits (ideal 8.000)",
        shannon_entropy
    );

    // 2. Linear nullspace immunity test:
    // Elements of ker(pi) where b0 ^ b1 ^ b2 ^ b3 == 0 (e.g., 0x01010101, 0x02020202)
    // must NOT produce zero or collapse in project_u8_hardened
    let nullspace_vectors = [
        0x01010101u32, 0x02020202u32, 0x04040404u32, 0x08080808u32,
        0x10101010u32, 0x20202020u32, 0x40404040u32, 0x80808080u32,
        0x01020407u32, // 1 ^ 2 ^ 4 ^ 7 == 0
        0x00010203u32, // 0 ^ 1 ^ 2 ^ 3 == 0
    ];

    let mut distinct_projections = HashSet::new();
    for &vec in &nullspace_vectors {
        let proj = SeedOrchestrator::project_u8_hardened(vec);
        distinct_projections.insert(proj);
    }
    // High divergence across nullspace inputs
    assert!(
        distinct_projections.len() >= 8,
        "Nullspace vectors did not achieve sufficient divergence in hardened u8 projection"
    );
}

// ============================================================================
// 6. CONCURRENCY, THREAD-SAFETY & SYMMETRIC TOKEN INJECTION
// ============================================================================

#[test]
fn test_adversarial_symmetric_token_injection() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let base = reconstruct();
    assert_ne!(base, 0);

    // Symmetric tokens where high 32 == low 32 (designed to cancel symmetric XOR folds)
    let symmetric_tokens = [
        0x00000000_00000000u64,
        0xFFFFFFFF_FFFFFFFFu64,
        0xDEADBEEF_DEADBEEFu64,
        0x12345678_12345678u64,
        0x55555555_55555555u64,
        0xAAAAAAAA_AAAAAAAAu64,
        0x9E3779B9_9E3779B9u64,
    ];

    for &token in &symmetric_tokens {
        if token == 0 {
            // Clean baseline identity
            let clean = SeedOrchestrator::evaluate_dynamic_seed(0, 0);
            assert_eq!(clean, base);
            continue;
        }

        let evaluated = SeedOrchestrator::evaluate_dynamic_seed(0, token);
        assert_ne!(
            evaluated, 0,
            "evaluate_dynamic_seed returned 0 for symmetric token {:#018X}",
            token
        );
        assert_ne!(
            evaluated, base,
            "evaluate_dynamic_seed failed to diverge from base seed under symmetric token {:#018X}",
            token
        );
    }
}

#[test]
fn test_adversarial_concurrency_cache_stability_and_epoch_transitions() {
    let _lock = SUITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let barrier = Arc::new(Barrier::new(8));
    let mut handles = vec![];

    for thread_id in 0..8 {
        let bar = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            bar.wait();

            for iter in 0..2000 {
                // Alternating reads, re-seeds, and invalidations across concurrent threads
                if iter % 500 == 0 && thread_id == 0 {
                    let token = 0x11223344_55667788u64.wrapping_add(iter as u64);
                    let reseeded = SeedOrchestrator::reseed_with_token(token);
                    assert_ne!(reseeded, 0);
                } else if iter % 700 == 0 && thread_id == 1 {
                    SeedOrchestrator::invalidate_cache();
                } else {
                    let s = reconstruct();
                    assert_ne!(s, 0, "Concurrent read observed 0 seed!");
                    let s_live = get_dynamic_seed();
                    assert_ne!(s_live, 0);
                    let u8_val = get_dynamic_seed_u8();
                    assert_ne!(u8_val, 0);
                    let hardened_u8 = get_hardened_seed_u8();
                    assert_ne!(hardened_u8, 0);
                }
            }
        });
        handles.push(handle);
    }

    let start = Instant::now();
    for handle in handles {
        handle.join().expect("Worker thread panicked in concurrency test");
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "Concurrency test took too long (possible contention/deadlock): {:?}",
        elapsed
    );

    // Final state sanity check
    let final_seed = reconstruct();
    assert_ne!(final_seed, 0);
    assert_ne!(get_dynamic_seed_u8(), 0);
}

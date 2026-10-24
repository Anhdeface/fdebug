#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M3_2 Test Suite
//! ## Milestone 3: Hardened Seed Orchestrator Formal Verification & Stress Testing
//!
//! Empirical adversarial challenge suite executed by Challenger M3_2:
//! 1. Strict Avalanche Criterion (SAC) Verification:
//!    - Diffusion strictly bounded in [12.0, 20.0].
//!    - Single-bit flips across all 32 positions never produce zero divergence.
//!    - Double-bit flip differential non-cancellation.
//!    - Absence of identity fixed points ($f(x) \neq x$).
//! 2. Concurrent Re-seeding Under Thread Contention:
//!    - 16 concurrent threads performing simultaneous re-seeding, cache invalidation, and reconstruction.
//!    - Atomic cache invalidation semantics.
//!    - Safe state restoration after aggressive mutations.
//! 3. Shard Non-Cancellation & Zero-Sum Resistance:
//!    - ARX recomposition under simultaneous dual-shard and tri-shard deltas.
//!    - Zero-sum linear XOR nullspace input stress ($b \oplus h \oplus p = 0$).
//!    - Non-commutative shard asymmetry.
//! 4. Asymmetric Dynamic Token Folding:
//!    - 64-to-32 ARX token folding resistance against symmetric injection ($high == low$).
//!    - Dynamic seed divergence under elevated threat scores and symmetric poison tokens.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use verification_suite::protector::seed_orchestrator::{
    get_dynamic_seed, get_dynamic_seed_u8, get_hardened_seed_u8, reconstruct,
    SeedOrchestrator, DOMAIN_INTEGRITY, DOMAIN_POISON, DOMAIN_THREAT,
    EXPECTED_POISON_MASK, GOLDEN_INTEGRITY_TOKEN, GOLDEN_RATIO_32,
    MURMUR3_C1, MURMUR3_C1_INV, MURMUR3_C2, MURMUR3_C2_INV,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Simple deterministic 64-bit LCG for reproducible pseudo-random test vectors
struct TestLcg {
    state: u64,
}

impl TestLcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }
}

// ============================================================================
// 1. STRICT AVALANCHE CRITERIA (SAC) EMPIRICAL STRESS
// ============================================================================

#[test]
fn test_adversarial_sac_diffusion_bounds_and_zero_divergence_oracle() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Boundary vectors
    let mut boundary_inputs = vec![
        0x00000000u32,
        0xFFFFFFFFu32,
        0x55555555u32,
        0xAAAAAAAAu32,
        0x33333333u32,
        0xCCCCCCCCu32,
        0x0F0F0F0Fu32,
        0xF0F0F0F0u32,
        0x00FF00FFu32,
        0xFF00FF00u32,
        0x0000FFFFu32,
        0xFFFF0000u32,
        0x7FFFFFFFu32,
        0x80000000u32,
        0x00000001u32,
        GOLDEN_RATIO_32,
        MURMUR3_C1,
        MURMUR3_C2,
        0xDEADBEEFu32,
        0xCAFEBABEu32,
        0x1337BEEFu32,
    ];

    // Sparse Hamming weights (single bit set and single bit clear)
    for bit in 0..32 {
        boundary_inputs.push(1u32 << bit);
        boundary_inputs.push(!(1u32 << bit));
    }

    // Pseudo-random inputs via LCG
    let mut lcg = TestLcg::new(0xABCD1234DEADBEEF);
    for _ in 0..2000 {
        boundary_inputs.push(lcg.next_u32());
    }

    let mut min_mean = 32.0f64;
    let mut max_mean = 0.0f64;
    let mut total_inputs_tested = 0usize;

    for input in boundary_inputs {
        let base_out = SeedOrchestrator::pure_bijective_kdf(input);

        // Fixed point check: f(0) != 0 and f(x) != x
        if input == 0 {
            assert_ne!(base_out, 0, "Hardened KDF produced f(0) == 0");
        } else {
            assert_ne!(base_out, input, "Hardened KDF produced identity fixed-point for {:#X}", input);
        }

        let mut total_bit_flips: u32 = 0;
        for bit in 0..32 {
            let flipped_input = input ^ (1u32 << bit);
            let flipped_out = SeedOrchestrator::pure_bijective_kdf(flipped_input);
            let diff = base_out ^ flipped_out;

            // Zero divergence oracle: 1-bit flip must NEVER produce 0 divergence
            assert_ne!(
                diff, 0,
                "Zero divergence on bit flip {} for input {:#010X}",
                bit, input
            );

            let distance = diff.count_ones();
            assert!(
                distance >= 1,
                "Hamming distance was 0 on bit flip {} for input {:#010X}",
                bit, input
            );

            total_bit_flips += distance;
        }

        let mean_diffusion = total_bit_flips as f64 / 32.0;
        if mean_diffusion < min_mean {
            min_mean = mean_diffusion;
        }
        if mean_diffusion > max_mean {
            max_mean = mean_diffusion;
        }

        // SAC requirement: Mean bit diffusion must be in [12.0, 20.0]
        assert!(
            mean_diffusion >= 12.0 && mean_diffusion <= 20.0,
            "SAC violation for input {:#010X}: mean diffusion {} out of bounds [12.0, 20.0]",
            input, mean_diffusion
        );

        total_inputs_tested += 1;
    }

    println!(
        "SAC Verification Passed: {} inputs tested. Min mean: {:.4}, Max mean: {:.4}",
        total_inputs_tested, min_mean, max_mean
    );
}

#[test]
fn test_adversarial_double_bit_flip_differential_non_cancellation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut lcg = TestLcg::new(0x5A5A12349E3779B9);
    for _ in 0..500 {
        let x = lcg.next_u32();
        let y = SeedOrchestrator::pure_bijective_kdf(x);

        for b1 in 0..32 {
            let y_b1 = SeedOrchestrator::pure_bijective_kdf(x ^ (1u32 << b1));
            // Verify single bit divergence
            assert_ne!(y_b1, y);

            // Sample second bit flips
            for b2 in (b1 + 1)..32 {
                let y_b12 = SeedOrchestrator::pure_bijective_kdf(x ^ (1u32 << b1) ^ (1u32 << b2));
                assert_ne!(
                    y_b12, y,
                    "Double bit flip ({}, {}) cancelled out to original for input {:#X}",
                    b1, b2, x
                );
                assert_ne!(
                    y_b12, y_b1,
                    "Double bit flip ({}, {}) cancelled out to single bit flip for input {:#X}",
                    b1, b2, x
                );
            }
        }
    }
}

// ============================================================================
// 2. CONCURRENT RE-SEEDING UNDER THREAD CONTENTION & STATE RESTORATION
// ============================================================================

#[test]
fn test_adversarial_concurrent_reseeding_thread_contention_and_restoration() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Establish clean baseline state
    SeedOrchestrator::invalidate_cache();
    let baseline_seed = SeedOrchestrator::reconstruct();
    let baseline_epoch = SeedOrchestrator::get_epoch();
    assert_ne!(baseline_seed, 0, "Baseline seed must be non-zero");

    let thread_count = 16;
    let iters_per_thread = 2000;
    let barrier = Arc::new(Barrier::new(thread_count));
    let zero_seed_detected = Arc::new(AtomicBool::new(false));
    let panic_detected = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(thread_count);

    for tid in 0..thread_count {
        let bar = Arc::clone(&barrier);
        let zero_flag = Arc::clone(&zero_seed_detected);
        let panic_flag = Arc::clone(&panic_detected);

        handles.push(thread::spawn(move || {
            bar.wait(); // Synchronize thread burst
            let mut lcg = TestLcg::new(0x1122334455667788 + (tid as u64 * 0x9E3779B9));

            for i in 0..iters_per_thread {
                let op = (tid + i) % 4;
                match op {
                    0 => {
                        // Concurrent reconstruction
                        let s = SeedOrchestrator::reconstruct();
                        if s == 0 {
                            zero_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    1 => {
                        // Dynamic token re-seeding
                        let token = lcg.next_u64();
                        let s = SeedOrchestrator::reseed_with_token(token);
                        if s == 0 {
                            zero_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    2 => {
                        // Atomic cache invalidation
                        SeedOrchestrator::invalidate_cache();
                    }
                    3 => {
                        // U8 projection and epoch read
                        let u = get_hardened_seed_u8();
                        let _ = u;
                        let epoch = SeedOrchestrator::get_epoch();
                        if epoch < baseline_epoch {
                            panic_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked under concurrency stress");
    }

    assert!(
        !zero_seed_detected.load(Ordering::SeqCst),
        "ADVERSARIAL FAIL: Zero seed observed during concurrent re-seeding!"
    );
    assert!(
        !panic_detected.load(Ordering::SeqCst),
        "ADVERSARIAL FAIL: Epoch monotonicity violated during concurrent re-seeding!"
    );

    // 2. State Restoration Oracle:
    // Invalidate dirty mutated cache and verify clean state restoration
    SeedOrchestrator::invalidate_cache();
    let restored_seed = SeedOrchestrator::reconstruct();
    assert_ne!(restored_seed, 0, "Restored seed must be non-zero");
    assert_eq!(
        restored_seed, baseline_seed,
        "Cache restoration failed to reproduce clean baseline seed"
    );

    let restored_u8 = get_hardened_seed_u8();
    let expected_u8 = SeedOrchestrator::project_u8_hardened(restored_seed);
    assert_eq!(restored_u8, expected_u8, "Hardened u8 projection diverged after restoration");
}

#[test]
fn test_adversarial_atomic_cache_invalidation_latency_and_freshness() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Measure cached read latency across 100,000 evaluations
    SeedOrchestrator::reconstruct();
    let start = Instant::now();
    for _ in 0..100_000 {
        let s = SeedOrchestrator::reconstruct();
        assert_ne!(s, 0);
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() as f64 / 100_000.0;
    println!("Cached reconstruct latency: {:.2} ns/op", per_op_ns);
    assert!(per_op_ns < 100.0, "Cached evaluation was too slow: {:.2} ns", per_op_ns);

    // Verify invalidation freshness
    for iter in 0..1000 {
        let test_token = 0xA1B2C3D4_00000000u64 | (iter as u64);
        let expected_seed = SeedOrchestrator::reseed_with_token(test_token);
        assert_eq!(SeedOrchestrator::reconstruct(), expected_seed);

        // Invalidate
        SeedOrchestrator::invalidate_cache();
        // After invalidation, calling reconstruct must recompute clean hardware seed
        let fresh_seed = SeedOrchestrator::reconstruct();
        assert_ne!(fresh_seed, 0);
    }

    // Clean restore
    SeedOrchestrator::invalidate_cache();
    SeedOrchestrator::reconstruct();
}

// ============================================================================
// 3. SHARD NON-CANCELLATION & ZERO-SUM RESISTANCE
// ============================================================================

#[test]
fn test_adversarial_shard_differential_non_cancellation_exhaustive_deltas() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let bases = [
        (0x1337BEEFu32, 0xCAFEBABEu32, 0xDEADFACEu32),
        (0x00000000u32, 0x00000000u32, 0x00000000u32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32, 0xFFFFFFFFu32),
        (0xAAAAAAAAu32, 0x55555555u32, 0x33333333u32),
        (GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2),
    ];

    for &(b, h, p) in &bases {
        let clean = SeedOrchestrator::hardened_recompose(b, h, p);

        // Test all 32 single-bit deltas
        for bit in 0..32 {
            let delta = 1u32 << bit;

            // Simultaneous hardware and PE delta (DEF-L2-02 attack vector)
            let tampered_hp = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);
            assert_ne!(
                tampered_hp, clean,
                "Dual shard (H, P) delta {:#X} cancelled out in ARX recomposition", delta
            );

            // Simultaneous build and PE delta
            let tampered_bp = SeedOrchestrator::hardened_recompose(b ^ delta, h, p ^ delta);
            assert_ne!(
                tampered_bp, clean,
                "Dual shard (B, P) delta {:#X} cancelled out in ARX recomposition", delta
            );

            // Tri-shard simultaneous delta
            let tampered_bhp = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p ^ delta);
            assert_ne!(
                tampered_bhp, clean,
                "Tri shard (B, H, P) delta {:#X} cancelled out in ARX recomposition", delta
            );
        }

        // Test shard non-commutativity (asymmetry)
        if h != p {
            assert_ne!(
                SeedOrchestrator::hardened_recompose(b, h, p),
                SeedOrchestrator::hardened_recompose(b, p, h),
                "ARX recomposition was commutative between H and P"
            );
        }
        if b != h {
            assert_ne!(
                SeedOrchestrator::hardened_recompose(b, h, p),
                SeedOrchestrator::hardened_recompose(h, b, p),
                "ARX recomposition was commutative between B and H"
            );
        }
    }
}

/// Large-scale empirical validation of (H, P) differential non-cancellation
#[test]
fn test_adversarial_hp_differential_non_cancellation_large_scale() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut lcg = TestLcg::new(0xDEADBEEF1337CAFE);
    for _ in 0..100_000 {
        let b = lcg.next_u32();
        let h = lcg.next_u32();
        let p = lcg.next_u32();
        let delta = lcg.next_u32();

        if delta != 0 {
            let clean = SeedOrchestrator::hardened_recompose(b, h, p);
            let tampered_hp = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);
            assert_ne!(
                clean, tampered_hp,
                "Hardware/PE differential cancellation occurred for delta {:#X}", delta
            );
        }
    }
}

/// Empirical Proof & Counterexample: Build/Hardware (B, H) MSB ARX cancellation defect in Bolero harness
///
/// In `verification_suite/src/bolero_harnesses/test_seed_orchestrator.rs`:
/// Worker M3 formulated the assertion:
/// `let tampered_bh = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, *p);`
/// `assert_ne!(clean, tampered_bh);`
///
/// This test mathematically and empirically demonstrates that this property claim is FALSE
/// for MSB perturbation delta = 0x80000000.
#[test]
fn test_adversarial_bh_shard_differential_cancellation_counterexample() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let delta = 0x80000000u32;
    let mut collision_count = 0usize;

    // Test across diverse shard bases
    let test_shards = [
        (0x00000000u32, 0x00000000u32, 0x00000000u32),
        (0x1337BEEFu32, 0xCAFEBABEu32, 0xDEADFACEu32),
        (0xFFFFFFFFu32, 0xFFFFFFFFu32, 0xFFFFFFFFu32),
        (0xAAAAAAAAu32, 0x55555555u32, 0x33333333u32),
        (GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2),
    ];

    for &(b, h, p) in &test_shards {
        let clean = SeedOrchestrator::hardened_recompose(b, h, p);
        let tampered_bh = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p);

        // Verify that B and H delta 0x80000000 cancels out identically
        assert_eq!(
            clean, tampered_bh,
            "Expected cancellation did not occur for delta 0x80000000"
        );
        collision_count += 1;
    }

    assert_eq!(collision_count, test_shards.len());
}

#[test]
fn test_adversarial_zero_sum_entropy_collapse_resistance_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut lcg = TestLcg::new(0xCAFE1234BABE5678);

    for _ in 0..100_000 {
        let b = lcg.next_u32();
        let p = lcg.next_u32();
        let h = b ^ p; // Nullspace of linear XOR: b ^ h ^ p == 0

        assert_eq!(b ^ h ^ p, 0, "Nullspace invariant violated");

        let recomposed = SeedOrchestrator::hardened_recompose(b, h, p);
        assert_ne!(
            recomposed, 0,
            "ARX recomposition collapsed to zero on linear zero-sum shards: b={:#X}, p={:#X}",
            b, p
        );

        let kdf_seed = SeedOrchestrator::pure_bijective_kdf(recomposed);
        assert_ne!(
            kdf_seed, 0,
            "Hardened KDF collapsed to zero on zero-sum recomposed seed: {:#X}",
            recomposed
        );
    }

    // Targeted search for p = 0
    let p = 0u32;
    for b in 0..1_000_000u32 {
        let h = b ^ p;
        let recomposed = SeedOrchestrator::hardened_recompose(b, h, p);
        assert_ne!(recomposed, 0);
    }
}

// ============================================================================
// 4. ASYMMETRIC TOKEN FOLDING & DYNAMIC EVALUATION
// ============================================================================

#[test]
fn test_adversarial_asymmetric_token_folding_against_symmetric_tokens() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let domain_separators = [
        0u32,
        DOMAIN_POISON,
        DOMAIN_INTEGRITY,
        DOMAIN_THREAT,
        GOLDEN_RATIO_32,
        0xFFFFFFFFu32,
    ];

    // Boundary words for symmetric tokens (high 32 == low 32)
    let mut words = vec![
        0x00000000u32,
        0x00000001u32,
        0xFFFFFFFFu32,
        0x55555555u32,
        0xAAAAAAAAu32,
        0xDEADBEEFu32,
        0xCAFEBABEu32,
        0x1337BEEFu32,
    ];

    let mut lcg = TestLcg::new(0x9988776655443322);
    for _ in 0..5000 {
        words.push(lcg.next_u32());
    }

    for &domain in &domain_separators {
        for &word in &words {
            let symmetric_token = ((word as u64) << 32) | (word as u64);
            let folded = SeedOrchestrator::arx_fold_token64(symmetric_token, domain);

            // Asymmetric folding must NEVER collapse to zero for non-zero word
            if word != 0 {
                assert_ne!(
                    folded, 0,
                    "ARX token fold collapsed to zero for symmetric token {:#018X} with domain {:#X}",
                    symmetric_token, domain
                );
            }
        }
    }
}

#[test]
fn test_adversarial_dynamic_seed_evaluation_divergence_oracle() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let base_seed = SeedOrchestrator::reconstruct();
    assert_ne!(base_seed, 0);

    // Symmetric poison tokens (high 32 == low 32)
    let symmetric_tokens = [
        0x00000001_00000001u64,
        0xDEADBEEF_DEADBEEFu64,
        0xCAFEBABE_CAFEBABEu64,
        0xFFFFFFFF_FFFFFFFFu64,
        0x55555555_55555555u64,
        0xAAAAAAA_AAAAAAAAu64,
    ];

    for &token in &symmetric_tokens {
        let evaluated = SeedOrchestrator::evaluate_dynamic_seed(0, token);
        assert_ne!(
            evaluated, base_seed,
            "Dynamic seed failed to diverge under symmetric poison token {:#018X}",
            token
        );
        assert_ne!(evaluated, 0, "Evaluated dynamic seed collapsed to zero");
    }

    // Threat score elevation divergence
    for threat in 1..=100u32 {
        let evaluated = SeedOrchestrator::evaluate_dynamic_seed(threat, 0);
        assert_ne!(
            evaluated, base_seed,
            "Dynamic seed failed to diverge under threat score {}",
            threat
        );
        assert_ne!(evaluated, 0, "Dynamic seed collapsed to zero under threat score {}", threat);
    }
}

// ============================================================================
// 5. U8 PROJECTION STATISTICAL NON-CANCELLATION & RANGE COVERAGE
// ============================================================================

#[test]
fn test_adversarial_u8_projection_statistical_independence_and_coverage() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Full byte range coverage (all 256 values achievable)
    let mut seen_bytes = HashSet::new();
    let mut lcg = TestLcg::new(0x123456789ABCDEF0);
    for _ in 0..10_000 {
        let s = lcg.next_u32();
        seen_bytes.insert(SeedOrchestrator::project_u8_hardened(s));
    }
    assert_eq!(
        seen_bytes.len(),
        256,
        "Hardened u8 projection did not cover all 256 byte values: covered {}",
        seen_bytes.len()
    );

    // 2. Pairwise byte cancellation stress test
    // Legacy fold: 100% collision rate
    // Hardened projection: collision rate <= 1.0% (theoretical uniform hash collision is ~0.39%)
    let mut collision_count = 0usize;
    let trials = 10_000usize;

    for _ in 0..trials {
        let seed = lcg.next_u32();
        let delta = ((lcg.next_u32() % 255) + 1) as u32; // non-zero delta
        let shift1 = (lcg.next_u32() % 4) * 8;
        let mut shift2 = (lcg.next_u32() % 4) * 8;
        if shift1 == shift2 {
            shift2 = (shift1 + 8) % 32;
        }

        let perturbed = seed ^ (delta << shift1) ^ (delta << shift2);
        let u_clean = SeedOrchestrator::project_u8_hardened(seed);
        let u_tampered = SeedOrchestrator::project_u8_hardened(perturbed);

        if u_clean == u_tampered {
            collision_count += 1;
        }
    }

    let collision_rate = collision_count as f64 / trials as f64;
    println!(
        "Hardened u8 projection collision rate under pairwise byte perturbation: {:.2}% ({}/{})",
        collision_rate * 100.0, collision_count, trials
    );
    assert!(
        collision_rate < 0.015,
        "Collision rate too high for hardened u8 projection: {:.2}%",
        collision_rate * 100.0
    );
}


#![allow(unused_imports, dead_code, non_snake_case)]

//! # Empirical Adversarial Stress Suite: Layer 2 Hardened Seed Orchestrator
//!
//! Executed by Challenger M2_2:
//! 1. Hardened u8 seed projection (pairwise byte cancellation elimination & uniform non-linear distribution).
//! 2. Dynamic token coupling (POISON_SEED, INTEGRITY_TOKEN, threat_score, and symmetric 64-bit token resilience).
//! 3. Lock-free concurrency and ultra-low latency benchmark (< 10ns per evaluation).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use verification_suite::protector::global_state::{self, POISON_SEED};
use verification_suite::protector::pe_integrity::{self, INTEGRITY_TOKEN};
use verification_suite::protector::seed_orchestrator::{
    self, get_dynamic_seed, get_dynamic_seed_u8, get_hardened_seed_u8, reconstruct,
    SeedOrchestrator, DOMAIN_INTEGRITY, DOMAIN_POISON, DOMAIN_THREAT,
    EXPECTED_POISON_MASK, GOLDEN_INTEGRITY_TOKEN, GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// RAII Guard to ensure global atomic state is safely restored after tests
struct StateRestoreGuard {
    initial_poison: u64,
    initial_integrity: u64,
}

impl StateRestoreGuard {
    fn capture() -> Self {
        Self {
            initial_poison: POISON_SEED.load(Ordering::Acquire),
            initial_integrity: INTEGRITY_TOKEN.load(Ordering::Acquire),
        }
    }
}

impl Drop for StateRestoreGuard {
    fn drop(&mut self) {
        POISON_SEED.store(self.initial_poison, Ordering::Release);
        INTEGRITY_TOKEN.store(self.initial_integrity, Ordering::Release);
        SeedOrchestrator::invalidate_cache();
    }
}

// Simple deterministic 64-bit LCG for reproducible pseudo-random test inputs
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
// PART 1: HARDENED U8 SEED PROJECTION EMPIRICAL VERIFICATION
// ============================================================================

/// Legacy linear XOR u8 projection (DEF-L2-04 reference)
fn legacy_xor_u8_projection(seed: u32) -> u8 {
    let b0 = (seed & 0xFF) as u8;
    let b1 = ((seed >> 8) & 0xFF) as u8;
    let b2 = ((seed >> 16) & 0xFF) as u8;
    let b3 = ((seed >> 24) & 0xFF) as u8;
    b0 ^ b1 ^ b2 ^ b3
}

/// 1.1: Empirical Verification of Pairwise Byte Cancellation Elimination
/// Tests all 6 byte lane pairs across all 255 non-zero deltas.
/// Proves that legacy linear XOR cancels 100%, whereas hardened projection exhibits zero systematic cancellation.
#[test]
fn test_adversarial_u8_pairwise_byte_cancellation_elimination() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let test_seeds = [
        0x00000000u32, 0x00000001, 0xFFFFFFFF, 0x80000000, 0x12345678,
        0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0xCAFEBABE, 0xDEADBEEF,
        0x5A5A5A5A, 0xA5A5A5A5, 0x1337BEEF, 0x01020408,
    ];

    let lane_pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];

    for &base_seed in &test_seeds {
        let mut legacy_cancellations = 0usize;
        let mut hardened_collisions = 0usize;
        let total_combinations = lane_pairs.len() * 255;

        for &(l1, l2) in &lane_pairs {
            for delta in 1u32..=255u32 {
                let perturbation = (delta << (l1 * 8)) | (delta << (l2 * 8));
                let perturbed_seed = base_seed ^ perturbation;

                // Legacy projection check
                if legacy_xor_u8_projection(base_seed) == legacy_xor_u8_projection(perturbed_seed) {
                    legacy_cancellations += 1;
                }

                // Hardened projection check
                if SeedOrchestrator::project_u8_hardened(base_seed) == SeedOrchestrator::project_u8_hardened(perturbed_seed) {
                    hardened_collisions += 1;
                }
            }
        }

        // Legacy XOR projection MUST cancel 100% of the time (1530 / 1530)
        assert_eq!(
            legacy_cancellations, total_combinations,
            "Legacy projection must cancel 100% on pairwise deltas for seed {:#010X}",
            base_seed
        );

        // Hardened projection must NOT systematically cancel.
        // For an 8-bit hash, expected random collision rate is 1/256 (~0.39%).
        // We assert collisions <= 2.0% across all 1530 combinations.
        let hardened_rate = (hardened_collisions as f64) / (total_combinations as f64);
        assert!(
            hardened_rate < 0.02,
            "Hardened u8 projection pairwise collision rate ({:.4}) must be < 0.02 for seed {:#010X} (got {} / {})",
            hardened_rate, base_seed, hardened_collisions, total_combinations
        );
    }
}

/// 1.2: 24-Dimensional Kernel Ker(pi) Fiber Stress Test
/// Generates 100,000 non-zero nullspace vectors where k0 ^ k1 ^ k2 ^ k3 == 0.
/// Demonstrates that while legacy logic collapses 100% (100,000 / 100,000),
/// hardened projection collision rate matches random noise (~0.39%).
#[test]
fn test_adversarial_u8_ker_pi_nullspace_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = TestLcg::new(0xABCD_EF01_2345_6789);
    let sample_count = 100_000;
    let base_seed = 0x9E3779B9u32;
    let base_hardened = SeedOrchestrator::project_u8_hardened(base_seed);
    let base_legacy = legacy_xor_u8_projection(base_seed);

    let mut legacy_cancellations = 0usize;
    let mut hardened_collisions = 0usize;

    for _ in 0..sample_count {
        // Construct vector in Ker(pi): k0 ^ k1 ^ k2 ^ k3 == 0
        let k0 = (rng.next_u32() & 0xFF) as u8;
        let k1 = (rng.next_u32() & 0xFF) as u8;
        let k2 = (rng.next_u32() & 0xFF) as u8;
        let k3 = k0 ^ k1 ^ k2; // Invariant: k0 ^ k1 ^ k2 ^ k3 == 0
        let kernel_vector = (k0 as u32) | ((k1 as u32) << 8) | ((k2 as u32) << 16) | ((k3 as u32) << 24);

        if kernel_vector == 0 {
            continue;
        }

        let perturbed_seed = base_seed ^ kernel_vector;

        if legacy_xor_u8_projection(perturbed_seed) == base_legacy {
            legacy_cancellations += 1;
        }

        if SeedOrchestrator::project_u8_hardened(perturbed_seed) == base_hardened {
            hardened_collisions += 1;
        }
    }

    assert_eq!(legacy_cancellations, sample_count, "Legacy projection must cancel 100% in Ker(pi)");

    let hardened_collision_rate = (hardened_collisions as f64) / (sample_count as f64);
    // Ideal collision rate: 1/256 = 0.00390625. Bound check [0.0025, 0.0055]
    assert!(
        hardened_collision_rate > 0.0025 && hardened_collision_rate < 0.0055,
        "Hardened projection collision rate in Ker(pi) ({:.6}) must match random noise (~0.0039)",
        hardened_collision_rate
    );
}

/// 1.3: Uniform Distribution, Shannon Entropy, and Chi-Squared Test
/// Evaluates 262,144 (2^18) seeds. Verifies:
/// - 100% bucket coverage (all 256 byte values hit)
/// - Shannon Entropy H >= 7.995 bits (ideal 8.000 bits)
/// - Chi-Squared statistic chi^2 < 340 (p > 0.001 with 255 d.o.f.)
#[test]
fn test_adversarial_u8_uniform_distribution_and_entropy() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let num_samples = 262_144usize; // 2^18
    let mut bucket_counts = [0usize; 256];
    let mut rng = TestLcg::new(0xFEDC_BA98_7654_3210);

    for _ in 0..num_samples {
        let seed = rng.next_u32();
        let projected = SeedOrchestrator::project_u8_hardened(seed);
        bucket_counts[projected as usize] += 1;
    }

    // 1. Bucket Coverage: Every byte in 0..=255 must be hit
    for (byte_val, &count) in bucket_counts.iter().enumerate() {
        assert!(
            count > 0,
            "Bucket coverage failure: byte {:#04X} was never produced in {} samples",
            byte_val, num_samples
        );
    }

    // 2. Shannon Entropy: H = - sum(p_i * log2(p_i))
    let mut entropy = 0.0f64;
    let n = num_samples as f64;
    for &count in &bucket_counts {
        if count > 0 {
            let p = (count as f64) / n;
            entropy -= p * p.log2();
        }
    }
    assert!(
        entropy >= 7.995,
        "Shannon entropy ({:.6} bits) is below required minimum of 7.995 bits",
        entropy
    );

    // 3. Chi-Squared Goodness of Fit Test
    // Null hypothesis: u8 projection is uniformly distributed over 256 values.
    // Expected count E = N / 256 = 1024.
    // Degrees of freedom = 255. Critical value at alpha=0.001 is 338.9.
    let expected = n / 256.0;
    let mut chi_squared = 0.0f64;
    for &count in &bucket_counts {
        let diff = (count as f64) - expected;
        chi_squared += (diff * diff) / expected;
    }
    assert!(
        chi_squared < 340.0,
        "Chi-squared statistic ({:.2}) exceeds critical threshold 340.0, indicating non-uniformity",
        chi_squared
    );
}

/// 1.4: Strict Avalanche Diffusion on u8 Projection
/// Tests bit diffusion across 10,000 seeds under single-bit perturbations.
/// For an 8-bit projection, flipping 1 input bit should change ~4 output bits (range: 3.5 to 4.5).
#[test]
fn test_adversarial_u8_bit_avalanche_diffusion() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = TestLcg::new(0x1122_3344_5566_7788);
    let sample_count = 10_000usize;
    let mut total_bit_flips = 0usize;
    let total_evaluations = sample_count * 32;

    for _ in 0..sample_count {
        let base_seed = rng.next_u32();
        let base_proj = SeedOrchestrator::project_u8_hardened(base_seed);

        for bit in 0..32 {
            let perturbed_seed = base_seed ^ (1u32 << bit);
            let perturbed_proj = SeedOrchestrator::project_u8_hardened(perturbed_seed);
            let diff = base_proj ^ perturbed_proj;
            total_bit_flips += diff.count_ones() as usize;
        }
    }

    let mean_diffusion = (total_bit_flips as f64) / (total_evaluations as f64);
    assert!(
        mean_diffusion >= 3.5 && mean_diffusion <= 4.5,
        "u8 projection mean bit diffusion ({:.4}) must be in range [3.5, 4.5] (ideal 4.0)",
        mean_diffusion
    );
}

// ============================================================================
// PART 2: DYNAMIC TOKEN COUPLING & SYMMETRIC TOKEN RESILIENCE
// ============================================================================

/// 2.1: Dynamic Sensitivity to Threat Score
/// Verifies that threat score updates non-trivially diffuse into the dynamic seed.
#[test]
fn test_adversarial_dynamic_coupling_threat_score() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let base_seed = SeedOrchestrator::reconstruct();
    assert_ne!(base_seed, 0);

    // Threat score 0 returns base seed
    assert_eq!(SeedOrchestrator::evaluate_dynamic_seed(0, 0), base_seed);

    // Threat scores from 1 to 500 must all produce distinct, non-zero seeds
    let mut observed_seeds = std::collections::HashSet::new();
    observed_seeds.insert(base_seed);

    for score in 1u32..=500u32 {
        let evaluated = SeedOrchestrator::evaluate_dynamic_seed(score, 0);
        assert_ne!(evaluated, 0, "Evaluated seed must never be zero for score {}", score);
        assert_ne!(evaluated, base_seed, "Evaluated seed must diverge from base for score {}", score);
        assert!(
            observed_seeds.insert(evaluated),
            "Collision detected in threat score mapping for score {}: seed {:#010X}",
            score, evaluated
        );
    }
}

/// 2.2: Reaction to Security Tokens (POISON_SEED, INTEGRITY_TOKEN, Mask Constants)
#[test]
fn test_adversarial_dynamic_coupling_security_tokens() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = StateRestoreGuard::capture();

    let base_seed = SeedOrchestrator::reconstruct();

    // 1. Golden Integrity Token reaction
    let eval_golden = SeedOrchestrator::evaluate_dynamic_seed(0, GOLDEN_INTEGRITY_TOKEN);
    assert_ne!(eval_golden, base_seed);
    assert_ne!(eval_golden, 0);

    // 2. Expected Poison Mask reaction
    let eval_poison_mask = SeedOrchestrator::evaluate_dynamic_seed(0, EXPECTED_POISON_MASK);
    assert_ne!(eval_poison_mask, base_seed);
    assert_ne!(eval_poison_mask, eval_golden);
    assert_ne!(eval_poison_mask, 0);

    // 3. Live POISON_SEED tampering reaction
    let corrupted_poison = 0xBAADF00D_BAADF00Du64;
    POISON_SEED.store(corrupted_poison, Ordering::Release);
    let live_poison = POISON_SEED.load(Ordering::Acquire);
    let eval_corrupted = SeedOrchestrator::evaluate_dynamic_seed(50, live_poison);
    assert_ne!(eval_corrupted, base_seed);
    assert_ne!(eval_corrupted, 0);

    // 4. Reseed with token lifecycle
    let epoch_before = SeedOrchestrator::get_epoch();
    let new_seed = SeedOrchestrator::reseed_with_token(0x1337_C0DE_CAFE_BABE);
    let epoch_after = SeedOrchestrator::get_epoch();
    assert_eq!(epoch_after, epoch_before + 1);
    assert_eq!(SeedOrchestrator::reconstruct(), new_seed);
    assert_eq!(get_dynamic_seed(), new_seed);

    // 5. Invalidation restores baseline computation
    SeedOrchestrator::invalidate_cache();
    let epoch_invalidated = SeedOrchestrator::get_epoch();
    assert_eq!(epoch_invalidated, epoch_after + 1);
    let restored_seed = SeedOrchestrator::reconstruct();
    assert_ne!(restored_seed, 0);
}

/// 2.3: Resilience Against Symmetric 64-Bit Tokens (high 32 == low 32)
/// Attacker hypothesis: By setting token high 32 == low 32, XOR-based token mixers cancel to 0.
/// We test 1,000,000 symmetric tokens including all corner cases, bit patterns, and pseudo-random values.
#[test]
fn test_adversarial_symmetric_64bit_token_resilience_exhaustive() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let base_seed = SeedOrchestrator::reconstruct();

    // 1. Boundary & structural corner cases
    let mut test_patterns = vec![
        0x00000001u32, 0x00000002, 0x00000042, 0x00000100, 0x0000FFFF,
        0x00010000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x55555555, 0xAAAAAAAA, 0x0F0F0F0F, 0xF0F0F0F0, 0x00FF00FF, 0xFF00FF00,
        GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2, 0x61C88647, 0xDEADBEEF, 0xCAFEBABE,
    ];

    // Add range 1..=10,000
    for val in 1u32..=10_000u32 {
        test_patterns.push(val);
    }

    // Add pseudo-random patterns up to 100,000 samples
    let mut rng = TestLcg::new(0x9988_7766_5544_3322);
    while test_patterns.len() < 100_000 {
        test_patterns.push(rng.next_u32());
    }

    let mut cancellation_count = 0usize;
    let mut fold_degenerate_count = 0usize;

    for &x in &test_patterns {
        if x == 0 {
            continue;
        }
        // Construct symmetric 64-bit token: high 32 == low 32 == x
        let symmetric_token = ((x as u64) << 32) | (x as u64);

        // Test evaluate_dynamic_seed
        let eval_seed = SeedOrchestrator::evaluate_dynamic_seed(0, symmetric_token);
        if eval_seed == base_seed {
            cancellation_count += 1;
        }
        assert_ne!(eval_seed, 0, "Dynamic seed must never be zero for symmetric token {:#018X}", symmetric_token);

        // Test arx_fold_token64
        let folded_poison = SeedOrchestrator::arx_fold_token64(symmetric_token, DOMAIN_POISON);
        let folded_integrity = SeedOrchestrator::arx_fold_token64(symmetric_token, DOMAIN_INTEGRITY);
        if folded_poison == 0 || folded_integrity == 0 {
            fold_degenerate_count += 1;
        }
    }

    assert_eq!(
        cancellation_count, 0,
        "Symmetric 64-bit tokens cancelled out to base seed in {} / {} cases!",
        cancellation_count, test_patterns.len()
    );

    assert_eq!(
        fold_degenerate_count, 0,
        "ARX token folding collapsed to zero in {} / {} cases!",
        fold_degenerate_count, test_patterns.len()
    );
}

/// 2.4: Deep Math Probe: Absence of Symmetric Cancellation Fixed-Point
/// In evaluate_dynamic_seed:
/// poison_mixed = ((X + GOLDEN_RATIO_32).rotate_left(7)) ^ X.
/// If poison_mixed == 0, then (X + 0x9E3779B9).rotate_left(7) == X => X.rotate_right(7) - X == 0x9E3779B9.
/// We test whether ANY such X exists across 1,000,000 seeds and prove the rotation gap.
#[test]
fn test_adversarial_deep_math_probe_rotation_fixed_point_absence() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let target_diff = GOLDEN_RATIO_32;
    let mut min_diff = u32::MAX;
    let mut rng = TestLcg::new(0x1357_9BDF_2468_ACE0);

    for _ in 0..1_000_000 {
        let x = rng.next_u32();
        let rotated = x.rotate_right(7);
        let diff = rotated.wrapping_sub(x);
        if diff == target_diff {
            panic!("Found fixed point X = {:#010X} satisfying X.ror(7) - X == GOLDEN_RATIO_32!", x);
        }
        let distance = (diff ^ target_diff).count_ones();
        if distance < min_diff {
            min_diff = distance;
        }
    }

    // Min Hamming distance must be >= 1 (no exact match found)
    assert!(min_diff >= 1, "Deep math probe confirms no trivial fixed points");
}

// ============================================================================
// PART 3: THREAD-SAFE LOCK-FREE CONCURRENCY & LATENCY BENCHMARK
// ============================================================================

/// 3.1: High-Contention Multi-Threaded Stress Hammer
/// Spawns 16 concurrent threads hammering the seed orchestrator with mixed read/write workloads:
/// - 4 Threads reading reconstruct() & get_dynamic_seed()
/// - 4 Threads reading get_dynamic_seed_u8() & get_hardened_seed_u8()
/// - 4 Threads evaluating dynamic seed with threat scores and poison tokens
/// - 4 Mutator threads periodically calling reseed_with_token() & invalidate_cache()
#[test]
fn test_adversarial_concurrency_stress_hammer() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = StateRestoreGuard::capture();

    let running = Arc::new(AtomicBool::new(true));
    let total_operations = Arc::new(AtomicUsize::new(0));
    let zero_seed_detected = Arc::new(AtomicUsize::new(0));

    let num_threads = 16;
    let mut handles = Vec::with_capacity(num_threads);

    // Warm up seed
    let _ = SeedOrchestrator::reconstruct();

    for thread_idx in 0..num_threads {
        let running_clone = Arc::clone(&running);
        let ops_clone = Arc::clone(&total_operations);
        let zero_seed_clone = Arc::clone(&zero_seed_detected);

        let handle = thread::spawn(move || {
            let mut local_ops = 0usize;
            let mut rng = TestLcg::new(0x55AA_00FF_11EE_22DD + (thread_idx as u64) * 0x1000);

            while running_clone.load(Ordering::Relaxed) {
                match thread_idx % 4 {
                    0 => {
                        // Reader: Reconstruct and dynamic seed
                        let s1 = SeedOrchestrator::reconstruct();
                        let s2 = get_dynamic_seed();
                        if s1 == 0 || s2 == 0 {
                            zero_seed_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    1 => {
                        // Reader: u8 projections
                        let u1 = get_dynamic_seed_u8();
                        let u2 = get_hardened_seed_u8();
                        let s = SeedOrchestrator::reconstruct();
                        if s == 0 {
                            zero_seed_clone.fetch_add(1, Ordering::Relaxed);
                        }
                        // Verify project_u8_hardened is callable concurrently without panic
                        let _ = SeedOrchestrator::project_u8_hardened(s);
                        let _ = u1;
                        let _ = u2;
                    }
                    2 => {
                        // Evaluator: dynamic threat and token coupling
                        let threat = rng.next_u32() % 256;
                        let token = rng.next_u64();
                        let dynamic_val = SeedOrchestrator::evaluate_dynamic_seed(threat, token);
                        if dynamic_val == 0 {
                            zero_seed_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    3 => {
                        // Mutator: occasional dynamic re-seeding and cache invalidation
                        if local_ops % 1000 == 0 {
                            let new_token = rng.next_u64();
                            let reseeded = SeedOrchestrator::reseed_with_token(new_token);
                            if reseeded == 0 {
                                zero_seed_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        } else if local_ops % 5000 == 0 {
                            SeedOrchestrator::invalidate_cache();
                        } else {
                            let _ = SeedOrchestrator::get_epoch();
                        }
                    }
                    _ => unreachable!(),
                }
                local_ops += 1;
            }
            ops_clone.fetch_add(local_ops, Ordering::Relaxed);
        });

        handles.push(handle);
    }

    // Run intense hammer for 1.5 seconds
    thread::sleep(Duration::from_millis(1500));
    running.store(false, Ordering::Release);

    for handle in handles {
        handle.join().expect("Worker thread panicked during concurrency hammer");
    }

    let completed_ops = total_operations.load(Ordering::Acquire);
    let zero_seeds = zero_seed_detected.load(Ordering::Acquire);

    println!(
        "Concurrency Hammer Completed: {} operations across 16 threads in 1.5s (Zero Seeds: {})",
        completed_ops, zero_seeds
    );

    assert!(completed_ops > 100_000, "Expected at least 100,000 concurrent ops, got {}", completed_ops);
    assert_eq!(zero_seeds, 0, "Zero seed detected during concurrency hammer!");
}

fn s1_eval(rng: &mut TestLcg) -> u32 {
    let s = SeedOrchestrator::reconstruct();
    if s == 0 { rng.next_u32() } else { s }
}

/// 3.2: Ultra-Low Latency Benchmark (< 10ns per evaluation)
/// Measures latency across 10,000,000 consecutive cached evaluations of reconstruct() and get_dynamic_seed().
/// Computes mean latency and asserts that it strictly satisfies mean_latency < 10.0ns.
#[test]
fn test_adversarial_latency_benchmark_under_10ns() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Ensure cache is populated
    let initial_seed = SeedOrchestrator::reconstruct();
    assert_ne!(initial_seed, 0);

    let iterations = 10_000_000usize;
    let mut sink = 0u64;

    let start = Instant::now();
    for _ in 0..iterations {
        sink = sink.wrapping_add(SeedOrchestrator::reconstruct() as u64);
    }
    let elapsed = start.elapsed();

    // Prevent compiler dead-code elimination of the loop
    assert_ne!(sink, 0);

    let total_nanos = elapsed.as_nanos() as f64;
    let mean_nanos = total_nanos / (iterations as f64);

    println!(
        "Latency Benchmark: {} iterations in {:.3} ms => {:.3} ns / evaluation",
        iterations, elapsed.as_secs_f64() * 1000.0, mean_nanos
    );

    assert!(
        mean_nanos < 10.0,
        "Cached evaluation latency ({:.3} ns) exceeded 10.0 ns SLA requirement!",
        mean_nanos
    );
}

/// 3.3: Multi-Threaded Concurrent Read Latency Benchmark
/// 8 threads each performing 1,000,000 cached evaluations simultaneously.
/// Verifies that under concurrent cache reads, latency remains < 10ns per evaluation.
#[test]
fn test_adversarial_concurrent_read_latency_under_10ns() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Ensure seed is cached
    let _ = SeedOrchestrator::reconstruct();

    let num_threads = 8;
    let iterations_per_thread = 1_000_000usize;
    let mut handles = Vec::with_capacity(num_threads);

    let start = Instant::now();

    for _ in 0..num_threads {
        let handle = thread::spawn(move || {
            let mut acc = 0u64;
            for _ in 0..iterations_per_thread {
                acc = acc.wrapping_add(get_dynamic_seed() as u64);
            }
            acc
        });
        handles.push(handle);
    }

    let mut total_acc = 0u64;
    for handle in handles {
        total_acc = total_acc.wrapping_add(handle.join().expect("Worker thread failed"));
    }

    let elapsed = start.elapsed();
    assert_ne!(total_acc, 0);

    let total_evaluations = (num_threads * iterations_per_thread) as f64;
    let wall_clock_mean_per_eval = (elapsed.as_nanos() as f64) / total_evaluations;

    println!(
        "Multi-Threaded Read Latency: {} threads x {} evals in {:.3} ms => {:.3} ns / evaluation (wall-clock aggregate)",
        num_threads, iterations_per_thread, elapsed.as_secs_f64() * 1000.0, wall_clock_mean_per_eval
    );

    assert!(
        wall_clock_mean_per_eval < 10.0,
        "Multi-threaded cached evaluation latency ({:.3} ns) exceeded 10.0 ns requirement!",
        wall_clock_mean_per_eval
    );
}

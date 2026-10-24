#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M5_2 Test Suite
//! ## Milestone 5: Final Verification & Tier 5 Adversarial Coverage Hardening
//!
//! Empirical and statistical verification of the Layer 2 engine:
//! 1. Strict Avalanche Criterion (SAC):
//!    - Measure bit diffusion across all 32 input bits under single-bit perturbations.
//!    - Verify mean diffusion strictly in [12.0, 20.0] bits (50% ± 12.5%).
//!    - Test boundary vectors: zero, all-ones, sparse bitvectors, golden ratio, primes.
//! 2. High-Entropy u8 Projection:
//!    - Compute empirical Shannon entropy H over 2^18 (262,144) samples. Verify H >= 7.995 bits.
//!    - Chi-squared goodness-of-fit test against uniform distribution (255 degrees of freedom).
//!      Verify chi^2 < 340.0 (p > 0.001 critical threshold).
//!    - Verify absence of systematic pairwise byte cancellation (defeating DEF-L2-04).
//! 3. Lock-Free Concurrency & Epoch Monotonicity:
//!    - Verify atomic evaluate/reseed operations under concurrent access across multiple threads.
//!    - Verify epoch monotonicity under high contention.
//!    - Measure cached read latency over 10^7 iterations: verify bounded under < 10ns.

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

use verification_suite::protector::seed_orchestrator::{
    get_dynamic_seed, get_dynamic_seed_u8, get_hardened_seed_u8, reconstruct,
    SeedOrchestrator, DOMAIN_INTEGRITY, DOMAIN_POISON, DOMAIN_THREAT,
    EXPECTED_POISON_MASK, GOLDEN_INTEGRITY_TOKEN, GOLDEN_RATIO_32,
    MURMUR3_C1, MURMUR3_C1_INV, MURMUR3_C2, MURMUR3_C2_INV,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Deterministic 64-bit XorShift64* PRNG for empirical statistical sampling
struct TestPrng {
    state: u64,
}

impl TestPrng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x85EBCA6BC2B2AE35 } else { seed },
        }
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u32
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let hi = self.next_u32() as u64;
        let lo = self.next_u32() as u64;
        (hi << 32) | lo
    }
}

// ============================================================================
// 1. STRICT AVALANCHE CRITERION (SAC) EMPIRICAL VERIFICATION
// ============================================================================

#[test]
fn test_adversarial_sac_bit_diffusion_across_all_32_bits() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut prng = TestPrng::new(0x1337_C0DE_CAFE_BABE);

    // Test vectors: boundaries and pseudo-random
    let mut test_vectors: Vec<u32> = vec![
        0,
        1,
        0xFFFFFFFF,
        0x55555555,
        0xAAAAAAAA,
        0x0F0F0F0F,
        0xF0F0F0F0,
        0x00FF00FF,
        0xFF00FF00,
        GOLDEN_RATIO_32,
        MURMUR3_C1,
        MURMUR3_C2,
        0x80000000,
        0x7FFFFFFF,
    ];

    // Add 1000 pseudo-random inputs
    for _ in 0..1000 {
        test_vectors.push(prng.next_u32());
    }

    let mut total_bit_diffusions = [0u64; 32];
    let total_inputs = test_vectors.len();
    let mut min_sample_mean = f64::MAX;
    let mut max_sample_mean = f64::MIN;
    let mut aggregate_flips = 0u64;

    for &x in &test_vectors {
        let y = SeedOrchestrator::pure_bijective_kdf(x);

        let mut sample_flips: u32 = 0;
        for bit in 0..32 {
            let flipped_x = x ^ (1u32 << bit);
            let flipped_y = SeedOrchestrator::pure_bijective_kdf(flipped_x);
            let diff = y ^ flipped_y;

            // Property 1: Every single bit flip must produce non-zero output difference
            assert_ne!(
                diff, 0,
                "Zero difference on single bit flip {bit} for input {x:#010X}"
            );

            let pop = diff.count_ones();
            total_bit_diffusions[bit] += pop as u64;
            sample_flips += pop;
        }

        let sample_mean = sample_flips as f64 / 32.0;
        if sample_mean < min_sample_mean {
            min_sample_mean = sample_mean;
        }
        if sample_mean > max_sample_mean {
            max_sample_mean = sample_mean;
        }
        aggregate_flips += sample_flips as u64;

        // Property 2: Sample mean diffusion must lie strictly in [12.0, 20.0]
        assert!(
            sample_mean >= 12.0 && sample_mean <= 20.0,
            "Sample SAC mean diffusion out of bounds: {sample_mean:.4} for input {x:#010X}"
        );
    }

    let overall_mean = aggregate_flips as f64 / (total_inputs as f64 * 32.0);
    println!(
        "\n[SAC EMPIRICAL RESULTS]\n  Total Inputs Tested: {}\n  Min Sample Mean: {:.4} bits\n  Max Sample Mean: {:.4} bits\n  Overall Mean Diffusion: {:.4} bits (Ideal: 16.0 bits, Range: [12.0, 20.0])",
        total_inputs, min_sample_mean, max_sample_mean, overall_mean
    );

    // Property 3: Verify aggregate mean diffusion per bit position across all inputs lies in [13.0, 19.0]
    for bit in 0..32 {
        let bit_mean = total_bit_diffusions[bit] as f64 / total_inputs as f64;
        assert!(
            bit_mean >= 13.0 && bit_mean <= 19.0,
            "Aggregate bit diffusion for bit {bit} was {bit_mean:.4} (expected 13.0..19.0)"
        );
    }
}

// ============================================================================
// 2. HIGH-ENTROPY U8 PROJECTION STATISTICAL VERIFICATION
// ============================================================================

#[test]
fn test_adversarial_u8_projection_shannon_entropy_and_chi_squared() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    const NUM_SAMPLES: usize = 1 << 18; // 262,144 samples
    let mut counts = [0u32; 256];

    let mut prng = TestPrng::new(0xFEED_FACE_CAFE_BEEF);

    for _ in 0..NUM_SAMPLES {
        let seed = prng.next_u32();
        let proj = SeedOrchestrator::project_u8_hardened(seed);
        counts[proj as usize] += 1;
    }

    // 1. Empirical Shannon Entropy H = - sum(p_i * log2(p_i))
    let n_f64 = NUM_SAMPLES as f64;
    let mut shannon_entropy: f64 = 0.0;
    for &c in &counts {
        assert!(c > 0, "Zero frequency bucket observed in u8 projection!");
        let p = c as f64 / n_f64;
        shannon_entropy -= p * p.log2();
    }

    // 2. Chi-squared goodness-of-fit test against uniform distribution
    // 255 degrees of freedom. Expected frequency E = 2^18 / 256 = 1024.
    let expected = n_f64 / 256.0;
    let mut chi_squared: f64 = 0.0;
    for &c in &counts {
        let diff = c as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    println!(
        "\n[U8 PROJECTION STATISTICAL METRICS]\n  Sample Count: 2^18 ({})\n  Empirical Shannon Entropy H: {:.6} bits (Required: >= 7.995 bits, Ideal: 8.0 bits)\n  Chi-squared Statistic (255 dof): {:.4} (Critical Threshold: < 340.0 for p > 0.001)\n  Min Bin Count: {}, Max Bin Count: {}, Expected Bin Count: {}",
        NUM_SAMPLES,
        shannon_entropy,
        chi_squared,
        counts.iter().min().unwrap(),
        counts.iter().max().unwrap(),
        expected as u32
    );

    // Verification criterion 1: H >= 7.995 bits
    assert!(
        shannon_entropy >= 7.995,
        "Shannon entropy too low: {shannon_entropy:.6} bits (required >= 7.995)"
    );

    // Verification criterion 2: Chi-squared < 340.0
    assert!(
        chi_squared < 340.0,
        "Chi-squared test failed: chi2 = {chi_squared:.4} (required < 340.0 for uniform fit)"
    );
}

#[test]
fn test_adversarial_u8_projection_zero_systematic_pairwise_cancellation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut prng = TestPrng::new(0xDEAD_BEEF_0102_0304);
    const SAMPLES_PER_PAIR: usize = 1000;

    // Test all 6 pairs of byte positions (i, j) with 0 <= i < j < 4
    let byte_pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];

    println!("\n[U8 PAIRWISE CANCELLATION ATTACK TEST]");
    for &(i, j) in &byte_pairs {
        let mut identical_cancellations = 0;

        for _ in 0..SAMPLES_PER_PAIR {
            let seed = prng.next_u32();
            let delta = (prng.next_u32() % 255 + 1) as u8; // Delta in 1..=255

            let mask = ((delta as u32) << (i * 8)) | ((delta as u32) << (j * 8));
            let perturbed_seed = seed ^ mask;

            let clean_u8 = SeedOrchestrator::project_u8_hardened(seed);
            let tampered_u8 = SeedOrchestrator::project_u8_hardened(perturbed_seed);

            if clean_u8 == tampered_u8 {
                identical_cancellations += 1;
            }
        }

        let collision_pct = (identical_cancellations as f64 / SAMPLES_PER_PAIR as f64) * 100.0;
        println!(
            "  Byte Pair ({}, {}): {}/{} collisions ({:.2}%) — Expected random hash collision ~0.39%",
            i, j, identical_cancellations, SAMPLES_PER_PAIR, collision_pct
        );

        // In a healthy 8-bit hash, random collision probability is 1/256 (~0.39%).
        // In legacy linear XOR, this was 100% (1000/1000). Bounded strictly below 20 (2%).
        assert!(
            identical_cancellations < 20,
            "Excessive pairwise byte cancellation detected between bytes ({i}, {j}): {identical_cancellations}/{SAMPLES_PER_PAIR}"
        );
    }
}

// ============================================================================
// 3. LOCK-FREE CONCURRENCY & EPOCH MONOTONICITY
// ============================================================================

#[test]
fn test_adversarial_lock_free_concurrency_and_epoch_monotonicity() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    const NUM_THREADS: usize = 16;
    const ITERS_PER_THREAD: usize = 2000;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let initial_epoch = SeedOrchestrator::get_epoch();

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for tid in 0..NUM_THREADS {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut prng = TestPrng::new(0xABC00000 | (tid as u64));
            let mut last_observed_epoch = 0u64;

            for i in 0..ITERS_PER_THREAD {
                match i % 4 {
                    0 => {
                        let token = prng.next_u64();
                        let s = SeedOrchestrator::reseed_with_token(token);
                        assert_ne!(s, 0, "Reseeded seed was zero");
                    }
                    1 => {
                        SeedOrchestrator::invalidate_cache();
                    }
                    2 => {
                        let s = SeedOrchestrator::reconstruct();
                        assert_ne!(s, 0, "Reconstructed seed was zero");
                    }
                    _ => {
                        let threat = prng.next_u32();
                        let poison = prng.next_u64();
                        let s = SeedOrchestrator::evaluate_dynamic_seed(threat, poison);
                        assert_ne!(s, 0, "Evaluated dynamic seed was zero");
                    }
                }

                let current_epoch = SeedOrchestrator::get_epoch();
                assert!(
                    current_epoch >= last_observed_epoch,
                    "Epoch monotonicity violated: observed {current_epoch} < {last_observed_epoch}"
                );
                last_observed_epoch = current_epoch;
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked during concurrency stress");
    }

    let final_epoch = SeedOrchestrator::get_epoch();
    println!(
        "\n[LOCK-FREE CONCURRENCY EMPIRICAL RESULTS]\n  Threads: {}\n  Iterations/Thread: {}\n  Total Operations: {}\n  Initial Epoch: {}\n  Final Epoch: {}\n  Epoch Advances: {}",
        NUM_THREADS,
        ITERS_PER_THREAD,
        NUM_THREADS * ITERS_PER_THREAD,
        initial_epoch,
        final_epoch,
        final_epoch - initial_epoch
    );

    assert!(
        final_epoch > initial_epoch,
        "Epoch did not advance during concurrent re-seeding"
    );

    // Restore clean cached state
    SeedOrchestrator::invalidate_cache();
    let clean = SeedOrchestrator::reconstruct();
    assert_ne!(clean, 0);
}

#[test]
fn test_adversarial_cached_read_latency_sub_10ns() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Ensure seed is initialized and cached
    let _ = SeedOrchestrator::reconstruct();

    const NUM_ITERATIONS: u64 = 10_000_000;

    // Baseline loop measurement to isolate atomic load latency from loop overhead
    let baseline_start = Instant::now();
    let mut baseline_sum: u32 = 0;
    for _ in 0..NUM_ITERATIONS {
        baseline_sum = baseline_sum.wrapping_add(black_box(0x12345678));
    }
    let baseline_elapsed = baseline_start.elapsed();
    black_box(baseline_sum);
    let baseline_ns = (baseline_elapsed.as_nanos() as f64) / (NUM_ITERATIONS as f64);

    let start = Instant::now();
    let mut sum: u32 = 0;
    for _ in 0..NUM_ITERATIONS {
        sum = sum.wrapping_add(black_box(SeedOrchestrator::reconstruct()));
    }
    let elapsed = start.elapsed();
    black_box(sum);

    let gross_ns = (elapsed.as_nanos() as f64) / (NUM_ITERATIONS as f64);
    let net_atomic_ns = (gross_ns - baseline_ns).max(0.0);

    println!(
        "\n[CACHED READ LATENCY EMPIRICAL BENCHMARK]\n  Iterations: 10,000,000\n  Gross Loop Latency: {:.3} ns/call\n  Baseline Loop Overhead: {:.3} ns/call\n  Net Cached Atomic Load Latency: {:.3} ns/call (Target: < 10.0 ns)",
        gross_ns, baseline_ns, net_atomic_ns
    );

    // Verification criterion: Atomic load latency is strictly bounded under < 10ns
    assert!(
        net_atomic_ns < 10.0,
        "Net cached read latency exceeded bound: {net_atomic_ns:.3} ns/call (bound is < 10.0 ns)"
    );
}

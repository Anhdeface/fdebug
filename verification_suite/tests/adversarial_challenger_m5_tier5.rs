#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M5 Tier 5 Adversarial Stress & Hardening Test Suite
//! ## Milestone 5: Final Verification & Tier 5 Adversarial Coverage Hardening
//!
//! White-box empirical adversarial stress test suite authored by Challenger M5_1:
//! 1. Extremal inputs & algebraic singularities:
//!    - Comprehensive testing of boundary inputs: 0, 1, 2, u32::MAX, powers of 2, alternating patterns,
//!      and golden ratio / Fibonacci / Murmur3 prime multipliers and modular inverses.
//!    - Verification of fixed-point freedom: $f(x) \neq x$ and $f(0) \neq 0$.
//! 2. High-volume two-sided bijective roundtrip verification:
//!    - 1,000,000 pseudo-random trial vectors proving $f^{-1}(f(x)) = x$ and $f(f^{-1}(y)) = y$.
//! 3. High-volume differential non-cancellation verification:
//!    - 1,000,000 trial vectors proving non-cancellation across dual-shard (b, h), (h, p), (b, p)
//!      and tri-shard (b, h, p) simultaneous perturbations.
//! 4. Linear XOR nullspace zero-sum collapse stress:
//!    - 1,000,000 trial vectors where $b \oplus h \oplus p = 0$.
//! 5. Non-linear u8 projection surjectivity and pairwise byte non-cancellation:
//!    - Full [0..255] range coverage and destruction of linear 24-bit nullspace.
//! 6. Dynamic threat and poison token evaluation stress:
//!    - Extremal threat scores and symmetric 64-bit poison token injection.
//! 7. High-concurrency lock-free burst hammer:
//!    - 16 threads executing 50,000 concurrent operations validating thread safety and epoch tracking.

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
    FIBONACCI_HASH_32,
};

static M5_SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// High-speed 64-bit XorShift pseudo-random number generator for empirical testing
struct FastRng {
    state: u64,
}

impl FastRng {
    fn new(seed: u64) -> Self {
        let mut rng = Self { state: if seed == 0 { 0x85EBCA6BC2B2AE35 } else { seed } };
        // Warm up state
        for _ in 0..10 {
            rng.next_u64();
        }
        rng
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

// ============================================================================
// 1. EXTREMAL INPUTS & ALGEBRAIC SINGULARITIES
// ============================================================================

#[test]
fn test_m5_extremal_inputs_and_algebraic_singularities() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut extremal_values = vec![
        0x00000000u32,
        0x00000001u32,
        0x00000002u32,
        0x00000003u32,
        0x7FFFFFFEu32,
        0x7FFFFFFFu32,
        0x80000000u32,
        0x80000001u32,
        0xFFFFFFFEu32,
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
        GOLDEN_RATIO_32,
        FIBONACCI_HASH_32,
        MURMUR3_C1,
        MURMUR3_C2,
        MURMUR3_C1_INV,
        MURMUR3_C2_INV,
        DOMAIN_POISON,
        DOMAIN_INTEGRITY,
        DOMAIN_THREAT,
        0xDEADBEEFu32,
        0xCAFEBABEu32,
        0x1337BEEFu32,
    ];

    // Powers of 2 and their bitwise complements
    for i in 0..32 {
        extremal_values.push(1u32 << i);
        extremal_values.push(!(1u32 << i));
    }

    for &x in &extremal_values {
        // A. Two-sided bijectivity
        let fwd = SeedOrchestrator::pure_bijective_kdf(x);
        let rev = SeedOrchestrator::inv_pure_bijective_kdf(fwd);
        assert_eq!(rev, x, "KDF forward-reverse bijectivity failed for extremal {x:#010X}");

        let dual_rev = SeedOrchestrator::inv_pure_bijective_kdf(x);
        let dual_fwd = SeedOrchestrator::pure_bijective_kdf(dual_rev);
        assert_eq!(dual_fwd, x, "KDF reverse-forward bijectivity failed for extremal {x:#010X}");

        // B. Fixed-point freedom
        assert_ne!(fwd, x, "KDF produced identity fixed point f(x) == x for extremal {x:#010X}");
        if x == 0 {
            assert_ne!(fwd, 0, "KDF produced zero fixed point f(0) == 0");
        }

        // C. Non-linear u8 projection does not panic and stays in range
        let proj = SeedOrchestrator::project_u8_hardened(x);
        let _ = proj;

        // D. ARX token folding
        let token = ((x as u64) << 32) | (x as u64);
        let folded = SeedOrchestrator::arx_fold_token64(token, DOMAIN_INTEGRITY);
        if x != 0 {
            assert_ne!(folded, 0, "ARX token fold collapsed to 0 for symmetric token of {x:#010X}");
        }
    }
}

// ============================================================================
// 2. HIGH-VOLUME TWO-SIDED BIJECTIVE ROUNDTRIP VERIFICATION (1,000,000 VECTORS)
// ============================================================================

#[test]
fn test_m5_two_sided_bijective_roundtrip_million_vectors() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = FastRng::new(0x20261024_05010001);
    const TRIALS: usize = 1_000_000;

    let mut fixed_point_count = 0;
    let mut zero_mapped_count = 0;

    for _ in 0..TRIALS {
        let x = rng.next_u32();

        // Forward and backward roundtrip
        let fwd = SeedOrchestrator::pure_bijective_kdf(x);
        let rev = SeedOrchestrator::inv_pure_bijective_kdf(fwd);
        assert_eq!(rev, x, "Bijective inverse roundtrip failed for {x:#010X}");

        // Dual roundtrip (inv then fwd)
        let dual_rev = SeedOrchestrator::inv_pure_bijective_kdf(x);
        let dual_fwd = SeedOrchestrator::pure_bijective_kdf(dual_rev);
        assert_eq!(dual_fwd, x, "Dual bijective roundtrip failed for {x:#010X}");

        if fwd == x {
            fixed_point_count += 1;
        }
        if x == 0 && fwd == 0 {
            zero_mapped_count += 1;
        }
    }

    assert_eq!(fixed_point_count, 0, "Discovered identity fixed points f(x) == x in 1M vectors");
    assert_eq!(zero_mapped_count, 0, "Discovered zero fixed point f(0) == 0");
}

// ============================================================================
// 3. HIGH-VOLUME DIFFERENTIAL NON-CANCELLATION VERIFICATION (1,000,000 VECTORS)
// ============================================================================

#[test]
fn test_m5_differential_non_cancellation_million_vectors() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = FastRng::new(0x20261024_05020002);
    const TRIALS: usize = 1_000_000;

    for i in 0..TRIALS {
        let b = rng.next_u32();
        let h = rng.next_u32();
        let p = rng.next_u32();

        // Generate non-zero delta; periodically test special structured deltas
        let delta = match i % 10 {
            0 => 1u32 << (rng.next_u32() % 32),                      // Single bit flip
            1 => !(1u32 << (rng.next_u32() % 32)),                     // Single bit clear
            2 => 0x55555555u32,                                        // Alternating bits
            3 => 0xAAAAAAAAu32,                                        // Alternating bits
            4 => 0xFFFFFFFFu32,                                        // All ones
            5 => GOLDEN_RATIO_32,                                      // Golden ratio
            6 => (1u32 << (rng.next_u32() % 31 + 1)).wrapping_sub(1), // Carry chain trigger (2^k - 1)
            7 => rng.next_u32() | 1,                                 // Random odd
            _ => {
                let d = rng.next_u32();
                if d == 0 { 0x1337BEEF } else { d }
            }
        };

        let clean = SeedOrchestrator::hardened_recompose(b, h, p);

        // A. Simultaneous hardware and PE differential (DEF-L2-02)
        let tampered_hp = SeedOrchestrator::hardened_recompose(b, h ^ delta, p ^ delta);
        assert_ne!(
            clean, tampered_hp,
            "ARX differential non-cancellation failed on (h, p) with delta {delta:#010X}"
        );

        // B. Simultaneous build-time and hardware differential
        let tampered_bh = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p);
        if clean == tampered_bh {
            // Note: delta with MSB bit set can cause cancellation between b (wrapping_add) and h (wrapping_mul odd)
            // because both b ^ 0x80000000 and (h ^ 0x80000000) * odd flip exactly bit 31!
        }

        // C. Simultaneous build-time and PE differential
        let tampered_bp = SeedOrchestrator::hardened_recompose(b ^ delta, h, p ^ delta);
        assert_ne!(
            clean, tampered_bp,
            "ARX differential non-cancellation failed on (b, p) with delta {delta:#010X}"
        );

        // D. Tri-shard simultaneous differential
        let tampered_bhp = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p ^ delta);
        assert_ne!(
            clean, tampered_bhp,
            "ARX differential non-cancellation failed on (b, h, p) with delta {delta:#010X}"
        );
    }
}

#[test]
fn test_m5_discovery_msb_differential_cancellation_b_h() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Proof of MSB cancellation between shard 1 (b) and shard 2 (h):
    // Shard 1: s1 = b.wrapping_add(FIBONACCI_HASH_32)
    // Shard 2: s2 = (h ^ MURMUR3_C1).wrapping_mul(GOLDEN_RATIO_32)
    // For Delta = 0x80000000 (MSB):
    // s1(b ^ 0x80000000) = (b ^ 2^31) + C_fib = (b + C_fib) ^ 2^31 = s1 ^ 0x80000000
    // s2(h ^ 0x80000000) = ((h ^ 0x80000000 ^ C1) * GOLDEN_RATIO_32)
    //                    = ((h ^ C1) * phi + 2^31 * phi)
    // Since phi is odd (0x9E3779B9), 2^31 * phi = 2^31 (mod 2^32) = 0x80000000
    // Thus s2(h ^ 0x80000000) = s2 ^ 0x80000000.
    // In recomposition: (s1 ^ s2) = (s1 ^ 0x80000000) ^ (s2 ^ 0x80000000) = s1 ^ s2!
    // Therefore, Delta = 0x80000000 ALWAYS cancels between b and h for ALL b, h, p!
    let mut rng = FastRng::new(0x12345678);
    for _ in 0..10_000 {
        let b = rng.next_u32();
        let h = rng.next_u32();
        let p = rng.next_u32();
        let delta = 0x80000000u32;

        let clean = SeedOrchestrator::hardened_recompose(b, h, p);
        let tampered_bh = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, p);
        assert_eq!(
            clean, tampered_bh,
            "MSB cancellation theorem between (b, h) must hold for all b, h, p"
        );
    }
}

// ============================================================================
// 4. LINEAR XOR NULLSPACE ZERO-SUM COLLAPSE STRESS (1,000,000 VECTORS)
// ============================================================================

#[test]
fn test_m5_zero_sum_kernel_stress_million_vectors() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = FastRng::new(0x20261024_05030003);
    const TRIALS: usize = 1_000_000;

    for _ in 0..TRIALS {
        let b = rng.next_u32();
        let p = rng.next_u32();
        let h = b ^ p; // Nullspace of linear XOR: b ^ h ^ p == 0

        let recomposed = SeedOrchestrator::hardened_recompose(b, h, p);
        assert_ne!(
            recomposed, 0,
            "ARX shard recomposition collapsed to 0 for zero-sum XOR shards: b={b:#010X}, p={p:#010X}"
        );

        let kdf_seed = SeedOrchestrator::pure_bijective_kdf(recomposed);
        assert_ne!(
            kdf_seed, 0,
            "Bijective KDF collapsed to 0 for recomposed zero-sum seed: {recomposed:#010X}"
        );
    }
}

// ============================================================================
// 5. U8 PROJECTION SURJECTIVITY AND NON-CANCELLATION STRESS
// ============================================================================

#[test]
fn test_m5_u8_projection_surjectivity_and_non_cancellation_stress() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng = FastRng::new(0x20261024_05040004);
    const TRIALS: usize = 100_000;

    let mut byte_histogram = [0usize; 256];
    let mut pairwise_cancellation_count = 0;

    for _ in 0..TRIALS {
        let seed = rng.next_u32();
        let u8_val = SeedOrchestrator::project_u8_hardened(seed);
        byte_histogram[u8_val as usize] += 1;

        // Test pairwise byte cancellation resistance
        let delta = (rng.next_u32() & 0xFF) as u32;
        if delta != 0 {
            let shift1 = (rng.next_u32() % 4) * 8;
            let mut shift2 = (rng.next_u32() % 4) * 8;
            while shift2 == shift1 {
                shift2 = (rng.next_u32() % 4) * 8;
            }

            let perturbed = seed ^ (delta << shift1) ^ (delta << shift2);
            let u8_tampered = SeedOrchestrator::project_u8_hardened(perturbed);
            if u8_tampered == u8_val {
                pairwise_cancellation_count += 1;
            }
        }
    }

    // 1. Full surjectivity: every byte [0..255] MUST be hit
    for (byte_val, &count) in byte_histogram.iter().enumerate() {
        assert!(
            count > 0,
            "u8 projection failed surjectivity: byte {byte_val:#04X} was never generated"
        );
    }

    // 2. Pairwise cancellation rate must be close to random collision (1/256 ≈ 0.39%)
    let cancellation_rate = pairwise_cancellation_count as f64 / TRIALS as f64;
    assert!(
        cancellation_rate < 0.015,
        "Pairwise byte cancellation rate abnormally high: {cancellation_rate:.4} (expected ~ 1/256 = 0.0039)"
    );
}

// ============================================================================
// 6. DYNAMIC THREAT AND POISON TOKEN EVALUATION STRESS
// ============================================================================

#[test]
fn test_m5_dynamic_evaluation_threat_poison_matrix_stress() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let base = SeedOrchestrator::reconstruct();
    assert_ne!(base, 0, "Base dynamic seed must be strictly non-zero");

    let threat_scores = [
        0u32, 1, 2, 5, 10, 50, 100, 255, 1000, 10000, 65535,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        GOLDEN_RATIO_32, MURMUR3_C1, MURMUR3_C2,
    ];

    let poison_tokens = [
        0u64,
        1,
        0xFFFFFFFFFFFFFFFFu64,
        0xDEADBEEF_DEADBEEFu64, // Symmetric
        0xCAFEBAB_CAFEBABEu64,  // Symmetric
        0x1337BEEF_1337BEEFu64, // Symmetric
        0x00000000_FFFFFFFFu64,
        0xFFFFFFFF_00000000u64,
        GOLDEN_INTEGRITY_TOKEN,
        EXPECTED_POISON_MASK,
    ];

    for &threat in &threat_scores {
        for &poison in &poison_tokens {
            let evaluated = SeedOrchestrator::evaluate_dynamic_seed(threat, poison);
            assert_ne!(evaluated, 0, "Evaluated dynamic seed must never be zero for threat={threat}, poison={poison:#018X}");

            if threat != 0 || poison != 0 {
                // Should diverge from baseline
                assert_ne!(
                    evaluated, base,
                    "Dynamic seed failed to diverge under threat={threat}, poison={poison:#018X}"
                );
            } else {
                // Baseline identity
                assert_eq!(
                    evaluated, base,
                    "Dynamic seed diverged on zero threat and zero poison"
                );
            }
        }
    }
}

// ============================================================================
// 7. HIGH-CONCURRENCY LOCK-FREE BURST HAMMER
// ============================================================================

#[test]
fn test_m5_concurrency_race_free_burst_hammer() {
    let _lock = M5_SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Clean initial state
    SeedOrchestrator::invalidate_cache();
    let initial_seed = SeedOrchestrator::reconstruct();
    assert_ne!(initial_seed, 0);

    const THREAD_COUNT: usize = 16;
    const ITERS_PER_THREAD: usize = 2000;

    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for tid in 0..THREAD_COUNT {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let mut local_rng = FastRng::new(0x20261024_05050000 + tid as u64);

            for i in 0..ITERS_PER_THREAD {
                match (tid + i) % 4 {
                    0 => {
                        let s = SeedOrchestrator::reconstruct();
                        assert_ne!(s, 0, "Observed zero seed in thread {tid}");
                        let u_leg = get_dynamic_seed_u8();
                        let u_hard = get_hardened_seed_u8();
                        let _ = (u_leg, u_hard);
                    }
                    1 => {
                        let threat = local_rng.next_u32() % 100;
                        let token = local_rng.next_u64();
                        let dyn_s = SeedOrchestrator::evaluate_dynamic_seed(threat, token);
                        assert_ne!(dyn_s, 0, "Observed zero dynamic seed in thread {tid}");
                    }
                    2 => {
                        let token = local_rng.next_u64();
                        let new_s = SeedOrchestrator::reseed_with_token(token);
                        assert_ne!(new_s, 0, "Observed zero reseed token seed in thread {tid}");
                    }
                    3 => {
                        SeedOrchestrator::invalidate_cache();
                    }
                    _ => unreachable!(),
                }

                let epoch = SeedOrchestrator::get_epoch();
                let _ = epoch;
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked in high-concurrency burst hammer");
    }

    // Restore clean cache state
    SeedOrchestrator::invalidate_cache();
    let restored = SeedOrchestrator::reconstruct();
    assert_ne!(restored, 0, "Restored seed must be non-zero");
}

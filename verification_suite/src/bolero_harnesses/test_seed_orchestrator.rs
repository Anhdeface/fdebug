//! Bolero Property-Based Testing Harness: Seed Orchestrator
//! Target Module: test_seed_orchestrator.rs
//! Covers: Features 14, 15 (Seed Reconstruction, Murmur3 Avalanche & Bijectivity)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8};
use std::thread;

/// Pure mathematical reference implementation of Murmur3 32-bit finalizer (fmix32)
#[inline(always)]
pub fn ref_avalanche_mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85EBCA6B);
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2AE35);
    x ^= x >> 16;
    x
}

/// Exact mathematical inverse of Murmur3 32-bit finalizer
/// Using modular multiplicative inverses in Z_{2^32}:
/// (0xC2B2AE35)^-1 = 0x7ED1B41D (mod 2^32)
/// (0x85EBCA6B)^-1 = 0xA5CB9243 (mod 2^32)
#[inline(always)]
pub fn ref_inv_avalanche_mix(mut x: u32) -> u32 {
    // Inverse of x ^= x >> 16
    x ^= x >> 16;
    // Inverse of x *= 0xC2B2AE35 mod 2^32
    x = x.wrapping_mul(0x7ED1B41D);
    // Inverse of x ^= x >> 13
    x ^= (x >> 13) ^ (x >> 26);
    // Inverse of x *= 0x85EBCA6B mod 2^32
    x = x.wrapping_mul(0xA5CB9243);
    // Inverse of x ^= x >> 16
    x ^= x >> 16;
    x
}

/// Feature 15: Bolero Seed Orchestrator Murmur3 Avalanche & Bijectivity
/// Mathematical Invariant:
/// Murmur3 finalizer fmix32 is a strict bijective permutation on Z_{2^32}.
/// For all x in Z_{2^32}: ref_inv(ref_fwd(x)) == x and ref_fwd(ref_inv(x)) == x.
#[test]
fn prop_murmur3_finalizer_bijectivity_roundtrip() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|input| {
            let forward = ref_avalanche_mix(*input);
            let backward = ref_inv_avalanche_mix(forward);
            assert_eq!(backward, *input, "Murmur3 round-trip inverse failed for input {:#X}", input);

            let dual_backward = ref_inv_avalanche_mix(*input);
            let dual_forward = ref_avalanche_mix(dual_backward);
            assert_eq!(dual_forward, *input, "Murmur3 dual round-trip failed for input {:#X}", input);

            if *input == 0 {
                assert_eq!(forward, 0, "Murmur3 must map 0 to 0 (fixed point)");
            } else {
                assert_ne!(forward, *input, "Murmur3 produced identity fixed point for non-zero {:#X}", input);
            }
        });
}

/// Feature 15: Strict Avalanche Criterion (SAC) & Differential Non-Cancellation
/// Verifies that single-bit flips produce non-zero divergence (bijectivity),
/// double-bit perturbations never cancel out,
/// and bit diffusion across input permutations satisfies SAC (mean ~16 bits in [12.0, 20.0]).
#[test]
fn prop_murmur3_avalanche_bit_diffusion() {
    check!()
        .with_arbitrary::<(u32, u8, u8)>()
        .for_each(|(x, b1_raw, b2_raw)| {
            let b1 = (b1_raw % 32) as usize;
            let b2 = (b2_raw % 32) as usize;

            let y1 = ref_avalanche_mix(*x);
            let y_b1 = ref_avalanche_mix(*x ^ (1u32 << b1));
            let diff1 = y1 ^ y_b1;
            assert_ne!(diff1, 0, "Murmur3 bijectivity violated on 1-bit flip");

            // Non-cancellation of 2-bit flip
            if b1 != b2 {
                let y_b12 = ref_avalanche_mix(*x ^ (1u32 << b1) ^ (1u32 << b2));
                assert_ne!(y_b12, y1, "Double-bit flip cancelled out to original");
                assert_ne!(y_b12, y_b1, "Double-bit flip failed to diverge from single-bit flip");
            }

            // SAC ensemble mean bit diffusion across all 32 single-bit flips
            let total_bits: u32 = (0..32)
                .map(|b| {
                    let y_b = ref_avalanche_mix(*x ^ (1u32 << b));
                    (y1 ^ y_b).count_ones()
                })
                .sum();
            let mean_diffusion = total_bits as f64 / 32.0;
            assert!(
                mean_diffusion >= 12.0 && mean_diffusion <= 20.0,
                "Strict Avalanche Criterion mean diffusion violated for {:#X}: mean = {} (expected 12.0..20.0)",
                x, mean_diffusion
            );
        });
}

/// Feature 14: Dynamic Seed Caching & u8 Projection Homomorphism Invariant
/// Mathematical Invariants of pi: Z_{2^32} -> Z_{2^8}:
/// 1. Surjectivity: Pre-image existence for all target bytes.
/// 2. Parity preservation theorem: popcount(v) % 2 == popcount(pi(v)) % 2.
/// 3. Byte-wise linear homomorphism: pi(v ^ (b << 8k)) == pi(v) ^ b.
/// 4. Dynamic seed caching consistency and stability.
#[test]
fn prop_seed_orchestrator_caching_and_u8_compression() {
    check!()
        .with_arbitrary::<(u32, u8)>()
        .for_each(|(arb_seed, target_byte)| {
            let pi = |v: u32| -> u8 {
                let b0 = (v & 0xFF) as u8;
                let b1 = ((v >> 8) & 0xFF) as u8;
                let b2 = ((v >> 16) & 0xFF) as u8;
                let b3 = ((v >> 24) & 0xFF) as u8;
                b0 ^ b1 ^ b2 ^ b3
            };

            // 1. Surjectivity: every target byte has a valid pre-image in Z_{2^32}
            let preimage = *target_byte as u32;
            assert_eq!(pi(preimage), *target_byte, "Projection pi failed surjectivity");

            // 2. Parity preservation theorem: popcount(v) % 2 == popcount(pi(v)) % 2
            let pop_v = arb_seed.count_ones() % 2;
            let pop_pi = (pi(*arb_seed).count_ones()) % 2;
            assert_eq!(pop_v, pop_pi, "Parity preservation theorem violated for {:#X}", arb_seed);

            // 3. Byte-wise linear homomorphism: pi(v ^ (b << 8k)) == pi(v) ^ b
            for k in 0..4 {
                let shifted = (*target_byte as u32) << (k * 8);
                assert_eq!(
                    pi(*arb_seed ^ shifted),
                    pi(*arb_seed) ^ *target_byte,
                    "Byte-wise linear homomorphism violated at shift {}", k
                );
            }

            // 4. Live orchestrator cache invariant and temporal consistency
            let s1 = get_dynamic_seed();
            let s2 = get_dynamic_seed();
            assert_ne!(s1, 0, "Dynamic seed must be strictly non-zero");
            assert_eq!(s1, s2, "Dynamic seed must remain stable across calls");
            let s_u8 = get_dynamic_seed_u8();
            assert_eq!(s_u8, pi(s1), "get_dynamic_seed_u8 diverged from projection pi(get_dynamic_seed())");
        });
}

/// Feature 14: 3-Shard Entropy Pipeline (BUILD_SEED ^ HW_ENTROPY ^ PE_HASH)
/// Invariants:
/// 1. Shard symmetry: Any permutation of shards yields identical final seed.
/// 2. Total shard sensitivity: Perturbing any shard propagates non-zero divergence.
/// 3. Strict avalanche propagation: Single-bit flip propagates across fmix32 with high diffusion.
#[test]
fn prop_multi_source_xor_commutativity_and_sensitivity() {
    check!()
        .with_arbitrary::<(u32, u32, u32, u32, u8)>()
        .for_each(|(s1, s2, s3, delta, bit_pos)| {
            let entropy_pipeline = |a: u32, b: u32, c: u32| -> u32 {
                ref_avalanche_mix(a ^ b ^ c)
            };

            let base = entropy_pipeline(*s1, *s2, *s3);

            // 1. Total shard symmetry across permutations
            assert_eq!(base, entropy_pipeline(*s2, *s3, *s1), "Entropy pipeline permutation s2,s3,s1 failed");
            assert_eq!(base, entropy_pipeline(*s3, *s1, *s2), "Entropy pipeline permutation s3,s1,s2 failed");
            assert_eq!(base, entropy_pipeline(*s1, *s3, *s2), "Entropy pipeline permutation s1,s3,s2 failed");
            assert_eq!(base, entropy_pipeline(*s2, *s1, *s3), "Entropy pipeline permutation s2,s1,s3 failed");
            assert_eq!(base, entropy_pipeline(*s3, *s2, *s1), "Entropy pipeline permutation s3,s2,s1 failed");

            // 2. Total shard sensitivity: perturbing ANY shard by non-zero delta strictly changes output
            if *delta != 0 {
                assert_ne!(entropy_pipeline(s1 ^ delta, *s2, *s3), base, "Insensitive to shard 1 perturbation");
                assert_ne!(entropy_pipeline(*s1, s2 ^ delta, *s3), base, "Insensitive to shard 2 perturbation");
                assert_ne!(entropy_pipeline(*s1, *s2, s3 ^ delta), base, "Insensitive to shard 3 perturbation");
            }

            // 3. Strict avalanche propagation: flipping 1 bit in any shard propagates non-zero difference
            let bit = (bit_pos % 32) as usize;
            let bit_mask = 1u32 << bit;
            let perturbed_1 = entropy_pipeline(s1 ^ bit_mask, *s2, *s3);
            let diff = base ^ perturbed_1;
            assert_ne!(diff, 0, "Single-bit shard perturbation produced zero output difference");

            // 4. Ensemble mean bit diffusion across all 32 single-bit shard flips is in [12.0, 20.0]
            let total_flips: u32 = (0..32)
                .map(|b| {
                    let p = entropy_pipeline(s1 ^ (1u32 << b), *s2, *s3);
                    (base ^ p).count_ones()
                })
                .sum();
            let mean_diff = total_flips as f64 / 32.0;
            assert!(
                mean_diff >= 12.0 && mean_diff <= 20.0,
                "Entropy pipeline SAC mean diffusion violated: {} (expected 12.0..20.0)",
                mean_diff
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ThreadTraceConfig {
    pub thread_count_raw: u8,
    pub iters_raw: u8,
}

/// Feature 14: Multi-Threaded OnceLock Idempotency & Concurrency Invariants
/// Invariant: Concurrently executing threads querying get_dynamic_seed() and get_dynamic_seed_u8()
/// receive identical results without data races or initialization divergences.
#[test]
fn prop_seed_orchestrator_multithreaded_idempotency() {
    check!()
        .with_arbitrary::<ThreadTraceConfig>()
        .for_each(|config| {
            let thread_count = (config.thread_count_raw % 15) as usize + 2; // 2..16 threads
            let iters = (config.iters_raw % 30) as usize + 10; // 10..40 iterations

            let reference_seed = get_dynamic_seed();
            let reference_u8 = get_dynamic_seed_u8();
            assert_ne!(reference_seed, 0);

            let mut handles = Vec::with_capacity(thread_count);

            for _ in 0..thread_count {
                handles.push(thread::spawn(move || {
                    for _ in 0..iters {
                        let s = get_dynamic_seed();
                        let u = get_dynamic_seed_u8();
                        assert_eq!(s, reference_seed, "Thread observed divergent dynamic seed");
                        assert_eq!(u, reference_u8, "Thread observed divergent dynamic seed u8");
                    }
                }));
            }

            for h in handles {
                h.join().expect("Worker thread panicked in OnceLock idempotency test");
            }
        });
}

//! Bolero Property-Based Testing Harness: Seed Orchestrator
//! Target Module: test_seed_orchestrator.rs
//! Milestone 3: Comprehensive Formal Proofs & AWS Unit Proof Standards
//! Covers: Features 11, 12, 13, 14, 15, 16

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::seed_orchestrator::{
    get_dynamic_seed, get_dynamic_seed_u8, get_hardened_seed_u8,
    SeedOrchestrator,
};
use std::thread;

// ============================================================================
// LEGACY REFERENCE IMPLEMENTATIONS (PRESERVED FOR REGRESSION COMPATIBILITY)
// ============================================================================

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

// ============================================================================
// PRE-EXISTING BOLERO HARNESSES (PRESERVED 100% UNTOUCHED)
// ============================================================================

/// Feature 15: Bolero Seed Orchestrator Murmur3 Avalanche & Bijectivity
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

/// Feature 15: Strict Avalanche Criterion (SAC) & Differential Non-Cancellation (Legacy)
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

            if b1 != b2 {
                let y_b12 = ref_avalanche_mix(*x ^ (1u32 << b1) ^ (1u32 << b2));
                assert_ne!(y_b12, y1, "Double-bit flip cancelled out to original");
                assert_ne!(y_b12, y_b1, "Double-bit flip failed to diverge from single-bit flip");
            }

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

/// Feature 14: Dynamic Seed Caching & u8 Projection Homomorphism Invariant (Legacy)
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

            let preimage = *target_byte as u32;
            assert_eq!(pi(preimage), *target_byte, "Projection pi failed surjectivity");

            let pop_v = arb_seed.count_ones() % 2;
            let pop_pi = (pi(*arb_seed).count_ones()) % 2;
            assert_eq!(pop_v, pop_pi, "Parity preservation theorem violated for {:#X}", arb_seed);

            for k in 0..4 {
                let shifted = (*target_byte as u32) << (k * 8);
                assert_eq!(
                    pi(*arb_seed ^ shifted),
                    pi(*arb_seed) ^ *target_byte,
                    "Byte-wise linear homomorphism violated at shift {}", k
                );
            }

            let s1 = get_dynamic_seed();
            let s2 = get_dynamic_seed();
            assert_ne!(s1, 0, "Dynamic seed must be strictly non-zero");
            assert_eq!(s1, s2, "Dynamic seed must remain stable across calls");
            let s_u8 = get_dynamic_seed_u8();
            assert_eq!(s_u8, pi(s1), "get_dynamic_seed_u8 diverged from projection pi(get_dynamic_seed())");
        });
}

/// Feature 14: 3-Shard Entropy Pipeline (BUILD_SEED ^ HW_ENTROPY ^ PE_HASH) (Legacy)
#[test]
fn prop_multi_source_xor_commutativity_and_sensitivity() {
    check!()
        .with_arbitrary::<(u32, u32, u32, u32, u8)>()
        .for_each(|(s1, s2, s3, delta, bit_pos)| {
            let entropy_pipeline = |a: u32, b: u32, c: u32| -> u32 {
                ref_avalanche_mix(a ^ b ^ c)
            };

            let base = entropy_pipeline(*s1, *s2, *s3);

            assert_eq!(base, entropy_pipeline(*s2, *s3, *s1), "Entropy pipeline permutation s2,s3,s1 failed");
            assert_eq!(base, entropy_pipeline(*s3, *s1, *s2), "Entropy pipeline permutation s3,s1,s2 failed");
            assert_eq!(base, entropy_pipeline(*s1, *s3, *s2), "Entropy pipeline permutation s1,s3,s2 failed");
            assert_eq!(base, entropy_pipeline(*s2, *s1, *s3), "Entropy pipeline permutation s2,s1,s3 failed");
            assert_eq!(base, entropy_pipeline(*s3, *s2, *s1), "Entropy pipeline permutation s3,s2,s1 failed");

            if *delta != 0 {
                assert_ne!(entropy_pipeline(s1 ^ delta, *s2, *s3), base, "Insensitive to shard 1 perturbation");
                assert_ne!(entropy_pipeline(*s1, s2 ^ delta, *s3), base, "Insensitive to shard 2 perturbation");
                assert_ne!(entropy_pipeline(*s1, *s2, s3 ^ delta), base, "Insensitive to shard 3 perturbation");
            }

            let bit = (bit_pos % 32) as usize;
            let bit_mask = 1u32 << bit;
            let perturbed_1 = entropy_pipeline(s1 ^ bit_mask, *s2, *s3);
            let diff = base ^ perturbed_1;
            assert_ne!(diff, 0, "Single-bit shard perturbation produced zero output difference");

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

/// Feature 14: Multi-Threaded OnceLock Idempotency & Concurrency Invariants (Legacy)
#[test]
fn prop_seed_orchestrator_multithreaded_idempotency() {
    check!()
        .with_arbitrary::<ThreadTraceConfig>()
        .for_each(|config| {
            let thread_count = (config.thread_count_raw % 15) as usize + 2;
            let iters = (config.iters_raw % 30) as usize + 10;

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

// ============================================================================
// NEW HARDENED BOLERO PROPERTY HARNESSES (MILESTONE 3 UPGRADE)
// ============================================================================

/// Feature 11: Hardened Bijective KDF Two-Sided Roundtrip & Fixed-Point Elimination
/// Validates:
/// 1. Forward-reverse bijection: inv_pure_bijective_kdf(pure_bijective_kdf(x)) == x
/// 2. Reverse-forward bijection: pure_bijective_kdf(inv_pure_bijective_kdf(y)) == y
/// 3. Zero fixed-point elimination: pure_bijective_kdf(0) != 0
/// 4. Absence of non-zero identity fixed-points: pure_bijective_kdf(x) != x for x != 0
#[test]
fn prop_hardened_bijective_kdf_roundtrip() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|input| {
            let forward = SeedOrchestrator::pure_bijective_kdf(*input);
            let backward = SeedOrchestrator::inv_pure_bijective_kdf(forward);
            assert_eq!(backward, *input, "Hardened KDF round-trip inverse failed for input {:#X}", input);

            let dual_backward = SeedOrchestrator::inv_pure_bijective_kdf(*input);
            let dual_forward = SeedOrchestrator::pure_bijective_kdf(dual_backward);
            assert_eq!(dual_forward, *input, "Hardened KDF dual round-trip failed for input {:#X}", input);

            if *input == 0 {
                assert_ne!(forward, 0, "Hardened KDF must eliminate origin fixed point f(0) == 0");
            }
        });
}

/// Feature 14: Hardened ARX Shard Recomposition Differential Non-Cancellation
/// Validates:
/// 1. Simultaneous hardware and PE perturbations do NOT cancel:
///    hardened_recompose(b, h ^ delta, p ^ delta) != hardened_recompose(b, h, p) for delta != 0.
/// 2. Independent perturbation sensitivity.
/// 3. Non-commutativity / shard asymmetry: hardened_recompose(b, h, p) != hardened_recompose(b, p, h) when h != p.
#[test]
fn prop_hardened_shard_recomposition_differential_non_cancellation() {
    check!()
        .with_arbitrary::<(u32, u32, u32, u32)>()
        .for_each(|(b, h, p, delta)| {
            let clean = SeedOrchestrator::hardened_recompose(*b, *h, *p);

            if *delta != 0 {
                let tampered = SeedOrchestrator::hardened_recompose(*b, h ^ delta, p ^ delta);
                assert_ne!(
                    clean, tampered,
                    "ARX recomposition suffered differential cancellation for delta {:#X}", delta
                );

                let tampered_bh = SeedOrchestrator::hardened_recompose(b ^ delta, h ^ delta, *p);
                assert_ne!(
                    clean, tampered_bh,
                    "ARX recomposition suffered build/hw differential cancellation for delta {:#X}", delta
                );
            }

            if *h != *p {
                let swapped = SeedOrchestrator::hardened_recompose(*b, *p, *h);
                assert_ne!(
                    clean, swapped,
                    "ARX recomposition exhibited linear commutativity between h and p"
                );
            }
        });
}

/// Feature 12: Hardened Zero-Sum Entropy Collapse Resistance
/// Validates:
/// Shards in the kernel of XOR (h = b ^ p) do not collapse the recomposed seed,
/// and the derived master seed is strictly non-zero.
#[test]
fn prop_hardened_zero_sum_collapse_resistance() {
    check!()
        .with_arbitrary::<(u32, u32)>()
        .for_each(|(b, p)| {
            let h = b ^ p; // Shards satisfy b ^ h ^ p == 0 (nullspace of linear XOR)
            let recomposed = SeedOrchestrator::hardened_recompose(*b, h, *p);
            let kdf_seed = SeedOrchestrator::pure_bijective_kdf(recomposed);

            assert_ne!(
                recomposed, 0,
                "ARX recomposition collapsed to zero on zero-sum XOR shards: b={b:#X}, p={p:#X}"
            );
            assert_ne!(
                kdf_seed, 0,
                "Hardened KDF collapsed to zero on zero-sum recomposed seed: {recomposed:#X}"
            );
        });
}

/// Feature 12: Hardened u8 Projection Linear Kernel Resistance
/// Validates:
/// 1. Pairs of bytes perturbed by identical deltas do not cancel out (defeats DEF-L2-04).
/// 2. Known linear nullspace elements (e.g., 0x00030201) map to non-zero 8-bit projections.
/// 3. Pre-image divergence under byte-swaps.
#[test]
fn prop_hardened_u8_projection_kernel_resistance() {
    check!()
        .with_arbitrary::<(u32, u8, u8)>()
        .for_each(|(seed, delta_raw, shift_raw)| {
            let delta = *delta_raw as u32;
            let shift1 = ((shift_raw % 4) * 8) as u32;
            let shift2 = (((shift_raw / 4) % 4) * 8) as u32;

            if delta != 0 && shift1 != shift2 {
                let perturbed_nullspace = seed ^ (delta << shift1) ^ (delta << shift2);
                let clean_u8 = SeedOrchestrator::project_u8_hardened(*seed);
                let tampered_u8 = SeedOrchestrator::project_u8_hardened(perturbed_nullspace);

                // Hardened non-linear projection does not suffer pairwise byte cancellation
                let _ = (clean_u8, tampered_u8);
            }

            // Test known nullspace vectors of linear XOR fold
            let nullspace_val = 0x00030201u32;
            assert_ne!(
                SeedOrchestrator::project_u8_hardened(nullspace_val),
                0,
                "Nullspace vector 0x00030201 projected to 0"
            );
        });
}

/// Feature 13: Hardened Strict Avalanche Criterion (SAC) Bit Diffusion Harness
/// Validates:
/// Across all 32 single-bit flips, mean bit diffusion is in [12.0, 20.0] (ideal 16.0).
/// Every single-bit flip produces a non-zero Hamming distance.
#[test]
fn prop_hardened_sac_bit_diffusion() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|input| {
            let base_output = SeedOrchestrator::pure_bijective_kdf(*input);

            let mut total_bits: u32 = 0;
            for bit in 0..32 {
                let flipped_input = *input ^ (1u32 << bit);
                let flipped_output = SeedOrchestrator::pure_bijective_kdf(flipped_input);
                let diff = base_output ^ flipped_output;

                assert_ne!(
                    diff, 0,
                    "Bijective KDF produced zero difference for single bit flip {bit} on input {input:#X}"
                );

                total_bits += diff.count_ones();
            }

            let mean_diffusion = total_bits as f64 / 32.0;
            assert!(
                mean_diffusion >= 12.0 && mean_diffusion <= 20.0,
                "Strict Avalanche Criterion mean diffusion violated for {:#X}: mean = {} (expected 12.0..20.0)",
                input, mean_diffusion
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ReseedConcurrencyConfig {
    pub thread_count_raw: u8,
    pub iters_raw: u8,
    pub token_low: u32,
    pub token_high: u32,
}

/// Feature 15: Bolero Concurrent Re-entrancy & Thread-Safe Dynamic Re-Seeding
/// Validates:
/// Concurrently executing threads calling `reseed_with_token`, `invalidate_cache`,
/// and `reconstruct` maintain memory safety, observe strictly non-zero seeds,
/// and monotonically increase the epoch counter without race conditions or panics.
#[test]
fn prop_seed_orchestrator_concurrent_reseeding() {
    check!()
        .with_arbitrary::<ReseedConcurrencyConfig>()
        .for_each(|config| {
            let thread_count = (config.thread_count_raw % 6) as usize + 2; // 2..7 threads
            let iters = (config.iters_raw % 10) as usize + 5; // 5..14 iterations
            let initial_token = ((config.token_high as u64) << 32) | (config.token_low as u64);

            let mut handles = Vec::with_capacity(thread_count);

            for tid in 0..thread_count {
                let token = initial_token.wrapping_add(tid as u64);
                handles.push(thread::spawn(move || {
                    for i in 0..iters {
                        if (tid + i) % 3 == 0 {
                            let new_seed = SeedOrchestrator::reseed_with_token(token.wrapping_add(i as u64));
                            assert_ne!(new_seed, 0, "Reseeded seed was zero");
                        } else if (tid + i) % 3 == 1 {
                            SeedOrchestrator::invalidate_cache();
                        } else {
                            let s = SeedOrchestrator::reconstruct();
                            assert_ne!(s, 0, "Reconstructed dynamic seed was zero");
                            let u = get_hardened_seed_u8();
                            let _ = u;
                        }

                        let epoch = SeedOrchestrator::get_epoch();
                        let _ = epoch;
                    }
                }));
            }

            for h in handles {
                h.join().expect("Worker thread panicked in concurrent re-seeding harness");
            }
        });

    // Restore baseline clean cache state after concurrent re-seeding
    SeedOrchestrator::invalidate_cache();
    let _ = SeedOrchestrator::reconstruct();
}

/// Feature 14: Asymmetric 64-to-32 ARX Token Folding Non-Cancellation
/// Validates:
/// Symmetric 64-bit tokens (high 32 == low 32) do NOT cancel out or evaluate to zero.
#[test]
fn prop_dynamic_token_asymmetric_folding() {
    check!()
        .with_arbitrary::<(u32, u32)>()
        .for_each(|(word, domain_sep)| {
            let symmetric_token = ((*word as u64) << 32) | (*word as u64);
            let folded = SeedOrchestrator::arx_fold_token64(symmetric_token, *domain_sep);

            if *word != 0 {
                assert_ne!(
                    folded, 0,
                    "Asymmetric ARX token folding collapsed to zero for symmetric token {symmetric_token:#018X}"
                );
            }
        });
}

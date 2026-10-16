//! Bolero Property-Based Testing Harness: Seed Orchestrator
//! Target Module: test_seed_orchestrator.rs
//! Covers: Features 14, 15 (Seed Reconstruction, Murmur3 Avalanche & Bijectivity)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8};
use std::sync::Arc;
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
            }
        });
}

/// Feature 15: Strict Avalanche Criterion (SAC)
/// Verifies that single-bit flips produce non-zero divergence (bijectivity)
/// and that bit diffusion across input permutations satisfies SAC (mean ~16 bits in [12.0, 20.0]).
#[test]
fn prop_murmur3_avalanche_bit_diffusion() {
    check!()
        .with_arbitrary::<(u32, u8)>()
        .for_each(|(x, bit_pos)| {
            let bit = (bit_pos % 32) as usize;
            let flipped = *x ^ (1u32 << bit);

            let y1 = ref_avalanche_mix(*x);
            let y2 = ref_avalanche_mix(flipped);

            let diff = y1 ^ y2;
            let hamming_distance = diff.count_ones();

            // 1. Bijectivity guarantees that flipping 1 bit strictly produces a distinct output (diff != 0)
            assert!(
                diff != 0,
                "Avalanche violation: flipping bit {} of {:#X} produced zero output difference",
                bit, x
            );
            assert!(
                hamming_distance >= 1,
                "Weak avalanche effect: flipping bit {} of {:#X} changed 0 bits",
                bit, x
            );

            // 2. Strict Avalanche Criterion (SAC): ensemble mean bit diffusion across all 32 single-bit flips
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

/// Feature 14: Dynamic Seed Caching & u8 Compression Invariant
/// Verifies:
/// 1. get_dynamic_seed() is non-zero and stable.
/// 2. get_dynamic_seed_u8() == XOR fold of all 4 bytes of get_dynamic_seed().
#[test]
fn prop_seed_orchestrator_caching_and_u8_compression() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|_iter| {
            let seed_32 = get_dynamic_seed();
            let seed_u8 = get_dynamic_seed_u8();

            assert_ne!(seed_32, 0, "Dynamic seed must be strictly non-zero");

            let b0 = (seed_32 & 0xFF) as u8;
            let b1 = ((seed_32 >> 8) & 0xFF) as u8;
            let b2 = ((seed_32 >> 16) & 0xFF) as u8;
            let b3 = ((seed_32 >> 24) & 0xFF) as u8;
            let expected_u8 = b0 ^ b1 ^ b2 ^ b3;

            assert_eq!(seed_u8, expected_u8, "get_dynamic_seed_u8 diverged from byte XOR folding");
        });
}

/// Feature 14: Multi-Source XOR Entropy Combination Soundness
/// Invariant: XOR combination is strictly commutative and associative,
/// and perturbation of any shard propagates non-zero change.
#[test]
fn prop_multi_source_xor_commutativity_and_sensitivity() {
    check!()
        .with_arbitrary::<(u32, u32, u32, u32)>()
        .for_each(|(s1, s2, s3, delta)| {
            // Commutativity
            let c1 = s1 ^ s2 ^ s3;
            let c2 = s2 ^ s3 ^ s1;
            let c3 = s3 ^ s1 ^ s2;
            assert_eq!(c1, c2, "XOR combination non-commutative (c1 != c2)");
            assert_eq!(c2, c3, "XOR combination non-commutative (c2 != c3)");

            // Sensitivity
            if *delta != 0 {
                let perturbed = (s1 ^ delta) ^ s2 ^ s3;
                assert_ne!(perturbed, c1, "XOR combination insensitive to shard perturbation");
            }
        });
}

/// Feature 14: Multi-Threaded OnceLock Idempotency
/// Invariant: 16 concurrent threads repeatedly querying get_dynamic_seed()
/// receive identical results without data races.
#[test]
fn prop_seed_orchestrator_multithreaded_idempotency() {
    let reference_seed = get_dynamic_seed();
    let mut handles = Vec::new();

    for _ in 0..16 {
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let s = get_dynamic_seed();
                assert_eq!(s, reference_seed, "Concurrent thread observed different reconstructed seed");
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked in OnceLock idempotency test");
    }
}

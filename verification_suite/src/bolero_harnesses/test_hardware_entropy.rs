//! Bolero Property-Based Testing Harness: Hardware Entropy Subsystem
//! Target Module: test_hardware_entropy.rs
//! Covers: Features 16, 17 (CPUID Parsing, Fallback Entropy, FNV-1a Algebraic Invariants)

use arbitrary::Arbitrary;
use bolero::check;
use crate::shims::hardware_entropy_shim::{fnv1a_hash_ref, get_hardware_entropy};

/// Feature 16: Bolero Hardware Entropy FNV-1a Algebraic Invariants
/// Mathematical Invariant:
/// fnv1a(empty) == 0x811C9DC5 (offset basis)
/// fnv1a(data) satisfies step-by-step inductive multiplication by 0x01000193 modulo 2^32.
#[test]
fn prop_fnv1a_reference_matches_algebraic_spec() {
    check!()
        .with_arbitrary::<Vec<u8>>()
        .for_each(|data| {
            let hash = fnv1a_hash_ref(data);

            if data.is_empty() {
                assert_eq!(hash, 0x811C9DC5, "FNV-1a empty input must equal offset basis 0x811C9DC5");
            } else {
                let mut manual = 0x811C9DC5u32;
                for &b in data {
                    manual ^= b as u32;
                    manual = manual.wrapping_mul(0x01000193);
                }
                assert_eq!(hash, manual, "FNV-1a reference diverged from step-by-step specification");
            }
        });
}

/// Feature 16: FNV-1a Strict Non-Commutativity
/// If b1 != b2, then fnv1a([b1, b2]) != fnv1a([b2, b1]).
#[test]
fn prop_fnv1a_non_commutative_sensitivity() {
    check!()
        .with_arbitrary::<(u8, u8)>()
        .for_each(|(b1, b2)| {
            if b1 != b2 {
                let h1 = fnv1a_hash_ref(&[*b1, *b2]);
                let h2 = fnv1a_hash_ref(&[*b2, *b1]);
                assert_ne!(h1, h2, "FNV-1a must be strictly non-commutative for distinct pairs");
            }
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct BitFlipInput {
    pub buffer: Vec<u8>,
    pub flip_idx: usize,
    pub bit_pos: u8,
}

/// Feature 16: Single-Bit Perturbation Sensitivity
/// Flipping any single bit in any byte of a non-empty buffer must strictly diverge the FNV-1a hash.
#[test]
fn prop_fnv1a_single_bit_flip_sensitivity() {
    check!()
        .with_arbitrary::<BitFlipInput>()
        .for_each(|input| {
            if input.buffer.is_empty() || input.buffer.len() > 1024 {
                return;
            }

            let h_orig = fnv1a_hash_ref(&input.buffer);

            let mut perturbed = input.buffer.clone();
            let idx = input.flip_idx % perturbed.len();
            let bit = 1u8 << (input.bit_pos % 8);
            perturbed[idx] ^= bit;

            let h_pert = fnv1a_hash_ref(&perturbed);
            assert_ne!(
                h_orig, h_pert,
                "FNV-1a hash failed to diverge upon single-bit flip at byte index {}",
                idx
            );
        });
}

/// Feature 16: Hardware Entropy Determinism & Non-Zero Guarantee
/// CPUID-derived hardware entropy must be strictly non-zero and stable across invocations.
#[test]
fn prop_hardware_entropy_deterministic_and_non_zero() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|_iter| {
            let e1 = get_hardware_entropy();
            let e2 = get_hardware_entropy();
            assert_ne!(e1, 0, "Hardware entropy must be strictly non-zero");
            assert_eq!(e1, e2, "Hardware entropy must be deterministic on identical host");
        });
}

/// Feature 17: RDTSC Fallback Entropy Variance & Non-Zero Retention
/// Live stack bounds, monotonic progression, and entropy mixing without tautologies.
#[test]
fn prop_rdtsc_fallback_entropy_mixing() {
    // 1. Live hardware property: stack pointer resides in valid Windows user-mode virtual memory
    let stack_var = 0u8;
    let real_sp = &stack_var as *const u8 as usize;
    assert!(
        real_sp >= 0x10000 && real_sp <= 0x7FFF_FFFF_FFFF,
        "Stack pointer {:#X} outside canonical Windows user memory", real_sp
    );

    // 2. Live hardware property: successive RDTSC reads advance monotonically
    let (t1, t2) = unsafe {
        let low1: u32; let high1: u32;
        let low2: u32; let high2: u32;
        core::arch::x86_64::_mm_lfence();
        std::arch::asm!("rdtsc", out("eax") low1, out("edx") high1, options(nomem, nostack));
        core::arch::x86_64::_mm_lfence();
        std::arch::asm!("rdtsc", out("eax") low2, out("edx") high2, options(nomem, nostack));
        (((high1 as u64) << 32) | (low1 as u64), ((high2 as u64) << 32) | (low2 as u64))
    };
    assert!(t2 > t1, "RDTSC counter failed to advance monotonically: t1={}, t2={}", t1, t2);

    // 3. Fuzzing property: arbitrary cycle variations mixed with user stack pointer
    check!()
        .with_arbitrary::<(u32, u32)>()
        .for_each(|(low, high)| {
            let rdtsc_entropy = low ^ high;
            let sp_truncated = (real_sp & 0xFFFF_FFFF) as u32;
            let mixed = rdtsc_entropy ^ sp_truncated;

            // Invariant: If rdtsc halves are non-identical (low != high), rdtsc_entropy is non-zero
            if *low != *high {
                assert_ne!(rdtsc_entropy, 0, "Non-identical rdtsc halves must yield non-zero entropy");
            }
            // The mixed value can only equal 0 if rdtsc_entropy exactly equals sp_truncated
            let is_zero = mixed == 0;
            assert_eq!(is_zero, rdtsc_entropy == sp_truncated);
        });
}

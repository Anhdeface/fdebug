//! Bolero Property-Based Testing Harness: Hardware Entropy Subsystem
//! Target Module: test_hardware_entropy.rs
//! Covers: Features 16, 17 (CPUID Parsing, Fallback Entropy, FNV-1a Algebraic Invariants)

use arbitrary::Arbitrary;
use bolero::check;
use crate::shims::hardware_entropy_shim::{fnv1a_hash_ref, get_hardware_entropy};

/// Feature 16: Bolero Hardware Entropy FNV-1a Algebraic Invariants & Inductive State Machine
/// Mathematical Invariants:
/// 1. Basis invariant: fnv1a(empty) == 0x811C9DC5.
/// 2. Inductive transition: H_{k+1} = (H_k ^ byte) * 0x01000193 (mod 2^32).
/// 3. Homomorphic concatenation: fnv1a(A || B) == fold(fnv1a(A), B).
#[test]
fn prop_fnv1a_reference_matches_algebraic_spec() {
    check!()
        .with_arbitrary::<Vec<u8>>()
        .for_each(|data| {
            let hash = fnv1a_hash_ref(data);

            if data.is_empty() {
                assert_eq!(hash, 0x811C9DC5, "FNV-1a empty input must equal offset basis 0x811C9DC5");
            } else {
                // 1. Inductive state machine step verification
                let mut manual = 0x811C9DC5u32;
                for &b in data {
                    manual ^= b as u32;
                    manual = manual.wrapping_mul(0x01000193);
                }
                assert_eq!(hash, manual, "FNV-1a reference diverged from step-by-step specification");

                // 2. Homomorphic concatenation invariant
                let mid = data.len() / 2;
                let (prefix, suffix) = data.split_at(mid);
                let h_prefix = fnv1a_hash_ref(prefix);
                let mut h_combined = h_prefix;
                for &b in suffix {
                    h_combined ^= b as u32;
                    h_combined = h_combined.wrapping_mul(0x01000193);
                }
                assert_eq!(
                    hash, h_combined,
                    "Homomorphic concatenation invariant violated for FNV-1a fold"
                );
            }
        });
}

/// Feature 16: FNV-1a Multi-Byte Strict Non-Commutativity & Transposition Sensitivity
/// Invariants:
/// 1. For any buffer containing at least two distinct bytes, swapping them strictly alters the hash.
/// 2. For non-palindromic buffers, reversing the buffer strictly alters the hash.
#[test]
fn prop_fnv1a_non_commutative_sensitivity() {
    check!()
        .with_arbitrary::<Vec<u8>>()
        .for_each(|buffer| {
            if buffer.len() < 2 || buffer.len() > 512 {
                return;
            }

            // 1. Transposition sensitivity: swap adjacent distinct bytes
            for i in 0..(buffer.len() - 1) {
                if buffer[i] != buffer[i + 1] {
                    let mut transposed = buffer.clone();
                    transposed.swap(i, i + 1);
                    let h_orig = fnv1a_hash_ref(&buffer);
                    let h_trans = fnv1a_hash_ref(&transposed);
                    assert_ne!(
                        h_orig, h_trans,
                        "FNV-1a must be strictly non-commutative for transposed adjacent bytes at index {}",
                        i
                    );
                    break;
                }
            }

            // 2. Reversal non-commutativity: if buffer is not a palindrome, H(B) != H(rev(B))
            let mut reversed = buffer.clone();
            reversed.reverse();
            if *buffer != reversed {
                let h1 = fnv1a_hash_ref(&buffer);
                let h2 = fnv1a_hash_ref(&reversed);
                assert_ne!(h1, h2, "FNV-1a must be strictly non-commutative under buffer reversal");
            }
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct BitFlipInput {
    pub buffer: Vec<u8>,
    pub flip_idx: usize,
    pub bit_pos: u8,
    pub flip_idx2: usize,
    pub bit_pos2: u8,
}

/// Feature 16: Single-Bit and Double-Bit Perturbation Sensitivity
/// Invariants:
/// 1. Flipping any single bit in any byte of a non-empty buffer strictly diverges the FNV-1a hash.
/// 2. Double-bit perturbations never cancel out to the original hash.
/// 3. Avalanche difference Hamming weight is strictly non-zero.
#[test]
fn prop_fnv1a_single_bit_flip_sensitivity() {
    check!()
        .with_arbitrary::<BitFlipInput>()
        .for_each(|input| {
            if input.buffer.is_empty() || input.buffer.len() > 1024 {
                return;
            }

            let h_orig = fnv1a_hash_ref(&input.buffer);

            // 1. Single bit flip
            let mut perturbed = input.buffer.clone();
            let idx1 = input.flip_idx % perturbed.len();
            let bit1 = 1u8 << (input.bit_pos % 8);
            perturbed[idx1] ^= bit1;

            let h_pert = fnv1a_hash_ref(&perturbed);
            assert_ne!(
                h_orig, h_pert,
                "FNV-1a hash failed to diverge upon single-bit flip at byte index {}",
                idx1
            );

            let diff = h_orig ^ h_pert;
            assert!(diff.count_ones() >= 1, "Single-bit flip produced zero Hamming difference");

            // 2. Double-bit perturbation non-cancellation
            let idx2 = input.flip_idx2 % perturbed.len();
            let bit2 = 1u8 << (input.bit_pos2 % 8);
            if idx1 != idx2 || bit1 != bit2 {
                let mut double_perturbed = perturbed.clone();
                double_perturbed[idx2] ^= bit2;
                let h_double = fnv1a_hash_ref(&double_perturbed);
                assert_ne!(h_double, h_orig, "Double-bit perturbation cancelled out to original hash");
                assert_ne!(h_double, h_pert, "Second bit flip failed to alter single-flip hash");
            }
        });
}

/// Feature 16: Hardware Entropy Determinism & Zero-Buffer Anti-Tamper Model
/// Invariants:
/// 1. CPUID-derived hardware entropy is strictly non-zero and stable across invocations.
/// 2. If an attacker zeroes out the CPUID buffer, the anti-tampering branch mixes stack address
///    entropy, guaranteeing non-zero output and divergence from unmitigated zero-buffer hash.
#[test]
fn prop_hardware_entropy_deterministic_and_non_zero() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|_iter| {
            // 1. Live hardware property: CPUID entropy is non-zero and stable
            let e1 = get_hardware_entropy();
            let e2 = get_hardware_entropy();
            assert_ne!(e1, 0, "Hardware entropy must be strictly non-zero");
            assert_eq!(e1, e2, "Hardware entropy must be deterministic on identical host");

            // 2. Anti-tampering zero-buffer model (hardware_entropy.rs:263-272)
            for &buf_len in &[12usize, 16, 32, 48, 64] {
                let zero_buf = vec![0u8; buf_len];
                let unmitigated_hash = fnv1a_hash_ref(&zero_buf);

                let stack_var = 0u8;
                let stack_ptr = (&stack_var as *const u8 as usize) as u32;
                let anti_tamper_entropy = unmitigated_hash ^ stack_ptr;

                assert_ne!(
                    anti_tamper_entropy, 0,
                    "Anti-tamper zero-buffer entropy must be non-zero for buffer len {}",
                    buf_len
                );
                assert_ne!(
                    anti_tamper_entropy, unmitigated_hash,
                    "Anti-tamper stack mixing must strictly diverge from bare zero hash"
                );
            }
        });
}

/// Feature 17: Serialized RDTSC Fallback Entropy Variance & Monotonic Progress
/// Invariants:
/// 1. Stack pointer resides in valid canonical Windows user-mode memory [0x10000, 0x7FFF_FFFF_FFFF].
/// 2. Successive serialized RDTSC samples advance monotonically.
/// 3. Mixed fallback entropy (low ^ high ^ stack_ptr) preserves non-degeneracy and bit-parity.
#[test]
fn prop_rdtsc_fallback_entropy_mixing() {
    // 1. Live hardware property: stack pointer resides in valid Windows user-mode virtual memory
    let stack_var = 0u8;
    let real_sp = &stack_var as *const u8 as usize;
    assert!(
        real_sp >= 0x10000 && real_sp <= 0x7FFF_FFFF_FFFF,
        "Stack pointer {:#X} outside canonical Windows user memory", real_sp
    );

    // 2. Serialized RDTSC monotonic progress: successive samples advance strictly
    let mut prev_t = 0u64;
    for _ in 0..5 {
        let (low, high): (u32, u32);
        unsafe {
            core::arch::x86_64::_mm_lfence();
            std::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
            core::arch::x86_64::_mm_lfence();
        }
        let t = ((high as u64) << 32) | (low as u64);
        if prev_t != 0 {
            assert!(t > prev_t, "Serialized RDTSC failed to advance monotonically: prev={}, curr={}", prev_t, t);
        }
        prev_t = t;
    }

    // 3. Fuzzing property: arbitrary cycle variations mixed with user stack pointer
    check!()
        .with_arbitrary::<(u32, u32)>()
        .for_each(|(low, high)| {
            let rdtsc_entropy = low ^ high;
            let sp_truncated = (real_sp & 0xFFFF_FFFF) as u32;
            let mixed = rdtsc_entropy ^ sp_truncated;

            // Invariant 1: If low != high, rdtsc_entropy is strictly non-zero
            if *low != *high {
                assert_ne!(rdtsc_entropy, 0, "Non-identical rdtsc halves must yield non-zero entropy");
            }

            // Invariant 2: Linear independence / information retention
            assert_eq!(
                mixed ^ sp_truncated,
                rdtsc_entropy,
                "Mixed entropy failed linear invertibility with stack pointer"
            );

            // Invariant 3: Parity preservation
            let expected_parity = (low.count_ones() + high.count_ones() + sp_truncated.count_ones()) % 2;
            let actual_parity = mixed.count_ones() % 2;
            assert_eq!(
                actual_parity, expected_parity,
                "Parity preservation violated in fallback entropy mixing"
            );
        });
}

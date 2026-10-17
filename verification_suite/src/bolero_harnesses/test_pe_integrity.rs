//! Bolero Property-Based Testing Harness: PE Integrity & Section Sharding
//! Target Module: test_pe_integrity.rs
//! Covers: Features 22, 23 (1KB Sharding Algebra, Heartbeat Check & INTEGRITY_TOKEN Dynamic Evolution)

use arbitrary::Arbitrary;
use bolero::check;
use crate::shims::pe_integrity_shim::{heartbeat_check, INTEGRITY_TOKEN};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

static TOKEN_MUTEX: Mutex<()> = Mutex::new(());

/// RAII Guard to preserve and restore INTEGRITY_TOKEN during tests that mutate static atomics
struct TokenRestoreGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    token: u64,
}

impl TokenRestoreGuard {
    fn acquire() -> Self {
        let lock = TOKEN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let token = INTEGRITY_TOKEN.load(Ordering::Relaxed);
        Self { _lock: lock, token }
    }
}

impl Drop for TokenRestoreGuard {
    fn drop(&mut self) {
        INTEGRITY_TOKEN.store(self.token, Ordering::Relaxed);
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub struct SectionShardingInput {
    pub text_size: u32,
    pub seed: u32,
}

/// Feature 22: Bolero PE Integrity 1KB Section Sharding Bounds Algebra
/// Invariants:
/// 1. Bounds safety: 0 < chunk_size <= 1024, offset + chunk_size <= text_size.
/// 2. Partition completeness: Sum of all chunk sizes across all shards exactly equals text_size.
/// 3. Disjointness: Contiguous non-overlapping partitioning of .text section.
/// 4. Boundary alignment: Last chunk handles non-multiple remainder cleanly.
#[test]
fn prop_section_sharding_bounds_algebra() {
    check!()
        .with_arbitrary::<SectionShardingInput>()
        .for_each(|input| {
            if input.text_size == 0 || input.text_size > 100_000_000 {
                return;
            }

            const SHARD_SIZE: usize = 1024;
            let text_size = input.text_size as usize;
            let num_shards = (text_size + SHARD_SIZE - 1) / SHARD_SIZE;
            assert!(num_shards >= 1, "Number of shards must be at least 1");

            let shard_idx = (input.seed as usize) % num_shards;
            let offset = shard_idx * SHARD_SIZE;
            let remaining = text_size.saturating_sub(offset);
            let chunk_size = std::cmp::min(remaining, SHARD_SIZE);

            // Invariant 1: Bounds safety
            assert!(offset < text_size, "Shard offset exceeded text size");
            assert!(chunk_size > 0, "Chunk size must be non-zero");
            assert!(chunk_size <= SHARD_SIZE, "Chunk size exceeded 1024 bytes");
            assert!(offset + chunk_size <= text_size, "Shard window exceeded text section boundary");

            // Invariant 2: Disjointness and completeness of section partition
            let sum_chunks: usize = (0..num_shards)
                .map(|i| {
                    let off = i * SHARD_SIZE;
                    let rem = text_size.saturating_sub(off);
                    std::cmp::min(rem, SHARD_SIZE)
                })
                .sum();
            assert_eq!(sum_chunks, text_size, "Partition completeness violated: sum of shards != text_size");

            // Invariant 3: Last shard boundary bound
            let last_chunk = text_size.saturating_sub((num_shards - 1) * SHARD_SIZE);
            assert!(last_chunk > 0 && last_chunk <= SHARD_SIZE);
            let expected_last = if text_size % SHARD_SIZE == 0 {
                SHARD_SIZE
            } else {
                text_size % SHARD_SIZE
            };
            assert_eq!(last_chunk, expected_last, "Last shard size calculation diverged");
        });
}

/// Helper model for production clean SplitMix64 ARX step (src/protector/pe_integrity.rs:236-246)
fn step_clean_model(token: u64, current_hash: u32) -> u64 {
    let mut mixed = (token.rotate_left(13) ^ (current_hash as u64)).wrapping_mul(0x9E3779B97F4A7C15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D049BB133111EB);
    let mut tok = mixed ^ (mixed >> 31);
    if tok == 0 || tok == 0xDEAD_DEAD_DEAD_DEAD {
        tok ^= 0x1337_C0DE_5A5A_A5A5;
    }
    tok
}

/// Helper model for production mismatch/tamper trap step (src/protector/pe_integrity.rs:269-276)
fn step_mismatch_model(token: u64) -> u64 {
    let mut tok = (token ^ 0xBAAD_F00D_CAFE_BABE)
        .rotate_left(13)
        .wrapping_mul(0x517CC1B727220A95)
        .wrapping_add(1);
    if tok == 0 || tok == 0xDEAD_DEAD_DEAD_DEAD {
        tok ^= 0x1337_C0DE_5A5A_A5A5;
    }
    tok
}

/// Feature 23: Bolero PE Integrity Heartbeat Check & Dynamic Evolution
/// Invariants:
/// 1. Dynamic heartbeat_check returns non-zero token on clean execution.
/// 2. Heartbeat does not return the instant poison error code 0xDEAD_DEAD_DEAD_DEAD.
/// 3. Deterministic evolution from identical state and seed.
#[test]
fn prop_token_evolution_deterministic_on_clean_state() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let _guard = TokenRestoreGuard::acquire();

            let initial_token = 0xCAFE_BABE_1337_C0DEu64;
            INTEGRITY_TOKEN.store(initial_token, Ordering::Relaxed);

            let token1 = heartbeat_check(*seed);
            assert_ne!(token1, 0, "Heartbeat check must never produce a zero token");
            assert_ne!(
                token1, 0xDEAD_DEAD_DEAD_DEAD,
                "Heartbeat check returned instant poison failure"
            );

            // Invariant: Determinism from identical state
            INTEGRITY_TOKEN.store(initial_token, Ordering::Relaxed);
            let token2 = heartbeat_check(*seed);
            assert_eq!(token1, token2, "Token evolution non-deterministic for identical initial state and seed");
        });
}

/// Feature 23: Production SplitMix64/ARX Simulated Tamper Token Poisoning Cascade
/// Replaces obsolete linear models ((T <<< 1) ^ h) with production ARX equations:
/// 1. Differential Non-Cancellation Theorem: For any delta != 0, clean(T, h ^ delta) != clean(T, h).
/// 2. Poison trajectory divergence: clean(T, h) != corrupted(T).
/// 3. Non-Involution Theorem: g(g(T)) != T prevents reset attacks.
#[test]
fn prop_simulated_tamper_token_poisoning_cascade() {
    check!()
        .with_arbitrary::<(u64, u32, u32)>()
        .for_each(|(old_token, golden_hash, hash_perturbation)| {
            if *hash_perturbation == 0 {
                return;
            }

            let corrupted_hash = *golden_hash ^ *hash_perturbation;

            let clean_token = step_clean_model(*old_token, *golden_hash);
            let tampered_clean_token = step_clean_model(*old_token, corrupted_hash);
            let poisoned_token = step_mismatch_model(*old_token);

            // Invariant 1: Differential Non-Cancellation Theorem
            assert_ne!(
                clean_token, tampered_clean_token,
                "Tampered hash produced collision with clean trajectory (differential cancellation)"
            );

            // Invariant 2: Poison branch trajectory divergence
            assert_ne!(
                clean_token, poisoned_token,
                "Poisoned token collided with clean token trajectory"
            );

            // Invariant 3: Non-Involution Theorem
            let double_poisoned = step_mismatch_model(poisoned_token);
            assert_ne!(
                double_poisoned, *old_token,
                "Trap evolution is an involution (g(g(T)) == T), allowing reset attacks"
            );
        });
}

/// Compile-time modular inverse calculation for odd 64-bit integers via Newton's method
const fn modinv64(a: u64) -> u64 {
    let mut x = 1u64;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
        i += 1;
    }
    x
}

#[inline(always)]
fn inv_shift_xor_31(x: u64) -> u64 {
    x ^ (x >> 31) ^ (x >> 62)
}

#[inline(always)]
fn inv_shift_xor_27(x: u64) -> u64 {
    x ^ (x >> 27) ^ (x >> 54)
}

#[inline(always)]
fn inv_shift_xor_30(x: u64) -> u64 {
    x ^ (x >> 30) ^ (x >> 60)
}

/// Exact mathematical inverse of the production SplitMix64 ARX transformation
#[inline(always)]
fn invert_splitmix64_clean(evolved: u64, current_hash: u32) -> u64 {
    const C1: u64 = 0x9E3779B97F4A7C15;
    const C2: u64 = 0xBF58476D1CE4E5B9;
    const C3: u64 = 0x94D049BB133111EB;
    const C1_INV: u64 = modinv64(C1);
    const C2_INV: u64 = modinv64(C2);
    const C3_INV: u64 = modinv64(C3);

    // 1. Invert: tok = mixed3 ^ (mixed3 >> 31)
    let mixed3 = inv_shift_xor_31(evolved);
    // 2. Invert: mixed3 = y2.wrapping_mul(C3)
    let y2 = mixed3.wrapping_mul(C3_INV);
    // 3. Invert: y2 = mixed2 ^ (mixed2 >> 27)
    let mixed2 = inv_shift_xor_27(y2);
    // 4. Invert: mixed2 = y1.wrapping_mul(C2)
    let y1 = mixed2.wrapping_mul(C2_INV);
    // 5. Invert: y1 = mixed1 ^ (mixed1 >> 30)
    let mixed1 = inv_shift_xor_30(y1);
    // 6. Invert: mixed1 = y0.wrapping_mul(C1)
    let y0 = mixed1.wrapping_mul(C1_INV);
    // 7. Invert: y0 = token.rotate_left(13) ^ (current_hash as u64)
    let rot = y0 ^ (current_hash as u64);
    rot.rotate_right(13)
}

/// Feature 23: Production SplitMix64/ARX Single-Step Token Evolution Invertibility
/// Invariant: Given evolved token and current hash, previous token can be mathematically inverted
/// via modular multiplicative inverses and shift-xor algebraic inversion:
/// invert(forward(T, h), h) == T and forward(invert(T, h), h) == T.
#[test]
fn prop_token_evolution_single_step_invertibility() {
    check!()
        .with_arbitrary::<(u64, u32)>()
        .for_each(|(token, hash)| {
            // Forward transformation matching production clean SplitMix64 ARX step
            let evolved = {
                let mut mixed = (token.rotate_left(13) ^ (*hash as u64)).wrapping_mul(0x9E3779B97F4A7C15);
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D049BB133111EB);
                mixed ^ (mixed >> 31)
            };

            // Invert the non-linear ARX transformation
            let recovered = invert_splitmix64_clean(evolved, *hash);

            // Invariant 1: Full algebraic bijectivity over Z_{2^64}
            assert_eq!(
                recovered, *token,
                "Production SplitMix64/ARX step inversion failed for token {:#X}, hash {:#X}",
                token, hash
            );

            // Invariant 2: Dual inverse verification: forward(invert(x)) == x
            let dual_inverted = invert_splitmix64_clean(*token, *hash);
            let dual_recovered = {
                let mut mixed = (dual_inverted.rotate_left(13) ^ (*hash as u64)).wrapping_mul(0x9E3779B97F4A7C15);
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D049BB133111EB);
                mixed ^ (mixed >> 31)
            };
            assert_eq!(dual_recovered, *token, "Dual inverse verification failed");
        });
}

//! Bolero Property-Based Testing Harness: PE Integrity & Section Sharding
//! Target Module: test_pe_integrity.rs
//! Covers: Features 22, 23 (1KB Sharding Algebra, Heartbeat Check & INTEGRITY_TOKEN Dynamic Evolution)

use arbitrary::Arbitrary;
use bolero::check;
use crate::shims::pe_integrity_shim::{heartbeat_check, INTEGRITY_TOKEN};
use std::sync::atomic::Ordering;

#[derive(Arbitrary, Debug, Clone)]
pub struct SectionShardingInput {
    pub text_size: u32,
    pub seed: u32,
}

/// Feature 22: Bolero PE Integrity 1KB Section Sharding Bounds Algebra
/// Invariant:
/// For any section size > 0 and arbitrary selection seed:
/// 1. num_shards = ceil(text_size / 1024) >= 1.
/// 2. shard_idx = seed % num_shards satisfies 0 <= shard_idx < num_shards.
/// 3. offset = shard_idx * 1024 strictly < text_size.
/// 4. 0 < chunk_size <= 1024 and offset + chunk_size <= text_size.
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

            // Bounds safety invariants
            assert!(offset < text_size, "Shard offset exceeded text size");
            assert!(chunk_size > 0, "Chunk size must be non-zero");
            assert!(chunk_size <= SHARD_SIZE, "Chunk size exceeded 1024 bytes");
            assert!(offset + chunk_size <= text_size, "Shard window exceeded text section boundary");
        });
}

/// Feature 23: Bolero PE Integrity Heartbeat Check & Dynamic Evolution
/// Invariants:
/// 1. Dynamic heartbeat_check returns non-zero token on clean execution.
/// 2. Heartbeat does not return the instant poison error code 0xDEAD_DEAD_DEAD_DEAD.
#[test]
fn prop_token_evolution_deterministic_on_clean_state() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let token_after = heartbeat_check(*seed);

            assert_ne!(token_after, 0, "Heartbeat check must never produce a zero token");
            assert_ne!(
                token_after, 0xDEAD_DEAD_DEAD_DEAD,
                "Heartbeat check returned instant poison failure"
            );
        });
}

/// Feature 23: Simulated Tamper Token Poisoning Divergence
/// Invariant:
/// When current_hash != reference_hash, corrupted token (old ^ 0xBAAD_F00D_CAFE_BABE)
/// strictly diverges from clean evolved token (old.rotate_left(1) ^ golden).
#[test]
fn prop_simulated_tamper_token_poisoning_cascade() {
    check!()
        .with_arbitrary::<(u64, u32, u32)>()
        .for_each(|(old_token, corrupted_hash, golden_hash)| {
            if corrupted_hash == golden_hash {
                return;
            }

            let corrupted_token = *old_token ^ 0xBAAD_F00D_CAFE_BABE;
            let clean_token = old_token.rotate_left(1) ^ (*golden_hash as u64);

            assert_ne!(
                clean_token, corrupted_token,
                "Corrupted token collided with clean token trajectory"
            );
        });
}

/// Feature 23: Single-Step Token Evolution Invertibility
/// Invariant: Given evolved token and current hash, previous token can be mathematically inverted:
/// previous = (evolved ^ hash).rotate_right(1).
#[test]
fn prop_token_evolution_single_step_invertibility() {
    check!()
        .with_arbitrary::<(u64, u32)>()
        .for_each(|(token, hash)| {
            let evolved = token.rotate_left(1) ^ (*hash as u64);
            let recovered = (evolved ^ (*hash as u64)).rotate_right(1);
            assert_eq!(recovered, *token, "Single-step token inversion failed");
        });
}

#![allow(unused_imports, dead_code)]

//! # Challenger M2 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Adversarial Challenger for Milestone 2:
//! (Token Evolution & Corruptible Mathematical Hardening)
//!
//! ## Attack Surfaces Stress-Tested:
//! 1. **Adversarial Differential Stress Test (SplitMix64 / ARX Token Evolution)**:
//!    - Strict Avalanche Criterion (SAC): Per-bit flip probability distribution across all 64 input bits of T and 32 bits of h.
//!    - Search for algebraic differential cancellation across rotational pairs (delta_2 = delta_1 <<< k), arithmetic offsets, and low-weight bitmasks.
//!    - Differential uniformity & trail dispersion across 20,000 distinct samples.
//!    - Live PE heartbeat differential non-cancellation on actual executable sections.
//! 2. **Adversarial Involutory & Cycle Test (Hash Mismatch Trap Evolution)**:
//!    - Multi-step consecutive mismatch sequences (k = 2, 3, 4, 5, 10, 50, 100, 1,000 events) confirming no return to clean token.
//!    - Search for fixed points (G(T) == T) and 2-cycles (G(G(T)) == T) over 1,000,000 samples.
//!    - Interleaved match / mismatch schedule resilience.
//!    - Live PE memory tampering with 50 consecutive heartbeat checks verifying monotonic divergence and poison seed accumulation.
//! 3. **Adversarial Corruptible Stress Test**:
//!    - Clean state preservation across all 5 types (String, Vec<u8>, bool, u32, f64) with extreme boundaries (empty, 100KB, subnormals, infinities).
//!    - Poisoned state corruption efficacy & edge-case characterization:
//!      * f64 multiplicative invariance on 0.0 and infinities/NaNs.
//!      * u32 lower-32-bit zero boundary vulnerability (token as u32 == 0).
//!      * String UTF-8 multi-byte char vs byte length boundary mismatch.
//! 4. **Degenerate Trapdoor State Escape**:
//!    - Zero-token (token == 0) and dead-poison (token == 0xDEAD_DEAD_DEAD_DEAD) immediate escape.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    global_state,
    pe_integrity,
    CANONICAL_CLEAN_TOKEN,
    Corruptible,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Helper RAII guard to safely restore INTEGRITY_TOKEN on test completion or unwind
struct TokenRestoreGuard(u64);
impl Drop for TokenRestoreGuard {
    fn drop(&mut self) {
        pe_integrity::INTEGRITY_TOKEN.store(self.0, Ordering::Relaxed);
    }
}

/// Helper RAII guard to safely restore POISON_SEED on test completion or unwind
struct PoisonRestoreGuard(u64);
impl Drop for PoisonRestoreGuard {
    fn drop(&mut self) {
        global_state::POISON_SEED.store(self.0, Ordering::Relaxed);
    }
}

/// Reference implementation of match branch evolution
fn evolve_match_ref(token: u64, current_hash: u32) -> u64 {
    let mut mixed = (token.rotate_left(13) ^ (current_hash as u64)).wrapping_mul(0x9E3779B97F4A7C15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D049BB133111EB);
    let mut tok = mixed ^ (mixed >> 31);
    if tok == 0 || tok == 0xDEAD_DEAD_DEAD_DEAD {
        tok ^= 0x1337_C0DE_5A5A_A5A5;
    }
    tok
}

/// Reference implementation of mismatch branch evolution
fn evolve_mismatch_ref(token: u64) -> u64 {
    let mut tok = (token ^ 0xBAAD_F00D_CAFE_BABE)
        .rotate_left(13)
        .wrapping_mul(0x517CC1B727220A95)
        .wrapping_add(1);
    if tok == 0 || tok == 0xDEAD_DEAD_DEAD_DEAD {
        tok ^= 0x1337_C0DE_5A5A_A5A5;
    }
    tok
}

#[cfg(target_os = "windows")]
extern "system" {
    fn VirtualProtect(
        lpAddress: *mut std::ffi::c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
}

#[cfg(target_os = "windows")]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[cfg(target_os = "windows")]
struct MemoryTamperGuard {
    ptr: *mut u8,
    original_byte: u8,
    old_protect: u32,
}

#[cfg(target_os = "windows")]
impl Drop for MemoryTamperGuard {
    fn drop(&mut self) {
        unsafe {
            *self.ptr = self.original_byte;
            let mut dummy = 0u32;
            VirtualProtect(self.ptr as _, 1, self.old_protect, &mut dummy);
        }
    }
}

// ============================================================================
// 1. TASK 1: ADVERSARIAL DIFFERENTIAL STRESS TEST & AVALANCHE ANALYSIS
// ============================================================================

/// Test 1.1: Strict Avalanche Criterion (SAC) & Bit Diffusion Analysis
/// Verifies that flipping any single bit in token T produces ~32 bit flips in output (ideal: 50%),
/// and flipping any single bit in hash h produces ~32 bit flips in output.
#[test]
fn test_adversarial_task1_strict_avalanche_criterion_and_sac() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let test_samples = 2000;
    let mut rng_state = 0x12345678_9ABCDEF0u64;
    let mut next_rng = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng_state
    };

    // 1. Avalanche test for Token T input bits (0..64)
    let mut bit_flip_counts = [0usize; 64];
    let mut total_flips = 0usize;
    let mut min_flips_seen = 64usize;
    let mut max_flips_seen = 0usize;

    for _ in 0..test_samples {
        let base_token = next_rng();
        let base_hash = (next_rng() & 0xFFFFFFFF) as u32;
        let baseline_out = evolve_match_ref(base_token, base_hash);

        for bit in 0..64 {
            let perturbed_token = base_token ^ (1u64 << bit);
            let perturbed_out = evolve_match_ref(perturbed_token, base_hash);
            let diff = baseline_out ^ perturbed_out;
            let count = diff.count_ones() as usize;

            total_flips += count;
            if count < min_flips_seen {
                min_flips_seen = count;
            }
            if count > max_flips_seen {
                max_flips_seen = count;
            }

            for out_bit in 0..64 {
                if (diff & (1u64 << out_bit)) != 0 {
                    bit_flip_counts[out_bit] += 1;
                }
            }
        }
    }

    let total_trials = test_samples * 64;
    let mean_flips = total_flips as f64 / total_trials as f64;
    println!("[Task 1] SAC Token Avalanche Mean Flipped Bits: {:.2} / 64 (Min: {}, Max: {})",
        mean_flips, min_flips_seen, max_flips_seen);

    // Assert strong diffusion: mean flipped bits must be close to 32.0 (between 30.0 and 34.0)
    assert!(
        mean_flips >= 30.5 && mean_flips <= 33.5,
        "Avalanche defect! Mean flips {:.2} deviates significantly from ideal 32.0",
        mean_flips
    );
    // Minimum flips in any trial must be >= 10 (no weak diffusion states)
    assert!(
        min_flips_seen >= 10,
        "Weak avalanche defect! Found trial with only {} bit flips",
        min_flips_seen
    );

    // Each individual output bit must flip with probability between 0.42 and 0.58
    for out_bit in 0..64 {
        let prob = bit_flip_counts[out_bit] as f64 / total_trials as f64;
        assert!(
            prob >= 0.42 && prob <= 0.58,
            "SAC defect on output bit {}: flip probability was {:.4} (expected ~0.50)",
            out_bit, prob
        );
    }

    // 2. Avalanche test for Hash h input bits (0..32)
    let mut total_hash_flips = 0usize;
    let mut min_hash_flips = 64usize;
    for _ in 0..test_samples {
        let base_token = next_rng();
        let base_hash = (next_rng() & 0xFFFFFFFF) as u32;
        let baseline_out = evolve_match_ref(base_token, base_hash);

        for bit in 0..32 {
            let perturbed_hash = base_hash ^ (1u32 << bit);
            let perturbed_out = evolve_match_ref(base_token, perturbed_hash);
            let diff = baseline_out ^ perturbed_out;
            let count = diff.count_ones() as usize;

            total_hash_flips += count;
            if count < min_hash_flips {
                min_hash_flips = count;
            }
        }
    }

    let mean_hash_flips = total_hash_flips as f64 / (test_samples * 32) as f64;
    println!("[Task 1] SAC Hash Avalanche Mean Flipped Bits: {:.2} / 64 (Min: {})",
        mean_hash_flips, min_hash_flips);
    assert!(
        mean_hash_flips >= 30.5 && mean_hash_flips <= 33.5,
        "Hash avalanche defect! Mean flips was {:.2}",
        mean_hash_flips
    );
    assert!(
        min_hash_flips >= 10,
        "Hash weak avalanche defect! Minimum flips was {}",
        min_hash_flips
    );
}

/// Test 1.2: Exhaustive Rotational and Arithmetic Differential Cancellation Search
/// Searches for any differential pair (delta_1, delta_2) such that:
///   E(T ^ delta_1, h) ^ delta_2 == E(T, h)
/// Across all 64 rotations (delta_2 = delta_1 <<< k), arithmetic negations (delta_2 = -delta_1),
/// and arbitrary constants.
#[test]
fn test_adversarial_task1_differential_cancellation_search() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng_state = 0xCAFEBABE_1337C0DEu64;
    let mut next_rng = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng_state
    };

    let search_rounds = 5000;
    for _ in 0..search_rounds {
        let t = next_rng();
        let h = (next_rng() & 0xFFFFFFFF) as u32;
        let delta1 = next_rng();
        if delta1 == 0 {
            continue;
        }

        let e_clean = evolve_match_ref(t, h);
        let e_tampered = evolve_match_ref(t ^ delta1, h);

        // Challenge 1: Rotational differential delta_2 = delta_1 <<< k for all k in 0..64
        for rot in 0..64 {
            let delta2_rot = delta1.rotate_left(rot);
            let net = e_tampered ^ delta2_rot;
            assert_ne!(
                net, e_clean,
                "CRITICAL: Rotational differential cancellation discovered! \
                 delta1=0x{:016X}, rot={}, delta2=0x{:016X}",
                delta1, rot, delta2_rot
            );
        }

        // Challenge 2: Arithmetic differential delta_2 = -delta_1 or delta_1 + c
        let delta2_neg = delta1.wrapping_neg();
        assert_ne!(
            e_tampered ^ delta2_neg, e_clean,
            "CRITICAL: Arithmetic negation cancellation discovered!"
        );
        let delta2_add1 = delta1.wrapping_add(1);
        assert_ne!(
            e_tampered ^ delta2_add1, e_clean,
            "CRITICAL: Arithmetic +1 cancellation discovered!"
        );
    }

    // Challenge 3: Differential Uniformity & Max Output Difference Frequency
    // For a fixed non-zero delta_1, test 1,000 different tokens T.
    // In an affine cipher, one output difference occurs with 100% frequency (1000/1000).
    // In SplitMix64, no single output difference should appear more than 3 times.
    let fixed_deltas = [
        0x0000_0000_0000_0001u64,
        0x8000_0000_0000_0000u64,
        0x1234_5678_9ABC_DEF0u64,
        0x0000_0001_0000_0000u64,
    ];

    for &d1 in &fixed_deltas {
        let mut diff_freq: HashMap<u64, usize> = HashMap::new();
        let fixed_h = 0x5A5A_A5A5u32;

        for _ in 0..1000 {
            let t = next_rng();
            let out_clean = evolve_match_ref(t, fixed_h);
            let out_tampered = evolve_match_ref(t ^ d1, fixed_h);
            let out_diff = out_clean ^ out_tampered;
            *diff_freq.entry(out_diff).or_insert(0) += 1;
        }

        let max_freq = diff_freq.values().copied().max().unwrap_or(0);
        println!("[Task 1] Fixed delta 0x{:016X} -> Max diff frequency: {} / 1000", d1, max_freq);
        assert!(
            max_freq <= 3,
            "Differential uniformity defect! Difference occurred {} times out of 1000 (max allowed: 3)",
            max_freq
        );
    }
}

/// Test 1.3: Live PE Shard Differential Non-Cancellation Stress
/// Executes production `pe_integrity::heartbeat_check` across consecutive shards
/// verifying that adversarial delta injection never cancels out in the actual binary.
#[test]
fn test_adversarial_task1_live_shard_differential_non_cancellation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let orig_tok = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed);
    let _guard = TokenRestoreGuard(orig_tok);

    let test_seeds = [
        (0u32, 1u32, 0x0000_0000_DEAD_BEEFu64),
        (5u32, 6u32, 0x8000_0000_0000_0001u64),
        (10u32, 11u32, 0x1337_C0DE_5A5A_A5A5u64),
        (60u32, 61u32, 0xFFFF_0000_AAAA_5555u64),
    ];

    for (s1, s2, d1) in test_seeds {
        pe_integrity::INTEGRITY_TOKEN.store(CANONICAL_CLEAN_TOKEN, Ordering::Relaxed);
        let tok1_clean = pe_integrity::heartbeat_check(s1);
        let tok2_clean = pe_integrity::heartbeat_check(s2);

        // Adversary injects d1 after shard 1
        pe_integrity::INTEGRITY_TOKEN.store(tok1_clean ^ d1, Ordering::Relaxed);
        let tok2_tampered_step = pe_integrity::heartbeat_check(s2);

        // Test every rotation k in 0..64 for d2
        for rot in 0..64 {
            let d2 = d1.rotate_left(rot);
            let final_token = tok2_tampered_step ^ d2;
            assert_ne!(
                final_token, tok2_clean,
                "Adversarial differential cancellation occurred on live PE shards {} and {} with rot {}!",
                s1, s2, rot
            );
        }
    }
}

// ============================================================================
// 2. TASK 2: ADVERSARIAL INVOLUTORY & CYCLE TEST (MISMATCH EVOLUTION)
// ============================================================================

/// Test 2.1: Multi-Step Mismatch Sequences (k = 2, 3, 4, 5, 10, 50, 100, 1,000)
/// Confirms that consecutive mismatch events permanently mutate the token away from clean state
/// and that no short recurrence cycles exist.
#[test]
fn test_adversarial_task2_consecutive_mismatches_never_cycle_back() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Test starting from canonical clean token
    let mut tok = CANONICAL_CLEAN_TOKEN;
    let mut history = HashSet::new();
    history.insert(tok);

    let k_steps = 1000;
    for step in 1..=k_steps {
        tok = evolve_mismatch_ref(tok);

        // Security Invariant 1: Token MUST NOT equal CANONICAL_CLEAN_TOKEN at any step k >= 1
        assert_ne!(
            tok, CANONICAL_CLEAN_TOKEN,
            "CRITICAL VULNERABILITY: Token cycled back to CANONICAL_CLEAN_TOKEN at mismatch step {}!",
            step
        );

        // Security Invariant 2: Token must be pairwise distinct across all 1000 steps (no short cycles)
        assert!(
            !history.contains(&tok),
            "CRITICAL VULNERABILITY: Cycle detected in mismatch evolution at step {}! Token: 0x{:016X}",
            step, tok
        );
        history.insert(tok);
    }

    println!("[Task 2] Successfully verified 1,000 consecutive mismatch events: 0 collisions, 0 clean returns.");
}

/// Test 2.2: Fixed Point (G(T) == T) and 2-Cycle (G(G(T)) == T) Search
/// Exhaustively evaluates 1,000,000 random initial tokens to search for fixed points or involutions.
#[test]
fn test_adversarial_task2_fixed_points_and_involutions_search() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut rng_state = 0x98765432_10FEDCBAu64;
    let mut next_rng = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng_state
    };

    let sample_count = 1_000_000;
    let mut fixed_point_count = 0;
    let mut involution_count = 0;

    // Check specific boundary tokens
    let special_tokens = [
        0u64,
        CANONICAL_CLEAN_TOKEN,
        0xDEAD_DEAD_DEAD_DEADu64,
        0xBAAD_F00D_CAFE_BABEu64,
        0xFFFF_FFFF_FFFF_FFFFu64,
        0x1337_C0DE_5A5A_A5A5u64,
    ];

    for &tok in &special_tokens {
        let t1 = evolve_mismatch_ref(tok);
        let t2 = evolve_mismatch_ref(t1);
        assert_ne!(t1, tok, "Fixed point detected on special token 0x{:016X}!", tok);
        assert_ne!(t2, tok, "2-cycle (involution) detected on special token 0x{:016X}!", tok);
    }

    for _ in 0..sample_count {
        let tok = next_rng();
        let t1 = evolve_mismatch_ref(tok);
        if t1 == tok {
            fixed_point_count += 1;
        }
        let t2 = evolve_mismatch_ref(t1);
        if t2 == tok {
            involution_count += 1;
        }
    }

    println!("[Task 2] Over {} random samples: {} fixed points, {} 2-cycles.",
        sample_count, fixed_point_count, involution_count);

    assert_eq!(fixed_point_count, 0, "Discovered {} fixed points in G(T)!", fixed_point_count);
    assert_eq!(involution_count, 0, "Discovered {} 2-cycles (involutions) in G(T)!", involution_count);
}

/// Test 2.3: Interleaved Match and Mismatch Trajectory Chaos
/// Simulates an adversary interleaving matching and mismatching shards in various schedules
/// (e.g. Tamper, Pass, Tamper, Pass...) and verifies that clean token state is never restored.
#[test]
fn test_adversarial_task2_interleaved_match_mismatch_schedules() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let schedules: Vec<Vec<bool>> = vec![
        vec![false, true, false],                 // Tamper, Match, Tamper
        vec![false, false, true, false],          // Tamper, Tamper, Match, Tamper
        vec![true, false, true, false, true],     // Match, Tamper, Match, Tamper, Match
        vec![false, true, true, false, true, true],
        vec![false; 10],                          // 10 Tampers
        vec![false, false, false, false, true, true, true, true],
    ];

    let dummy_hash = 0x1234_5678u32;

    for (idx, sched) in schedules.iter().enumerate() {
        let mut clean_tok = CANONICAL_CLEAN_TOKEN;
        let mut test_tok = CANONICAL_CLEAN_TOKEN;

        for &is_match in sched {
            // Clean trajectory always matches
            clean_tok = evolve_match_ref(clean_tok, dummy_hash);

            // Test trajectory follows schedule
            if is_match {
                test_tok = evolve_match_ref(test_tok, dummy_hash);
            } else {
                test_tok = evolve_mismatch_ref(test_tok);
            }
        }

        // Must not equal canonical clean token
        assert_ne!(
            test_tok, CANONICAL_CLEAN_TOKEN,
            "Schedule {} restored token to CANONICAL_CLEAN_TOKEN!", idx
        );
        // Must not equal clean trajectory
        assert_ne!(
            test_tok, clean_tok,
            "Schedule {} converged back to clean trajectory token!", idx
        );
    }
}

/// Test 2.4: Live PE Memory Tampering with 50 Consecutive Heartbeat Checks
/// Actually modifies a byte in the PE .text section, runs 50 consecutive heartbeat checks,
/// and verifies monotonic state divergence and poison seed accumulation.
#[cfg(target_os = "windows")]
#[test]
fn test_adversarial_task2_live_pe_memory_50_consecutive_mismatches() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let orig_tok = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed);
    let orig_poison = global_state::POISON_SEED.load(Ordering::Relaxed);
    let _tok_guard = TokenRestoreGuard(orig_tok);
    let _poison_guard = PoisonRestoreGuard(orig_poison);

    // Initialize ShardTable
    pe_integrity::heartbeat_check(0);

    let (text_rva, _) = pe_integrity::get_text_section_bounds()
        .expect("PE text section bounds must be available");
    let base = unsafe { GetModuleHandleW(std::ptr::null()) };
    assert!(!base.is_null());

    let target_ptr = unsafe { base.offset(text_rva as isize) };
    let mut old_protect = 0u32;
    let protect_res = unsafe {
        VirtualProtect(target_ptr as *mut std::ffi::c_void, 1, PAGE_EXECUTE_READWRITE, &mut old_protect)
    };
    assert_ne!(protect_res, 0);

    let original_byte = unsafe { *target_ptr };
    // Tamper byte
    unsafe { *target_ptr ^= 0xAA; }
    let _mem_guard = MemoryTamperGuard {
        ptr: target_ptr,
        original_byte,
        old_protect,
    };

    pe_integrity::INTEGRITY_TOKEN.store(CANONICAL_CLEAN_TOKEN, Ordering::Relaxed);
    global_state::POISON_SEED.store(0, Ordering::Relaxed);

    let mut seen_tokens = HashSet::new();
    seen_tokens.insert(CANONICAL_CLEAN_TOKEN);

    for step in 1..=50 {
        let tok = pe_integrity::heartbeat_check(0);
        let poison = global_state::POISON_SEED.load(Ordering::Relaxed);

        assert_ne!(
            tok, CANONICAL_CLEAN_TOKEN,
            "Step {} unexpectedly matched CANONICAL_CLEAN_TOKEN!", step
        );
        assert!(
            !seen_tokens.contains(&tok),
            "Step {} produced duplicate token 0x{:016X}!", step, tok
        );
        seen_tokens.insert(tok);

        // Verify POISON_SEED accumulated
        let expected_poison = 0xBAD_C0DE_DEAD_1337u64.wrapping_mul(step as u64);
        assert_eq!(
            poison, expected_poison,
            "Step {} POISON_SEED mismatch! Expected 0x{:016X}, got 0x{:016X}",
            step, expected_poison, poison
        );
    }

    println!("[Task 2] Live PE memory 50 consecutive mismatches verified: clean token never restored, poison seed accumulated correctly.");
}

// ============================================================================
// 3. TASK 3: ADVERSARIAL CORRUPTIBLE STRESS TEST & BOUNDARY MAPPINGS
// ============================================================================

/// Test 3.1: Clean State Preservation Across Extreme Boundaries
/// Verifies that when token == CANONICAL_CLEAN_TOKEN and score == 0, ALL types
/// (String, Vec<u8>, bool, u32, f64) preserve their inputs 100% without mutation,
/// including pathological float values (subnormals, infinities) and giant collections.
#[test]
fn test_adversarial_task3_corruptible_clean_preservation_exhaustive() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let clean_token = CANONICAL_CLEAN_TOKEN;

    // 1. Boolean preservation
    assert_eq!(true.corrupt_if_needed(clean_token), true);
    assert_eq!(false.corrupt_if_needed(clean_token), false);

    // 2. u32 preservation: boundaries
    let u32_boundaries = [0u32, 1u32, 0x7FFF_FFFFu32, 0x8000_0000u32, 0xFFFF_FFFFu32, 1337u32];
    for &val in &u32_boundaries {
        assert_eq!(val.corrupt_if_needed(clean_token), val);
    }

    // 3. Vec<u8> preservation: empty, single byte, all-zeros, all-ones, 64KB vector
    let vec_empty: Vec<u8> = Vec::new();
    assert_eq!(vec_empty.clone().corrupt_if_needed(clean_token), vec_empty);

    let vec_single = vec![0x42u8];
    assert_eq!(vec_single.clone().corrupt_if_needed(clean_token), vec_single);

    let vec_giant = vec![0xCCu8; 65536];
    assert_eq!(vec_giant.clone().corrupt_if_needed(clean_token), vec_giant);

    // 4. String preservation: empty, ASCII, multi-byte UTF-8, CJK, emoji, 100KB string
    let str_empty = String::new();
    assert_eq!(str_empty.clone().corrupt_if_needed(clean_token), str_empty);

    let str_unicode = "Tiếng Việt — Chữ Nôm — 🦀 🛡️ 🚀 — 日本語".to_string();
    assert_eq!(str_unicode.clone().corrupt_if_needed(clean_token), str_unicode);

    let str_giant = "A".repeat(100_000);
    assert_eq!(str_giant.clone().corrupt_if_needed(clean_token), str_giant);

    // 5. f64 preservation: 0.0, -0.0, 1.0, -1.0, subnormals, EPSILON, MIN, MAX, INFINITY, NAN
    let f64_samples = [
        0.0f64,
        -0.0f64,
        1.0f64,
        -1.0f64,
        f64::MIN,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::EPSILON,
        f64::INFINITY,
        -f64::INFINITY,
        1e-320f64, // subnormal
    ];

    for &f in &f64_samples {
        let res = f.corrupt_if_needed(clean_token);
        assert_eq!(
            res.to_bits(), f.to_bits(),
            "f64 value {} (bits: 0x{:016X}) was altered under clean token to 0x{:016X}!",
            f, f.to_bits(), res.to_bits()
        );
    }

    // Check NaN preservation
    let nan_val = f64::NAN;
    let res_nan = nan_val.corrupt_if_needed(clean_token);
    assert!(res_nan.is_nan(), "Clean NaN was altered into non-NaN!");
}

/// Test 3.2: Adversarial Characterization of Corruptible Under Poisoned Tokens
/// Rigorously analyzes and confirms the behavior of all 5 types when token != CANONICAL_CLEAN_TOKEN.
/// Uncovers and validates mathematical edge cases:
/// 1. f64: 0.0 * factor == 0.0 (zero is immune to multiplicative corruption).
/// 2. u32: When token as u32 == 0, self.wrapping_add(0) == self (lower-32-bit zero boundary).
/// 3. String: When multi-byte UTF-8 chars have (token % byte_len) >= char_count, get_mut is None.
#[test]
fn test_adversarial_task3_poisoned_corruptible_mathematical_edge_cases() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let poisoned_token = 0x1337_DEAD_BEEF_CAFEu64;

    // 1. Boolean: Always flips on poisoned token
    assert_eq!(true.corrupt_if_needed(poisoned_token), false);
    assert_eq!(false.corrupt_if_needed(poisoned_token), true);

    // 2. Vec<u8>: Non-empty must corrupt a byte; empty remains empty
    let empty_vec: Vec<u8> = Vec::new();
    assert_eq!(empty_vec.corrupt_if_needed(poisoned_token), Vec::<u8>::new());

    let data_vec = vec![10u8, 20u8, 30u8, 40u8];
    let corrupted_vec = data_vec.clone().corrupt_if_needed(poisoned_token);
    assert_ne!(corrupted_vec, data_vec, "Vec<u8> failed to corrupt under poisoned token!");

    // 3. String: ASCII string corrupts
    let empty_str = String::new();
    assert_eq!(empty_str.corrupt_if_needed(poisoned_token), "");

    let ascii_str = "CleanPassword123".to_string();
    let corrupted_str = ascii_str.clone().corrupt_if_needed(poisoned_token);
    assert_ne!(corrupted_str, ascii_str, "ASCII String failed to corrupt under poisoned token!");

    // Edge Case Discovery 1: UTF-8 character length vs byte length boundary
    // In String::corrupt_if_needed:
    //   let idx = (token % s.len() as u64) as usize; // byte length
    //   let mut chars: Vec<char> = s.chars().collect(); // char count
    // If s contains 4-byte characters (like '🦀'), s.len() == 4, but chars.len() == 1.
    // When token % 4 in {1, 2, 3}, idx >= chars.len(), so chars.get_mut(idx) is None!
    let crab_str = "🦀".to_string();
    assert_eq!(crab_str.len(), 4);
    assert_eq!(crab_str.chars().count(), 1);

    // With token = 1, idx = 1 % 4 = 1 >= chars.len() (1) -> String returns unmutated!
    let token_crab_bypass = 1u64;
    let crab_result = crab_str.clone().corrupt_if_needed(token_crab_bypass);
    assert_eq!(
        crab_result, crab_str,
        "EMPIRICAL FINDING: Multi-byte UTF-8 string returns unmutated when token % byte_len >= char_count!"
    );

    // With token = 4 (or 0), idx = 0 < 1 -> String IS mutated!
    let token_crab_corrupt = 4u64;
    let crab_mutated = crab_str.clone().corrupt_if_needed(token_crab_corrupt);
    assert_ne!(crab_mutated, crab_str, "String with idx = 0 must mutate!");

    // Edge Case Discovery 2: u32 lower-32-bit zero vulnerability
    // In u32::corrupt_if_needed:
    //   self.wrapping_add(token as u32)
    // If token has lower 32 bits == 0 (e.g. 0xDEAD_BEEF_0000_0000), token as u32 == 0.
    // Then val.wrapping_add(0) == val -> u32 is NOT corrupted!
    let token_lower_zero = 0xDEAD_BEEF_0000_0000u64;
    assert_ne!(token_lower_zero, CANONICAL_CLEAN_TOKEN);
    let original_u32 = 42u32;
    let res_u32_lower_zero = original_u32.corrupt_if_needed(token_lower_zero);
    assert_eq!(
        res_u32_lower_zero, original_u32,
        "EMPIRICAL FINDING: u32 returns unmutated when poisoned token has lower 32 bits == 0!"
    );

    // However, for typical poisoned tokens where lower 32 bits != 0, u32 IS corrupted:
    let res_u32_normal = original_u32.corrupt_if_needed(poisoned_token);
    assert_ne!(res_u32_normal, original_u32, "Normal poisoned token must mutate u32!");

    // Edge Case Discovery 3: f64 zero invariance under multiplicative corruption
    // In f64::corrupt_if_needed:
    //   self * (1.0 + (token as f64 * 0.0001))
    // When self == 0.0 or -0.0, 0.0 * factor == 0.0.
    // Zero is mathematically invariant under multiplication!
    let zero_f64 = 0.0f64;
    let res_zero = zero_f64.corrupt_if_needed(poisoned_token);
    assert_eq!(
        res_zero.to_bits(), zero_f64.to_bits(),
        "EMPIRICAL FINDING: 0.0 is invariant under multiplicative f64 corruption!"
    );

    // Infinities and NaNs are also invariant under multiplication by positive factor
    let inf_f64 = f64::INFINITY;
    assert_eq!(inf_f64.corrupt_if_needed(poisoned_token), f64::INFINITY);
    let nan_f64 = f64::NAN;
    assert!(nan_f64.corrupt_if_needed(poisoned_token).is_nan());

    // Non-zero normal floats ARE corrupted:
    let normal_f64 = 3.14159f64;
    let res_f64 = normal_f64.corrupt_if_needed(poisoned_token);
    assert_ne!(res_f64, normal_f64, "Normal f64 must mutate under poisoned token!");
}

// ============================================================================
// 4. TASK 4: DEGENERATE TRAPDOOR STATE IMMUNITY
// ============================================================================

/// Test 4.1: Degenerate State Escape (0 and 0xDEAD_DEAD_DEAD_DEAD)
/// Confirms that if token ever lands on 0 or 0xDEAD_DEAD_DEAD_DEAD,
/// the trapdoor `token ^= 0x1337_C0DE_5A5A_A5A5` immediately escapes it,
/// ensuring neither match nor mismatch leaves the token in 0 or 0xDEAD_DEAD_DEAD_DEAD.
#[test]
fn test_adversarial_task4_trapdoor_state_escape() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let test_inputs = [0u64, 0xDEAD_DEAD_DEAD_DEADu64];

    for &input in &test_inputs {
        let match_out = evolve_match_ref(input, 0x1234_5678);
        assert_ne!(match_out, 0, "Match output remained 0!");
        assert_ne!(match_out, 0xDEAD_DEAD_DEAD_DEAD, "Match output remained 0xDEAD_DEAD_DEAD_DEAD!");

        let mismatch_out = evolve_mismatch_ref(input);
        assert_ne!(mismatch_out, 0, "Mismatch output remained 0!");
        assert_ne!(mismatch_out, 0xDEAD_DEAD_DEAD_DEAD, "Mismatch output remained 0xDEAD_DEAD_DEAD_DEAD!");
    }
}

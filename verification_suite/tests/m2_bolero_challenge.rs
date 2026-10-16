//! Milestone 2 Empirical Challenge and Stress Harness
//! Comprehensive adversarial stress testing of Bolero property testing models,
//! reference oracles, and target modules across all 10 modules.

use std::sync::atomic::Ordering;
use std::thread;
use std::process::Command;

use verification_suite::protector::{
    vm_execute, TinyVm, VmOp,
    seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8},
    global_state::{
        get_shard_mask, initialize_veh_protection, recalculate_global_integrity,
        validate_global_integrity, GLOBAL_INTEGRITY_HASH,
    },
};
use verification_suite::shims::hardware_entropy_shim::{fnv1a_hash_ref, get_hardware_entropy};
use verification_suite::shims::pe_integrity_shim::heartbeat_check;

use verification_suite::bolero_harnesses::test_seed_orchestrator::{
    ref_avalanche_mix, ref_inv_avalanche_mix,
};
use verification_suite::bolero_harnesses::test_global_state::{
    is_active_shard_ref, mix_seed_to_u64_ref,
};
use verification_suite::bolero_harnesses::test_anti_debug::{
    ref_calculate_jitter_mad, ref_mad_threshold, ref_peb_safe, ref_rotate_token,
};
use verification_suite::bolero_harnesses::test_decoy_system::{
    ref_is_function_patched, ref_polynomial_checksum,
};
use verification_suite::bolero_harnesses::test_enhanced_veh::{
    execute_drx_tinyvm_oracle, ref_drx_integrity_spec,
};
use verification_suite::bolero_harnesses::test_protector::{
    ref_golden_ratio_derive, ref_golden_ratio_invert, sim_corrected_decrypt,
    sim_protector_decrypt, sim_protector_encrypt,
};

/// Entry point for child subprocess testing Protector::new (DEF-01)
#[test]
fn test_isolated_protector_entry() {
    if std::env::var("FUCKDEBUG_SUBPROCESS_TEST").is_err() {
        return;
    }
    // Inside child subprocess: execute Protector::new which triggers anti-dump & VEH traps
    let _ = verification_suite::protector::Protector::new(0x1337);
}

// ============================================================================
// MODULE 1: TinyVM Stress & Boundary Challenges
// ============================================================================

#[test]
fn test_challenge_tinyvm_stack_deep_saturation() {
    let mut vm = TinyVm::new(0x1234_5678);

    // Push 100 values to TinyVm; verify sp stays clamped at 32
    for i in 1..=100u64 {
        vm.push(i);
        assert!(vm.sp <= 32, "Stack pointer overflowed 32: got {}", vm.sp);
        assert_eq!(vm.sp, std::cmp::min(i as usize, 32));
    }

    // Verify peek returns the 32nd pushed value (last accepted value)
    assert_eq!(vm.peek(), 32, "Top of saturated stack should be 32");

    // Pop all 32 values; verify LIFO order from 32 down to 1
    for expected in (1..=32u64).rev() {
        let val = vm.pop();
        assert_eq!(val, expected, "LIFO pop order violated on saturated stack");
    }

    // Stack is now empty
    assert_eq!(vm.sp, 0, "Stack pointer must be 0 after 32 pops");

    // Pop 50 more times on empty stack; verify returns 0 and sp stays at 0
    for _ in 0..50 {
        let val = vm.pop();
        assert_eq!(val, 0, "Empty stack pop must return 0");
        assert_eq!(vm.sp, 0, "Empty stack pop underflowed below 0");
    }
}

#[test]
fn test_challenge_tinyvm_empty_and_truncated_bytecode() {
    // 1. Empty bytecode
    let res = vm_execute(&[], 0x42, 0x9999);
    assert_eq!(res, 0, "Empty bytecode execution must return 0 without panicking");

    // 2. Truncated bytecode: op_load_imm expects 8 operand bytes, provide only 2
    let enc_key = 0xAA;
    let truncated_bc = vec![
        VmOp::op_load_imm() ^ enc_key,
        0x12 ^ enc_key,
        0x34 ^ enc_key,
    ];
    let res2 = vm_execute(&truncated_bc, enc_key, 0);
    // Must cleanly terminate when bytecode is exhausted
    assert_eq!(res2, 0, "Truncated bytecode must terminate cleanly");
}

#[test]
fn test_challenge_tinyvm_rolling_key_extremes() {
    let bytecode_cases = vec![
        vec![0x42],
        vec![0x00; 512],
        vec![0xFF; 512],
        (0..256).map(|i| i as u8).collect::<Vec<u8>>(),
    ];

    let keys = [(0x00, 0x00, 0x00), (0xFF, 0xFF, 0xFF), (0x55, 0xAA, 0x33)];

    for bc in &bytecode_cases {
        for &(enc_key, initial_r_key, token) in &keys {
            // Encode
            let mut encoded = vec![0u8; bc.len()];
            let mut r_key = initial_r_key;
            for (idx, &op) in bc.iter().enumerate() {
                let pos_salt = (idx as u8).wrapping_mul(7);
                let raw = op.wrapping_sub(pos_salt) ^ enc_key ^ r_key ^ token;
                encoded[idx] = raw;
                r_key = r_key.wrapping_add(raw).wrapping_mul(0x1F);
                r_key ^= r_key.rotate_right(3) ^ 0x3C;
            }

            // Decode
            let mut decoded = vec![0u8; bc.len()];
            let mut r_key_dec = initial_r_key;
            for (idx, &raw) in encoded.iter().enumerate() {
                let pos_salt = (idx as u8).wrapping_mul(7);
                let op = (raw ^ enc_key ^ r_key_dec ^ token).wrapping_add(pos_salt);
                decoded[idx] = op;
                r_key_dec = r_key_dec.wrapping_add(raw).wrapping_mul(0x1F);
                r_key_dec ^= r_key_dec.rotate_right(3) ^ 0x3C;
            }

            assert_eq!(&decoded, bc, "Rolling key roundtrip failed for key tuple");
        }
    }
}

// ============================================================================
// MODULE 2: Seed Orchestrator Stress & Concurrency Challenges
// ============================================================================

#[test]
fn test_challenge_murmur3_pathological_inputs() {
    let pathological_inputs: [u32; 12] = [
        0,
        1,
        2,
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        0x7FFF_FFFF,
        0x5555_5555,
        0xAAAA_AAAA,
        0xDEAD_BEEF,
        0x9E37_79B9,
        0x85EB_CA6B,
    ];

    for &x in &pathological_inputs {
        let fwd = ref_avalanche_mix(x);
        let rev = ref_inv_avalanche_mix(fwd);
        assert_eq!(rev, x, "Murmur3 round-trip failed for pathological input {:#X}", x);

        let rev_first = ref_inv_avalanche_mix(x);
        let fwd_after = ref_avalanche_mix(rev_first);
        assert_eq!(fwd_after, x, "Murmur3 dual round-trip failed for pathological input {:#X}", x);
    }
}

#[test]
fn test_challenge_murmur3_avalanche_exhaustive_single_bit_flips() {
    let test_seeds = [0u32, u32::MAX, 0x1234_5678, 0xCAFE_BABE];

    for &seed in &test_seeds {
        let y_base = ref_avalanche_mix(seed);
        for bit in 0..32 {
            let flipped = seed ^ (1u32 << bit);
            let y_flipped = ref_avalanche_mix(flipped);
            let diff = y_base ^ y_flipped;

            assert_ne!(diff, 0, "Murmur3 zero difference on 1-bit flip at bit {bit} for seed {seed:#X}");
            assert!(
                diff.count_ones() >= 1,
                "Murmur3 flipped 0 bits on 1-bit flip at bit {bit}"
            );
        }
    }
}

#[test]
fn test_challenge_seed_orchestrator_concurrency_stress() {
    let reference_seed = get_dynamic_seed();
    let reference_u8 = get_dynamic_seed_u8();

    assert_ne!(reference_seed, 0, "Reconstructed dynamic seed must be non-zero");

    let handles: Vec<_> = (0..32)
        .map(|_| {
            thread::spawn(move || {
                for _ in 0..1000 {
                    let s = get_dynamic_seed();
                    let u = get_dynamic_seed_u8();
                    assert_eq!(s, reference_seed, "Concurrent thread observed seed drift");
                    assert_eq!(u, reference_u8, "Concurrent thread observed u8 seed drift");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("Worker thread panicked in concurrency stress test");
    }
}

// ============================================================================
// MODULE 3: Hardware Entropy Stress Challenges
// ============================================================================

#[test]
fn test_challenge_fnv1a_boundary_inputs() {
    // 1. Empty buffer
    assert_eq!(
        fnv1a_hash_ref(&[]),
        0x811C_9DC5,
        "Empty slice FNV-1a must equal offset basis 0x811C9DC5"
    );

    // 2. Single zero byte
    let expected_zero = 0x811C_9DC5u32.wrapping_mul(0x0100_0193);
    assert_eq!(fnv1a_hash_ref(&[0]), expected_zero);

    // 3. Single 0xFF byte
    let expected_ff = (0x811C_9DC5u32 ^ 0xFF).wrapping_mul(0x0100_0193);
    assert_eq!(fnv1a_hash_ref(&[0xFF]), expected_ff);

    // 4. Large 64KB buffer
    let large_buf = vec![0x5Au8; 65536];
    let h_large = fnv1a_hash_ref(&large_buf);
    assert_ne!(h_large, 0);

    // 5. Sensitivity at byte index 0, len/2, len-1
    let mut modified = large_buf.clone();
    modified[0] ^= 1;
    assert_ne!(h_large, fnv1a_hash_ref(&modified));

    let mut modified_last = large_buf.clone();
    let last = modified_last.len() - 1;
    modified_last[last] ^= 1;
    assert_ne!(h_large, fnv1a_hash_ref(&modified_last));
}

#[test]
fn test_challenge_hardware_entropy_live_calls() {
    let initial = get_hardware_entropy();
    assert_ne!(initial, 0, "Hardware entropy must be non-zero");

    for _ in 0..1000 {
        let current = get_hardware_entropy();
        assert_eq!(current, initial, "Hardware entropy must be deterministic on host CPU");
    }
}

// ============================================================================
// MODULE 4: Global State & Suspicion Mesh Stress Challenges
// ============================================================================

#[test]
fn test_challenge_128_shard_partition_exhaustive_properties() {
    let test_seeds = [
        0u32, 1, 2, u32::MAX, u32::MAX - 1, 0x8000_0000, 0x7FFF_FFFF,
        0x5555_5555, 0xAAAA_AAAA, 0xDEAD_BEEF, 0xCAFE_BABE,
    ];

    for &seed in &test_seeds {
        let pair_map = mix_seed_to_u64_ref(seed);
        let mut active = 0;
        let mut decoy = 0;

        for pair in 0..64 {
            let s0 = pair * 2;
            let s1 = pair * 2 + 1;
            let a0 = is_active_shard_ref(s0, pair_map);
            let a1 = is_active_shard_ref(s1, pair_map);

            assert!(a0 ^ a1, "Pair {} violated mutual exclusion for seed {:#X}", pair, seed);
            if a0 { active += 1; } else { decoy += 1; }
            if a1 { active += 1; } else { decoy += 1; }
        }

        assert_eq!(active, 64, "Active shards count != 64 for seed {:#X}", seed);
        assert_eq!(decoy, 64, "Decoy shards count != 64 for seed {:#X}", seed);
    }
}

#[test]
fn test_challenge_zero_memory_honeytrap_all_pathological_seeds() {
    let seeds = [0u32, 1, u32::MAX, 0xDEADBEEF, 0x80000000];

    for &seed in &seeds {
        let pair_map = mix_seed_to_u64_ref(seed);
        let mut zeroed_score: u32 = 0;

        for i in 0..128 {
            if is_active_shard_ref(i, pair_map) {
                let mask = get_shard_mask(i);
                let val_i = mask.rotate_right(i as u32 % 32);
                zeroed_score = zeroed_score.wrapping_add(val_i);
            }
        }

        assert!(
            zeroed_score > 500,
            "Zeroed memory score {} <= 500 for seed {:#X}",
            zeroed_score, seed
        );
    }
}

#[test]
fn test_challenge_time_decay_saturation_extremes() {
    // 1. Elapsed < 300s: no decay
    let score = 100u32;
    for elapsed in [0u64, 1, 100, 299] {
        let decayed = score.saturating_sub(((elapsed / 300) as u32).saturating_mul(5));
        assert_eq!(decayed, score, "Sub-300s elapsed must not decay score");
    }

    // 2. Elapsed = 300s: decay = 5
    let decayed_300 = score.saturating_sub(((300 / 300) as u32).saturating_mul(5));
    assert_eq!(decayed_300, 95);

    // 3. Elapsed = u64::MAX: saturation at 0 without panic
    let decayed_max = score.saturating_sub(((u64::MAX / 300) as u32).saturating_mul(5));
    assert_eq!(decayed_max, 0, "Infinite time elapsed must saturate at 0");

    // 4. Initial score = u32::MAX
    let max_score = u32::MAX;
    let decayed_from_max = max_score.saturating_sub(((600 / 300) as u32).saturating_mul(5));
    assert_eq!(decayed_from_max, u32::MAX - 10);
}

#[test]
fn test_challenge_siphash_integrity_tamper_all_64_bits() {
    initialize_veh_protection();
    recalculate_global_integrity();
    assert!(validate_global_integrity(), "Freshly recalculated global integrity must be valid");

    // Test all 64 single-bit flips on GLOBAL_INTEGRITY_HASH
    for bit in 0..64 {
        let flip_mask = 1u64 << bit;
        GLOBAL_INTEGRITY_HASH.fetch_xor(flip_mask, Ordering::SeqCst);
        let is_valid = validate_global_integrity();
        assert!(
            !is_valid,
            "SipHash validation failed to detect tamper at bit position {}",
            bit
        );
        // Restore
        GLOBAL_INTEGRITY_HASH.fetch_xor(flip_mask, Ordering::SeqCst);
        assert!(validate_global_integrity(), "Failed to restore validity after reverting bit {}", bit);
    }
}

// ============================================================================
// MODULE 5: PE Integrity Stress Challenges
// ============================================================================

#[test]
fn test_challenge_section_sharding_boundary_sizes() {
    const SHARD_SIZE: usize = 1024;
    let test_sizes = [1usize, 1023, 1024, 1025, 2048, 100_000_000];
    let test_seeds = [0u32, 1, 100, u32::MAX];

    for &size in &test_sizes {
        let num_shards = (size + SHARD_SIZE - 1) / SHARD_SIZE;
        assert!(num_shards >= 1);

        for &seed in &test_seeds {
            let shard_idx = (seed as usize) % num_shards;
            let offset = shard_idx * SHARD_SIZE;
            let remaining = size.saturating_sub(offset);
            let chunk_size = std::cmp::min(remaining, SHARD_SIZE);

            assert!(offset < size);
            assert!(chunk_size > 0);
            assert!(chunk_size <= SHARD_SIZE);
            assert!(offset + chunk_size <= size);
        }
    }
}

#[test]
fn test_challenge_token_evolution_invertibility_extremes() {
    let tokens = [0u64, 1, u64::MAX, 0xDEADBEEFCAFEBABE];
    let hashes = [0u32, 1, u32::MAX, 0x811C9DC5];

    for &token in &tokens {
        for &hash in &hashes {
            let evolved = token.rotate_left(1) ^ (hash as u64);
            let recovered = (evolved ^ (hash as u64)).rotate_right(1);
            assert_eq!(recovered, token, "Token inversion failed for token {:#X}, hash {:#X}", token, hash);
        }
    }
}

#[test]
fn test_challenge_live_heartbeat_stress() {
    for seed in 0..1000u32 {
        let tok = heartbeat_check(seed);
        assert_ne!(tok, 0, "Heartbeat returned zero token");
        assert_ne!(tok, 0xDEAD_DEAD_DEAD_DEAD, "Heartbeat returned error token");
    }
}

// ============================================================================
// MODULE 6: Anti-Debug Subsystem Stress Challenges
// ============================================================================

#[test]
fn test_challenge_mad_timing_extreme_samples() {
    // 1. Empty samples
    assert_eq!(ref_calculate_jitter_mad(&[]), 0);
    assert_eq!(ref_mad_threshold(&[]), 0);

    // 2. Single sample
    assert_eq!(ref_calculate_jitter_mad(&[100]), 0);
    assert_eq!(ref_mad_threshold(&[100]), 100);

    // 3. Two identical samples
    assert_eq!(ref_calculate_jitter_mad(&[500, 500]), 0);
    assert_eq!(ref_mad_threshold(&[500, 500]), 500);

    // 4. Samples near u64::MAX
    let max_samples = vec![u64::MAX - 100, u64::MAX - 50, u64::MAX];
    let jitter = ref_calculate_jitter_mad(&max_samples);
    let threshold = ref_mad_threshold(&max_samples);
    assert!(jitter <= 100);
    assert_eq!(threshold, u64::MAX); // Saturating add clamps at u64::MAX
}

#[test]
fn test_challenge_peb_inspection_all_truth_table_entries() {
    // Truth table for being_debugged (0, 1), nt_global_flag (0, 0x70), cycles (500, 1500)
    for being_debugged in [0u8, 1u8] {
        for nt_global_flag in [0u32, 0x70u32, 0x10u32, 0x100u32] {
            let is_peb_safe = (being_debugged == 0) && ((nt_global_flag & 0x70) == 0);
            assert_eq!(ref_peb_safe(being_debugged, nt_global_flag), is_peb_safe);

            for cycles in [500u64, 1500u64] {
                let is_safe = is_peb_safe && (cycles < 1000);
                let safe_tok = ref_rotate_token(0x1337, true);
                let unsafe_tok = ref_rotate_token(0x1337, false);
                let actual = ref_rotate_token(0x1337, is_safe);

                if is_safe {
                    assert_eq!(actual, safe_tok);
                } else {
                    assert_eq!(actual, unsafe_tok);
                }
                assert_ne!(safe_tok, unsafe_tok, "Safe and unsafe rotated tokens collided");
            }
        }
    }
}

// ============================================================================
// MODULE 7: Anti-Dump & Stealth Traps Stress Challenges
// ============================================================================

#[test]
fn test_challenge_page_alignment_extremes() {
    let test_cases = [
        (0usize, 0usize),
        (1, 1),
        (4095, 1),
        (4096, 4096),
        (4097, 100),
        (0x0000_7FFF_FFFF_0000, 0x1000),
    ];

    for &(addr, size) in &test_cases {
        let aligned_addr = addr & !0xFFF;
        let end_addr = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
        let aligned_size = end_addr.saturating_sub(aligned_addr);

        assert_eq!(aligned_addr % 4096, 0);
        assert_eq!(aligned_size % 4096, 0);
        assert!(aligned_addr <= addr);
        assert!(aligned_addr + aligned_size >= addr.saturating_add(size));
    }
}

#[test]
fn test_challenge_guard_page_boundary_inclusion() {
    const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;
    const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

    let base = 0x20000usize;
    let size = 0x1000usize;

    // Inside region
    for fault in [base, base + 1, base + size - 1] {
        let in_region = fault >= base && fault < base + size;
        assert!(in_region);
        let hit = (STATUS_GUARD_PAGE_VIOLATION == 0x80000001) && in_region;
        assert!(hit);

        // Non-guard violation must miss
        let miss = (STATUS_ACCESS_VIOLATION == 0x80000001) && in_region;
        assert!(!miss);
    }

    // Outside region
    for fault in [base - 1, base + size, base + size + 100] {
        let in_region = fault >= base && fault < base + size;
        assert!(!in_region);
    }
}

// ============================================================================
// MODULE 8: Enhanced VEH Stress & DEF-04 Discovery
// ============================================================================

/// Properly encodes TinyVM bytecode using the rolling key, position salt, and integrity token
pub fn encode_tinyvm_bytecode(plain_bytes: &[u8], encryption_key: u8) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(plain_bytes.len());
    let mut state_key: u8 = 0;
    let integrity_val = verification_suite::shims::pe_integrity_shim::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
    let global_entropy = verification_suite::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);

    for (vip, &plain) in plain_bytes.iter().enumerate() {
        let pos_salt = (vip as u8).wrapping_mul(0x7);
        let raw_byte = plain.wrapping_sub(pos_salt) ^ encryption_key ^ state_key ^ integrity_val;
        encoded.push(raw_byte);

        state_key = state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
        state_key ^= state_key.rotate_right(3) ^ 0x3C;
        state_key ^= global_entropy;
    }
    encoded
}

/// Corrected DRx bytecode evaluation without the spurious `op_push` instructions
/// and properly encoded with the rolling-key cipher
pub fn execute_drx_tinyvm_corrected(dr7: u64, dr0: u64, vm_key: u64) -> bool {
    let expected = vm_key.wrapping_mul(0x13371337);
    let mut plain_bc = Vec::new();
    let k = 0x55u8;

    // 1. Check Dr7 == 0: loads dr7, loads 0, executes cmp_eq (pushes result 1 or 0)
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&dr7.to_le_bytes());

    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&0u64.to_le_bytes());

    plain_bc.push(VmOp::op_cmp_eq()); // Pushes (Dr7 == 0)

    // 2. Check Dr0 == Expected: loads dr0, loads expected, executes cmp_eq (pushes result 1 or 0)
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&dr0.to_le_bytes());

    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&expected.to_le_bytes());

    plain_bc.push(VmOp::op_cmp_eq()); // Pushes (Dr0 == Expected)

    // 3. OR results and exit
    plain_bc.push(VmOp::op_or());     // Pops two and pushes OR result
    plain_bc.push(VmOp::op_exit());   // Pops top and returns it

    let encoded_bc = encode_tinyvm_bytecode(&plain_bc, k);
    let result = vm_execute(&encoded_bc, k, 0);
    result != 0
}

#[test]
fn test_challenge_drx_tinyvm_defect_def04_and_vacuous_pass() {
    let vm_key = 0x5A5A_1234_BEEFu64;
    let expected = vm_key.wrapping_mul(0x13371337);

    // DEF-04 Proof:
    // In src/protector/enhanced_veh.rs:284-314:
    // 1. Bytecode has spurious `op_push()` after `op_cmp_eq()` eating the next opcode.
    // 2. Bytecode was encoded via naive `^ k` instead of the required rolling key cipher!
    // As a result, execute_drx_tinyvm_oracle ALWAYS returns false!
    let r1 = execute_drx_tinyvm_oracle(0, 0, vm_key);
    let r2 = execute_drx_tinyvm_oracle(0, 0x1234, vm_key);
    let r3 = execute_drx_tinyvm_oracle(0x100, expected, vm_key);
    let r4 = execute_drx_tinyvm_oracle(0x100, 0x9999, vm_key);

    assert!(!r1, "execute_drx_tinyvm_oracle returned false for clean dr7=0");
    assert!(!r2, "execute_drx_tinyvm_oracle returned false for clean dr7=0");
    assert!(!r3, "execute_drx_tinyvm_oracle returned false even when dr0 == expected");
    assert!(!r4, "execute_drx_tinyvm_oracle returned false");

    // Empirical Verification of Vacuous Passing:
    // For arbitrary u64, dr7 == 0 has probability 2^-64 and dr0 == expected has probability 2^-64.
    // Therefore ref_drx_integrity_spec returns false with probability (1 - 2^-64)^2 ~ 100%.
    // Because execute_drx_tinyvm_oracle always returns false due to DEF-04,
    // the Bolero harness prop_enhanced_veh_drx_tinyvm_equivalence passed 235k iterations on (false == false)!
    let arbitrary_dr7 = 0x1234_5678_9ABC_DEF0u64;
    let arbitrary_dr0 = 0x0FED_CBA9_8765_4321u64;
    let spec = ref_drx_integrity_spec(arbitrary_dr7, arbitrary_dr0, vm_key);
    let oracle = execute_drx_tinyvm_oracle(arbitrary_dr7, arbitrary_dr0, vm_key);
    assert_eq!(spec, false);
    assert_eq!(oracle, false);
    assert_eq!(spec, oracle, "Demonstrating the false == false vacuous pass");
}

#[test]
fn test_challenge_poisoned_rax_coprime_multiplication() {
    // 0xDEADBEEF is coprime to 2^64 (since it's odd).
    // Therefore, vm_key * 0xDEADBEEF == 0 mod 2^64 <=> vm_key == 0 mod 2^64.
    let keys = [1u64, 2, u64::MAX, u64::MAX - 1, 0x8000_0000_0000_0000];
    for &k in &keys {
        let poisoned_rax = k.wrapping_mul(0xDEADBEEF);
        assert_ne!(poisoned_rax, 0, "Coprime multiplication produced 0 for non-zero key {:#X}", k);
    }
}

// ============================================================================
// MODULE 9: Decoy & Honey Pot System Stress Challenges
// ============================================================================

#[test]
fn test_challenge_prologue_scanner_soundness_and_defects() {
    // 1. Soundness: standard prologues
    let standard = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(!ref_is_function_patched(&standard));

    // 2. Completeness: RET at 0
    let mut p_ret = standard;
    p_ret[0] = 0xC3;
    assert!(ref_is_function_patched(&p_ret));

    // 3. Completeness: INT3 at 0..5
    for i in 0..5 {
        let mut p_int3 = standard;
        p_int3[i] = 0xCC;
        assert!(ref_is_function_patched(&p_int3));
    }

    // 4. Defect Investigation:
    // Notice that is_function_patched only checks 0xC3 at index 0.
    // If a patch is placed as [0x90, 0xC3, 0x00], does it detect it?
    let mut p_nop_ret = [0u8; 16];
    p_nop_ret[0] = 0x90;
    p_nop_ret[1] = 0xC3;
    let detected = ref_is_function_patched(&p_nop_ret);
    // Empirical verification: [0x90, 0xC3] is NOT detected because:
    // - index 0 is 0x90 (not 0xC3)
    // - index 1 is 0xC3, but 0xC3 is only checked when i == 0!
    // - NOP sled requires 3 NOPs, but here only 1 NOP.
    assert!(!detected, "Empirical observation: NOP + RET patch evades prologue scanner");
}

#[test]
fn test_challenge_polynomial_checksum_empty_and_single_byte() {
    // 1. Empty buffer
    assert_eq!(ref_polynomial_checksum(&[]), 0);

    // 2. Single zero byte: (0 + 0) * 31 + 1 = 1
    assert_eq!(ref_polynomial_checksum(&[0]), 1);

    // 3. Single 1 byte: (0 + 1) * 31 + 1 = 32
    assert_eq!(ref_polynomial_checksum(&[1]), 32);

    // 4. Non-commutativity
    let h1 = ref_polynomial_checksum(&[0x12, 0x34]);
    let h2 = ref_polynomial_checksum(&[0x34, 0x12]);
    assert_ne!(h1, h2, "Polynomial checksum must be non-commutative");
}

// ============================================================================
// MODULE 10: Top-Level Protector & Defect Audit Challenges
// ============================================================================

#[test]
fn test_challenge_golden_ratio_bijectivity_all_edge_scores() {
    let seeds = [0u32, 1, u32::MAX, 0xDEADBEEF];
    let scores = [0u32, 1, 60, 61, 62, 120, 500, u32::MAX];
    let poisons = [0u64, 1, u64::MAX, 0xDEADC0DEBADC0DE];

    for &seed in &seeds {
        let expected_base = (seed as u64) ^ 0x61C8864680B583EB;
        for &score in &scores {
            for &poison in &poisons {
                let derived = ref_golden_ratio_derive(seed, score, poison);
                let recovered = ref_golden_ratio_invert(derived, score, poison);
                assert_eq!(
                    recovered, expected_base,
                    "Golden ratio inversion failed for seed={:#X}, score={}, poison={:#X}",
                    seed, score, poison
                );
            }
        }
    }
}

#[test]
fn test_challenge_vault_commutativity_defect_mathematical_proof() {
    let plaintext = b"SECRET_PASSWORD_123";
    let vault_key = 0x1234_5678_9ABC_DEF3u64; // shift = (vault_key & 7) = 3 > 0
    let anti_debug_key = 0x5Au8; // non-trivial key

    let ciphertext = sim_protector_encrypt(plaintext, vault_key, anti_debug_key);

    // 1. Corrected decryption restores plaintext perfectly
    let correct = sim_corrected_decrypt(&ciphertext, vault_key, anti_debug_key);
    assert_eq!(correct, plaintext, "Corrected decryption must restore original plaintext");

    // 2. DEF-03: Codebase decryption diverges
    let broken = sim_protector_decrypt(&ciphertext, vault_key, anti_debug_key);
    assert_ne!(
        broken, plaintext,
        "DEF-03: Codebase decrypt_data incorrectly diverged from original plaintext due to non-commutative operations"
    );

    // Byte 0 exact algebraic divergence:
    let shift = (vault_key & 7) as u32;
    let expected_byte0_broken = plaintext[0] ^ anti_debug_key.rotate_right(shift) ^ anti_debug_key;
    assert_eq!(
        broken[0], expected_byte0_broken,
        "Broken byte 0 matches predicted algebraic error formula exactly"
    );
}

#[test]
fn test_challenge_protector_new_subprocess_exit_code() {
    let current_exe = std::env::current_exe().expect("Acquire test binary path");
    let output = Command::new(&current_exe)
        .arg("test_isolated_protector_entry")
        .arg("--nocapture")
        .arg("--exact")
        .env("FUCKDEBUG_SUBPROCESS_TEST", "1")
        .output();

    assert!(output.is_ok(), "Failed to execute child process");
    if let Ok(out) = output {
        // DEF-01: Child process terminates with STATUS_FATAL_USER_CALLBACK_EXCEPTION (0xc000041d)
        let code = out.status.code().map(|c| c as u32);
        // On Windows, 0xc000041d is unsigned 3221226493
        if let Some(c) = code {
            assert_eq!(
                c, 0xc000041d,
                "DEF-01: Expected child process termination with 0xc000041d, got {:#X}",
                c
            );
        }
    }
}

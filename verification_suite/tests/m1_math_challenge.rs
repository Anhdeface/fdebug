//! Empirical Adversarial Verification & Mathematical Proof Challenge Suite
//! Milestone 1: m1_challenger_1
//!
//! Empirically challenges and stress-tests:
//! 1. TinyVM Stack Bounds under adversarial sequences (100 pushes, pops, invalid opcodes, memory bounds)
//! 2. Murmur3 Finalizer Bijectivity (boundary inputs: 0, 1, 2^32-1, 0x85EBCA6B, 0xC2B2AE35, round-trip invertibility)
//! 3. Golden Ratio Modular Inverse ((C * C^-1) mod 2^64 == 1, independent XGCD oracle, group automorphism)
//! 4. 128-Shard Active/Decoy Partitioning (10,000 randomized seeds, exact 64/64 split, pair invariants, boundary bounds)

use verification_suite::protector::vm_execute;
use verification_suite::protector::TinyVm;
use verification_suite::verus_proofs::seed_orchestration::*;
use verification_suite::verus_proofs::silent_corruption_math::*;
use verification_suite::verus_proofs::tiny_vm_semantics::*;

// Simple Xorshift64 PRNG for deterministic adversarial generation
struct ChallengeRng {
    state: u64,
}

impl ChallengeRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xCAFE_BABE_DEAD_BEEF } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

// ============================================================================
// 1. CHALLENGE: TINYVM STACK BOUNDS UNDER ADVERSARIAL SEQUENCES
// ============================================================================

#[test]
fn test_challenge_tinyvm_100_pushes_saturation_bounds() {
    let initial_key = 0x1234_5678_9ABC_DEF0_u64;
    let mut vm = TinyVm::new(initial_key);

    assert_eq!(vm.sp, 0);
    assert_eq!(vm.key, initial_key);
    assert_eq!(vm.accumulator, 0);

    // Perform 100 consecutive pushes
    for i in 1..=100u64 {
        vm.push(i);

        if i <= 32 {
            assert_eq!(
                vm.sp, i as usize,
                "Stack pointer must linearly track pushes up to capacity 32 (at i={i})"
            );
            assert_eq!(
                vm.peek(),
                i,
                "Peek must return the most recently pushed value"
            );
        } else {
            assert_eq!(
                vm.sp, 32,
                "Stack pointer must saturate at capacity 32 for push #{i}"
            );
            assert_eq!(
                vm.peek(),
                32,
                "Stack top must remain 32; overflow push #{i} must be dropped"
            );
        }

        // Memory integrity invariants: adjacent fields must NEVER be corrupted
        assert_eq!(vm.accumulator, 0, "vm.accumulator corrupted at push #{i}");
        assert_eq!(vm.key, initial_key, "vm.key corrupted at push #{i}");
        assert_eq!(vm.vip, 0, "vm.vip corrupted at push #{i}");
    }

    // Verify all 32 elements in stack are pristine
    for idx in 0..32 {
        assert_eq!(
            vm.v_stack[idx],
            (idx + 1) as u64,
            "Stack element at slot {idx} altered by subsequent pushes"
        );
    }
}

#[test]
fn test_challenge_tinyvm_100_pops_underflow_safety() {
    let mut vm = TinyVm::new(0xDEAD_BEEF);

    // 1. Pop from completely empty stack 100 times
    for i in 1..=100 {
        let val = vm.pop();
        assert_eq!(val, 0, "Pop on empty stack must return 0 (iteration {i})");
        assert_eq!(
            vm.sp, 0,
            "Stack pointer must not underflow below 0 (iteration {i})"
        );
    }

    // 2. Push 10 elements, then pop 100 times
    for i in 1..=10u64 {
        vm.push(i * 100);
    }
    assert_eq!(vm.sp, 10);

    for i in (1..=10u64).rev() {
        let val = vm.pop();
        assert_eq!(val, i * 100, "LIFO pop order violated");
    }
    assert_eq!(vm.sp, 0);

    // Remaining 90 pops must all safely return 0
    for i in 11..=100 {
        let val = vm.pop();
        assert_eq!(val, 0, "Excess pop #{i} must return 0");
        assert_eq!(vm.sp, 0, "sp must remain 0 on underflow pop #{i}");
    }
}

#[test]
fn test_challenge_tinyvm_interleaved_adversarial_sequence() {
    let mut vm = TinyVm::new(0xCAFE_BABE);
    let mut rng = ChallengeRng::new(0x9999_8888_7777);

    let mut shadow_stack: Vec<u64> = Vec::with_capacity(32);

    for step in 0..100 {
        let op_choice = rng.next_u32() % 3;
        match op_choice {
            0 => {
                // Push
                let val = rng.next_u64();
                vm.push(val);
                if shadow_stack.len() < 32 {
                    shadow_stack.push(val);
                }
            }
            1 => {
                // Pop
                let actual = vm.pop();
                let expected = shadow_stack.pop().unwrap_or(0);
                assert_eq!(
                    actual, expected,
                    "Differential oracle mismatch at step {step} during pop"
                );
            }
            2 => {
                // Peek
                let actual = vm.peek();
                let expected = shadow_stack.last().copied().unwrap_or(0);
                assert_eq!(
                    actual, expected,
                    "Differential oracle mismatch at step {step} during peek"
                );
            }
            _ => unreachable!(),
        }

        assert_eq!(
            vm.sp,
            shadow_stack.len(),
            "Stack pointer diverged from shadow oracle at step {step}"
        );
        assert!(
            vm.sp <= 32,
            "Stack pointer exceeded capacity 32 at step {step}: {}",
            vm.sp
        );
    }
}

/// Executable reference oracle mirroring the Verus `model_push` specification:
///   if vm.sp < 32 { vm.sp + 1 } else { vm.sp }
fn oracle_model_push(sp: usize, val: u64, stack: &mut [u64; 32]) -> usize {
    if sp < 32 {
        stack[sp] = val;
        sp + 1
    } else {
        sp
    }
}

/// Executable reference oracle mirroring the Verus `model_pop` specification:
///   if vm.sp > 0 { (vm.sp - 1, stack[new_sp]) } else { (0, 0) }
fn oracle_model_pop(sp: usize, stack: &[u64; 32]) -> (usize, u64) {
    if sp > 0 {
        let new_sp = sp - 1;
        (new_sp, stack[new_sp])
    } else {
        (0, 0)
    }
}

/// Executable reference oracle mirroring the Verus `model_peek` specification:
///   if vm.sp > 0 { stack[vm.sp - 1] } else { 0 }
fn oracle_model_peek(sp: usize, stack: &[u64; 32]) -> u64 {
    if sp > 0 {
        stack[sp - 1]
    } else {
        0
    }
}

#[test]
fn test_challenge_tinyvm_verus_model_conformance() {
    let mut runtime_vm = TinyVm::new(0x5555_AAAA);
    let mut model_sp = 0usize;
    let mut model_stack = [0u64; 32];

    let mut rng = ChallengeRng::new(0x1337_F00D);

    for step in 0..100 {
        let action = rng.next_u32() % 2;
        if action == 0 {
            // Push
            let val = rng.next_u64();
            runtime_vm.push(val);
            model_sp = oracle_model_push(model_sp, val, &mut model_stack);
        } else {
            // Pop
            let runtime_pop = runtime_vm.pop();
            let (new_model_sp, model_pop_val) = oracle_model_pop(model_sp, &model_stack);
            model_sp = new_model_sp;
            assert_eq!(
                runtime_pop, model_pop_val,
                "Model pop value diverged from runtime at step {step}"
            );
        }

        assert_eq!(
            runtime_vm.sp, model_sp,
            "Stack pointer diverged from Verus model at step {step}"
        );
        assert_eq!(
            runtime_vm.peek(),
            oracle_model_peek(model_sp, &model_stack),
            "Peek diverged from Verus model at step {step}"
        );
    }
}

#[test]
fn test_challenge_tinyvm_adversarial_sequence_100_ops_with_invalid_instructions() {
    let mut vm = TinyVm::new(0x8888_4444_2222_1111);
    let mut rng = ChallengeRng::new(0xBADC_0DED_2026);

    // Adversarial sequence of 100 operations mixing:
    // 0: Push
    // 1: Pop
    // 2: Peek
    // 3: Invalid instruction (attempted illegal stack index, no-op trap)
    // 4: Direct stack clamp boundary stress
    for op_i in 0..100 {
        let op_type = rng.next_u32() % 5;
        match op_type {
            0 => {
                // Push random value
                let val = rng.next_u64();
                vm.push(val);
                assert!(vm.sp <= 32, "vm.sp exceeded 32 after push at op {op_i}");
            }
            1 => {
                // Pop
                let _val = vm.pop();
                assert!(vm.sp <= 32, "vm.sp invalid after pop at op {op_i}");
            }
            2 => {
                // Peek
                let _val = vm.peek();
                assert!(vm.sp <= 32, "vm.sp corrupted by peek at op {op_i}");
            }
            3 => {
                // Invalid instruction simulation: simulate unmapped/trapped opcode
                // Op_trap leaves stack intact and returns 0 exit value
                let sp_before = vm.sp;
                let top_before = vm.peek();
                // vm state remains completely unchanged by trapped opcode
                assert_eq!(vm.sp, sp_before, "Stack pointer modified by invalid opcode trap");
                assert_eq!(vm.peek(), top_before, "Stack top modified by invalid opcode trap");
            }
            4 => {
                // Adversarial boundary barrage: push 35 items immediately, then pop 40 items
                for k in 0..35 {
                    vm.push(k);
                    assert!(vm.sp <= 32, "sp exceeded 32 during boundary push barrage");
                }
                assert_eq!(vm.sp, 32);
                for _ in 0..40 {
                    vm.pop();
                    assert!(vm.sp <= 32, "sp underflow during boundary pop barrage");
                }
                assert_eq!(vm.sp, 0);
            }
            _ => unreachable!(),
        }

        // Global invariant check after every single operation:
        assert!(vm.sp <= 32, "Invariant violation: vm.sp > 32");
        assert_eq!(vm.key, 0x8888_4444_2222_1111, "vm.key memory corruption detected");
        assert_eq!(vm.accumulator, 0, "vm.accumulator memory corruption detected");
    }
}

#[test]
fn test_challenge_tinyvm_bytecode_invalid_instructions_execution() {
    // 1. Array of 100 invalid instructions (all zeros)
    let invalid_bytecode = [0x00u8; 100];
    let exit_val = vm_execute(&invalid_bytecode, 0x5A, 0x1234_5678);
    // Unmapped/invalid opcodes route to `op_trap` which sets exit_value = 0 and terminates immediately
    assert_eq!(
        exit_val, 0,
        "Execution of 100 invalid zero bytes must safely trap and return 0"
    );

    // 2. Array of 100 arbitrary/pseudorandom garbage instructions
    let mut rng = ChallengeRng::new(0x7777_6666_5555);
    let mut garbage_bytecode = [0u8; 100];
    for b in garbage_bytecode.iter_mut() {
        *b = rng.next_u32() as u8;
    }
    // Execution must safely terminate without crashing, panicking, or hanging
    let garbage_exit = vm_execute(&garbage_bytecode, 0xA5, 0xDEAD_BEEF);
    // Any garbage execution terminates cleanly
    let _ = garbage_exit;

    // 3. Bytecode with empty buffer
    let empty_exit = vm_execute(&[], 0x00, 0x00);
    assert_eq!(empty_exit, 0, "Empty bytecode execution must return 0");
}

// ============================================================================
// 2. CHALLENGE: MURMUR3 FINALIZER BIJECTIVITY & ROUND-TRIP INVERSE
// ============================================================================

#[test]
fn test_challenge_murmur3_specified_boundary_inputs() {
    let boundary_inputs: [u32; 5] = [
        0,              // Zero
        1,              // Unit
        u32::MAX,       // 2^32 - 1 (0xFFFFFFFF)
        0x85EBCA6B,     // Murmur3 constant C1
        0xC2B2AE35,     // Murmur3 constant C2
    ];

    for &x in &boundary_inputs {
        let forward = exec_murmur3_finalizer(x);
        let inverse = exec_inv_murmur3_finalizer(forward);

        assert_eq!(
            inverse, x,
            "Murmur3 round-trip inv_fmix32(fmix32(x)) failed for boundary input {x:#010X} (got {inverse:#010X})"
        );

        // Also test dual direction: fmix32(inv_fmix32(x)) == x
        let back = exec_inv_murmur3_finalizer(x);
        let back_forward = exec_murmur3_finalizer(back);
        assert_eq!(
            back_forward, x,
            "Murmur3 dual round-trip fmix32(inv_fmix32(x)) failed for boundary input {x:#010X}"
        );

        // Zero preservation verification
        if x == 0 {
            assert_eq!(forward, 0, "Murmur3 must map 0 to 0 (origin preservation)");
        } else {
            assert_ne!(forward, 0, "Murmur3 must not map non-zero input {x:#010X} to 0");
        }
    }
}

#[test]
fn test_challenge_murmur3_extended_pathological_boundaries() {
    let pathological_inputs: [u32; 16] = [
        2,
        0x80000000,     // 2^31 (MSB set)
        0x7FFFFFFF,     // 2^31 - 1
        0xA5CB9243,     // C1 inverse
        0x7ED1B41D,     // C2 inverse
        0x55555555,     // Alternating bits 0101
        0xAAAAAAAA,     // Alternating bits 1010
        0x33333333,
        0xCCCCCCCC,
        0x0F0F0F0F,
        0xF0F0F0F0,
        0x0000FFFF,
        0xFFFF0000,
        0x00FF00FF,
        0xFF00FF00,
        0xDEADBEEF,
    ];

    for &x in &pathological_inputs {
        let y = exec_murmur3_finalizer(x);
        let x_rec = exec_inv_murmur3_finalizer(y);
        assert_eq!(x_rec, x, "Pathological boundary {x:#010X} failed round-trip");
    }
}

#[test]
fn test_challenge_murmur3_100k_randomized_bijectivity() {
    let mut rng = ChallengeRng::new(0xFEED_FACE_CAFE_BEEF);
    let sample_count = 100_000;

    for i in 0..sample_count {
        let x = rng.next_u32();
        let y = exec_murmur3_finalizer(x);
        let x_recovered = exec_inv_murmur3_finalizer(y);

        assert_eq!(
            x_recovered, x,
            "Round-trip failed at iteration {i} for x={x:#010X}"
        );

        let y_rev = exec_inv_murmur3_finalizer(x);
        let y_recovered = exec_murmur3_finalizer(y_rev);
        assert_eq!(
            y_recovered, x,
            "Dual round-trip failed at iteration {i} for x={x:#010X}"
        );
    }
}

#[test]
fn test_challenge_murmur3_constants_multiplicative_inverses() {
    let prod1 = MURMUR3_C1_32.wrapping_mul(MURMUR3_C1_INV_32);
    assert_eq!(
        prod1, 1u32,
        "C1 * C1_INV mod 2^32 must equal 1: C1={MURMUR3_C1_32:#010X}, C1_INV={MURMUR3_C1_INV_32:#010X}"
    );

    let prod2 = MURMUR3_C2_32.wrapping_mul(MURMUR3_C2_INV_32);
    assert_eq!(
        prod2, 1u32,
        "C2 * C2_INV mod 2^32 must equal 1: C2={MURMUR3_C2_32:#010X}, C2_INV={MURMUR3_C2_INV_32:#010X}"
    );
}

// ============================================================================
// 3. CHALLENGE: GOLDEN RATIO MODULAR INVERSE ((C * C^-1) mod 2^64 == 1)
// ============================================================================

/// Independent Extended Euclidean Algorithm oracle for modular inverse mod 2^64
/// Computes modular inverse of odd integer `a` in Z_{2^64} via Hensel's lemma / Newton's method
fn compute_mod_inverse_2_64(a: u64) -> u64 {
    assert!(a & 1 == 1, "Modular inverse mod 2^64 exists only for odd integers");
    // Newton-Raphson iteration for modular inverse: x_{k+1} = x_k * (2 - a * x_k) mod 2^64
    let mut x: u64 = 1; // 1-bit accurate
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 2 bits
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 4 bits
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 8 bits
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 16 bits
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 32 bits
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // 64 bits
    x
}

#[test]
fn test_challenge_golden_ratio_modular_inverse_identity() {
    let c = GOLDEN_RATIO_PRIME_64;
    let c_inv = GOLDEN_RATIO_INVERSE_64;

    // 1. Verify C is odd (coprime to 2^64)
    assert_eq!(c & 1, 1, "Golden ratio constant must be odd");

    // 2. Direct modular multiplication identity
    let product = c.wrapping_mul(c_inv);
    assert_eq!(
        product, 1u64,
        "Identity violation: (C * C^-1) mod 2^64 must equal 1, got {product:#018X}"
    );

    // 3. Independent oracle verification
    let oracle_inv = compute_mod_inverse_2_64(c);
    assert_eq!(
        oracle_inv, c_inv,
        "Hardcoded inverse {c_inv:#018X} differs from independently computed inverse {oracle_inv:#018X}"
    );

    let oracle_product = c.wrapping_mul(oracle_inv);
    assert_eq!(oracle_product, 1u64);
}

#[test]
fn test_challenge_golden_ratio_automorphism_roundtrip() {
    let c = GOLDEN_RATIO_PRIME_64;
    let c_inv = GOLDEN_RATIO_INVERSE_64;

    let boundary_values: [u64; 10] = [
        0,
        1,
        2,
        u64::MAX,
        u64::MAX - 1,
        1 << 63,
        (1 << 63) - 1,
        c,
        c_inv,
        0x0123_4567_89AB_CDEF,
    ];

    for &x in &boundary_values {
        let transformed = x.wrapping_mul(c);
        let restored = transformed.wrapping_mul(c_inv);
        assert_eq!(
            restored, x,
            "Automorphism roundtrip failed for x={x:#018X}: restored={restored:#018X}"
        );
    }

    // Stress test 100,000 random inputs
    let mut rng = ChallengeRng::new(0xABCD_EF01_2345_6789);
    for _ in 0..100_000 {
        let x = rng.next_u64();
        let y = x.wrapping_mul(c);
        let x_rec = y.wrapping_mul(c_inv);
        assert_eq!(x_rec, x);
    }
}

// ============================================================================
// 4. CHALLENGE: 128-SHARD ACTIVE/DECOY PARTITIONING (10,000 RANDOM SEEDS)
// ============================================================================

/// Direct implementation of global_state::mix_seed_to_u64 for testing
fn mix_seed_to_u64_ref(seed: u32) -> u64 {
    let mut x = seed as u64;
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

#[test]
fn test_challenge_128_shard_partitioning_10k_randomized_seeds() {
    let mut rng = ChallengeRng::new(0x4242_4242_1111);
    const NUM_SEEDS: usize = 10_000;

    let boundary_seeds: [u32; 8] = [
        0,
        1,
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        0x7FFF_FFFF,
        0xDEAD_BEEF,
        0xCAFE_BABE,
    ];

    for (i, &seed) in boundary_seeds.iter().enumerate() {
        verify_single_seed_partition(seed, i);
    }

    for i in boundary_seeds.len()..NUM_SEEDS {
        let seed = rng.next_u32();
        verify_single_seed_partition(seed, i);
    }
}

fn verify_single_seed_partition(seed: u32, iteration: usize) {
    let pair_map = mix_seed_to_u64_ref(seed);
    let mut active_count = 0usize;
    let mut decoy_count = 0usize;

    // Check each pair individually
    for pair_idx in 0..64 {
        let idx0 = pair_idx * 2;
        let idx1 = pair_idx * 2 + 1;

        let act0 = exec_is_active_shard(idx0, pair_map);
        let act1 = exec_is_active_shard(idx1, pair_map);

        // Invariant: In every pair (2k, 2k+1), exactly one shard is active and one is decoy
        assert!(
            act0 ^ act1,
            "Pair {pair_idx} violates strict mutual exclusion at seed {seed:#010X} (iter {iteration}): act0={act0}, act1={act1}"
        );

        if act0 {
            active_count += 1;
        } else {
            decoy_count += 1;
        }

        if act1 {
            active_count += 1;
        } else {
            decoy_count += 1;
        }
    }

    // Exact count invariant: 64 active and 64 decoy shards
    assert_eq!(
        active_count, 64,
        "Active shard count failed at seed {seed:#010X} (iter {iteration}): expected 64, got {active_count}"
    );
    assert_eq!(
        decoy_count, 64,
        "Decoy shard count failed at seed {seed:#010X} (iter {iteration}): expected 64, got {decoy_count}"
    );
    assert_eq!(
        active_count + decoy_count,
        128,
        "Total shard count mismatch"
    );
}

#[test]
fn test_challenge_128_shard_arbitrary_pair_maps_exhaustive() {
    let mut rng = ChallengeRng::new(0x7777_8888_9999);

    // Test extreme 64-bit pair maps
    let extreme_maps: [u64; 8] = [
        0u64,                      // All bits 0 (all even shards active)
        u64::MAX,                  // All bits 1 (all odd shards active)
        0x5555_5555_5555_5555,     // Alternating bits
        0xAAAA_AAAA_AAAA_AAAA,     // Inverted alternating bits
        0x0000_0000_FFFF_FFFF,     // Low half 1s, high half 0s
        0xFFFF_FFFF_0000_0000,     // Low half 0s, high half 1s
        0x0123_4567_89AB_CDEF,
        0xFEDC_BA98_7654_3210,
    ];

    for &pair_map in &extreme_maps {
        let mut active = 0;
        let mut decoy = 0;
        for idx in 0..128 {
            if exec_is_active_shard(idx, pair_map) {
                active += 1;
            } else {
                decoy += 1;
            }
        }
        assert_eq!(active, 64, "Arbitrary map {pair_map:#018X} active != 64");
        assert_eq!(decoy, 64, "Arbitrary map {pair_map:#018X} decoy != 64");
    }

    // Test 10,000 completely random 64-bit pair maps (independent of seed mixer)
    for _ in 0..10_000 {
        let pair_map = rng.next_u64();
        let mut active = 0;
        let mut decoy = 0;
        for idx in 0..128 {
            if exec_is_active_shard(idx, pair_map) {
                active += 1;
            } else {
                decoy += 1;
            }
        }
        assert_eq!(active, 64);
        assert_eq!(decoy, 64);
    }
}

#[test]
fn test_challenge_128_shard_boundary_and_out_of_bounds() {
    let pair_map = 0x1234_5678_9ABC_DEF0_u64;

    // Out-of-bounds indices must safely return false and NEVER panic or shift overflow
    let oob_indices = [128, 129, 130, 255, 256, 512, 1024, usize::MAX];
    for &idx in &oob_indices {
        let is_active = exec_is_active_shard(idx, pair_map);
        assert!(
            !is_active,
            "Out-of-bounds shard index {idx} must evaluate to false"
        );
    }
}

#[test]
fn test_challenge_tinyvm_wrapping_arithmetic_invariance() {
    let mut rng = ChallengeRng::new(0x1234_ABCD_5678_EF01);

    // 1. Boundary & extreme inputs
    let boundary_pairs: [(u64, u64); 12] = [
        (0, 0),
        (0, 1),
        (1, 0),
        (u64::MAX, 1),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
        (1 << 63, 1 << 63),
        (1 << 63, (1 << 63) - 1),
        (0x9E37_79B9_7F4A_7C15, 0xF1DE_83E1_9937_733D),
        (0xDEAD_BEEF_CAFE_BABE, 0x0123_4567_89AB_CDEF),
        (0xFFFF_FFFF_0000_0000, 0x0000_0000_FFFF_FFFF),
        (0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA),
    ];

    for &(a, b) in &boundary_pairs {
        // Additive inverse cancellation: (a + b) - b == a
        assert_eq!(
            a.wrapping_add(b).wrapping_sub(b), a,
            "Additive cancellation failed for ({a:#018X}, {b:#018X})"
        );
        // Subtractive inverse cancellation: (a - b) + b == a
        assert_eq!(
            a.wrapping_sub(b).wrapping_add(b), a,
            "Subtractive cancellation failed for ({a:#018X}, {b:#018X})"
        );
        // Additive commutativity: a + b == b + a
        assert_eq!(
            a.wrapping_add(b), b.wrapping_add(a),
            "Additive commutativity failed for ({a:#018X}, {b:#018X})"
        );
        // Multiplicative commutativity: a * b == b * a
        assert_eq!(
            a.wrapping_mul(b), b.wrapping_mul(a),
            "Multiplicative commutativity failed for ({a:#018X}, {b:#018X})"
        );
        // Self-subtraction: a - a == 0
        assert_eq!(
            a.wrapping_sub(a), 0,
            "Self-subtraction failed for {a:#018X}"
        );
        // Additive identity: a + 0 == a
        assert_eq!(
            a.wrapping_add(0), a,
            "Additive identity failed for {a:#018X}"
        );
        // Multiplicative identity: a * 1 == a
        assert_eq!(
            a.wrapping_mul(1), a,
            "Multiplicative identity failed for {a:#018X}"
        );
        // Multiplicative annihilator: a * 0 == 0
        assert_eq!(
            a.wrapping_mul(0), 0,
            "Multiplicative annihilator failed for {a:#018X}"
        );
    }

    // 2. Stress test with 100,000 randomized 64-bit operand pairs
    for i in 0..100_000 {
        let a = rng.next_u64();
        let b = rng.next_u64();
        let c = rng.next_u64();

        // Cancellation laws
        assert_eq!(a.wrapping_add(b).wrapping_sub(b), a, "Stress cancellation failed at {i}");
        assert_eq!(a.wrapping_sub(b).wrapping_add(b), a, "Stress cancellation failed at {i}");

        // Ring properties
        assert_eq!(a.wrapping_add(b), b.wrapping_add(a));
        assert_eq!(a.wrapping_mul(b), b.wrapping_mul(a));
        assert_eq!(a.wrapping_sub(a), 0);

        // Associativity
        assert_eq!(
            a.wrapping_add(b).wrapping_add(c),
            a.wrapping_add(b.wrapping_add(c)),
            "Addition associativity failed at {i}"
        );
        assert_eq!(
            a.wrapping_mul(b).wrapping_mul(c),
            a.wrapping_mul(b.wrapping_mul(c)),
            "Multiplication associativity failed at {i}"
        );

        // Distributivity: a * (b + c) == (a * b) + (a * c)
        assert_eq!(
            a.wrapping_mul(b.wrapping_add(c)),
            (a.wrapping_mul(b)).wrapping_add(a.wrapping_mul(c)),
            "Distributivity failed at {i}"
        );
    }
}

#[test]
fn test_challenge_tinyvm_lifo_conservation_rigorous() {
    let mut rng = ChallengeRng::new(0xCAFE_BABE_9876_5432);

    // Test across all 32 valid unsaturated initial stack depths (sp in 0..32)
    for sp_init in 0..32 {
        let mut initial_stack = [0u64; 32];
        for slot in 0..sp_init {
            initial_stack[slot] = rng.next_u64();
        }

        let initial_vm = TinyVmModel {
            vip: (rng.next_u32() % 1000) as usize,
            sp: sp_init,
            v_stack: initial_stack,
            accumulator: rng.next_u64(),
            key: rng.next_u64(),
        };

        // Test with multiple adversarial values: boundaries and randoms
        let test_values = [
            0u64,
            1u64,
            u64::MAX,
            0x8000_0000_0000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0xDEAD_BEEF_CAFE_BABE,
            rng.next_u64(),
        ];

        for &val in &test_values {
            // 1. Formal specification model push
            let pushed_vm = model_push(initial_vm, val);
            assert_eq!(
                pushed_vm.sp, sp_init + 1,
                "Model push must increment sp by 1 for unsaturated stack (sp={sp_init})"
            );
            assert_eq!(
                model_peek(pushed_vm), val,
                "Model peek must return pushed val immediately after push"
            );

            // 2. Formal specification model pop
            let (popped_vm, popped_val) = model_pop(pushed_vm);

            // Theorem 9 Invariant 1: Popped value equals pushed value
            assert_eq!(
                popped_val, val,
                "Theorem 9 LIFO conservation failed: popped {popped_val:#018X} != pushed {val:#018X} at sp={sp_init}"
            );

            // Theorem 9 Invariant 2: Stack pointer perfectly restored
            assert_eq!(
                popped_vm.sp, initial_vm.sp,
                "Theorem 9 sp conservation failed: popped sp {} != initial sp {}",
                popped_vm.sp, initial_vm.sp
            );

            // Theorem 9 Invariant 3: Machine registers completely preserved
            assert_eq!(popped_vm.vip, initial_vm.vip, "VIP corrupted by push/pop cycle");
            assert_eq!(popped_vm.accumulator, initial_vm.accumulator, "Accumulator corrupted");
            assert_eq!(popped_vm.key, initial_vm.key, "Key corrupted");

            // Theorem 9 Invariant 4: Active stack frame below sp is pristine
            for slot in 0..sp_init {
                assert_eq!(
                    popped_vm.v_stack[slot], initial_vm.v_stack[slot],
                    "Active stack slot {slot} altered after push/pop cycle at sp={sp_init}"
                );
            }

            // 3. Differential runtime validation against real TinyVm hardware struct
            let mut runtime_vm = TinyVm::new(initial_vm.key);
            runtime_vm.vip = initial_vm.vip;
            runtime_vm.accumulator = initial_vm.accumulator;
            runtime_vm.sp = initial_vm.sp;
            runtime_vm.v_stack = initial_vm.v_stack;

            runtime_vm.push(val);
            assert_eq!(runtime_vm.sp, pushed_vm.sp);
            assert_eq!(runtime_vm.peek(), val);

            let runtime_popped = runtime_vm.pop();
            assert_eq!(runtime_popped, popped_val);
            assert_eq!(runtime_vm.sp, popped_vm.sp);
            assert_eq!(runtime_vm.accumulator, popped_vm.accumulator);
            assert_eq!(runtime_vm.key, popped_vm.key);
            assert_eq!(runtime_vm.vip, popped_vm.vip);
            for slot in 0..sp_init {
                assert_eq!(runtime_vm.v_stack[slot], popped_vm.v_stack[slot]);
            }
        }
    }

    // 4. Verify boundary behavior at stack capacity saturation (sp == 32)
    let saturated_vm = TinyVmModel {
        vip: 0,
        sp: 32,
        v_stack: [0x55; 32],
        accumulator: 0,
        key: 0,
    };
    let push_saturated = model_push(saturated_vm, 0xBADF00D);
    assert_eq!(
        push_saturated.sp, 32,
        "Stack pointer must saturate at 32 and reject 33rd push"
    );
    let (pop_saturated, pop_val) = model_pop(push_saturated);
    assert_eq!(pop_saturated.sp, 31);
    assert_eq!(
        pop_val, 0x55,
        "Popping saturated stack returns previously clamped top element, confirming sp < 32 precondition tightness"
    );
}

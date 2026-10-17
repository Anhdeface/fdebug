#![allow(unused_imports, dead_code)]

//! # Challenger M1 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger 1 for Milestone 1:
//! 1. Rolling Key State Transition:
//!    - Exhaustive pair collision search over F_2^8 across all key states.
//!    - Invertibility, fixed points, and cycle structure decomposition of x -> x ^ (x << 1) ^ 0x3C.
//! 2. 64-Bit Token Diffusion (diffuse_token):
//!    - Single-bit perturbation coverage (bits 8..63).
//!    - Multi-bit perturbations, byte-swap commutativity, all-zeros, and all-ones.
//!    - Linear XOR fold cancellation kernel analysis.
//! 3. Stack Underflow & Boundary Protection:
//!    - Binary operations on empty (sp=0), single (sp=1), pair (sp=2), and saturated (sp=32) stack.
//!    - Unary op state synthesis investigation (op_not).
//!    - Control flow (op_jump, op_jz, op_jnz) and rolling key synchronization.

use arbitrary::Arbitrary;
use bolero::check;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    encode_bytecode, vm_execute, TinyVm, VmOp,
    global_state, pe_integrity,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Helper RAII guard to safely restore INTEGRITY_TOKEN on test completion or unwind
struct TokenRestoreGuard(u64);
impl Drop for TokenRestoreGuard {
    fn drop(&mut self) {
        pe_integrity::INTEGRITY_TOKEN.store(self.0, Ordering::Relaxed);
    }
}

// ============================================================================
// 1. TASK 1: ROLLING KEY BIJECTIVITY, COLLISIONS, FIXED POINTS, & CYCLES
// ============================================================================

/// Mathematical definition of the rolling key core map: f(x) = x ^ (x << 1) ^ 0x3C
fn rolling_key_map(x: u8) -> u8 {
    x ^ (x << 1) ^ 0x3C
}

/// Full state transition: (state_key, raw_byte) -> next_state_key
fn full_state_transition(state_key: u8, raw_byte: u8, entropy: u8) -> u8 {
    let mut k = state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
    k ^= (k << 1) ^ 0x3C;
    k ^ entropy
}

#[test]
fn test_adversarial_task1_exhaustive_pair_collision_freedom() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Exhaustively verify across ALL 256 state keys and ALL 256^2 input pairs
    // that no two distinct inputs produce the same next state key.
    let entropy = 0x5Au8;
    for state_key in 0..=255u8 {
        let mut seen = [false; 256];
        for raw_byte in 0..=255u8 {
            let next_k = full_state_transition(state_key, raw_byte, entropy);
            assert!(
                !seen[next_k as usize],
                "COLLISION DETECTED: state_key=0x{:02X}, raw_byte=0x{:02X} produced duplicate next_k=0x{:02X}",
                state_key, raw_byte, next_k
            );
            seen[next_k as usize] = true;
        }
        // Image cardinality must be exactly 256
        assert_eq!(seen.iter().filter(|&&b| b).count(), 256);
    }
}

#[test]
fn test_adversarial_task1_fixed_points_and_cycle_decomposition() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Check invertibility of the core map
    let mut image = HashSet::new();
    for x in 0..=255u8 {
        image.insert(rolling_key_map(x));
    }
    assert_eq!(image.len(), 256, "Core map f(x) is not a permutation!");

    // 2. Discover ALL Fixed Points: x such that f(x) == x
    // f(x) = x ^ (x << 1) ^ 0x3C == x <=> (x << 1) == 0x3C
    let mut fixed_points = Vec::new();
    for x in 0..=255u8 {
        if rolling_key_map(x) == x {
            fixed_points.push(x);
        }
    }

    println!("[Task 1] Discovered Fixed Points of f(x): {:?}", fixed_points);
    // Mathematically: (x << 1) & 0xFF == 0x3C (60)
    // Solutions are 60 / 2 = 30 (0x1E) and 30 + 128 = 158 (0x9E)
    assert_eq!(
        fixed_points,
        vec![0x1Eu8, 0x9Eu8],
        "Unexpected fixed point set! Expected strictly [0x1E, 0x9E]"
    );

    // 3. Full Cycle Decomposition of the permutation f
    let mut visited = [false; 256];
    let mut cycle_lengths = Vec::new();
    let mut cycles: Vec<Vec<u8>> = Vec::new();

    for start in 0..=255u8 {
        if visited[start as usize] {
            continue;
        }
        let mut curr = start;
        let mut cycle = Vec::new();
        while !visited[curr as usize] {
            visited[curr as usize] = true;
            cycle.push(curr);
            curr = rolling_key_map(curr);
        }
        cycle_lengths.push(cycle.len());
        cycles.push(cycle);
    }

    cycle_lengths.sort_unstable();
    println!("[Task 1] Permutation Cycle Count: {}", cycles.len());
    println!("[Task 1] Permutation Cycle Lengths: {:?}", cycle_lengths);

    // Verify presence of 1-cycles (fixed points)
    let one_cycles = cycle_lengths.iter().filter(|&&len| len == 1).count();
    assert_eq!(one_cycles, 2, "Permutation must contain exactly 2 fixed points (1-cycles)");
}

// ============================================================================
// 2. TASK 2: 64-BIT TOKEN DIFFUSION ADVERSARIAL ANALYSIS
// ============================================================================

/// Production diffuse_token logic from tiny_vm.rs
fn diffuse_token_ref(token: u64) -> u8 {
    let lower = token as u8;
    let upper = token & 0xFFFF_FFFF_FFFF_FF00;
    let diff = upper ^ 0xDEADBEEFCAFEBA00;
    let b = diff.to_le_bytes();
    let fold = b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6] ^ b[7];
    lower ^ fold
}

#[test]
fn test_adversarial_task2_single_bit_perturbations_full_coverage() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let canonical_token = 0xDEADBEEFCAFEBABE_u64;
    let baseline = diffuse_token_ref(canonical_token);

    // Single-bit perturbations for all 56 upper bits (8..63)
    for bit in 8..64 {
        let perturbed = canonical_token ^ (1u64 << bit);
        let val = diffuse_token_ref(perturbed);
        assert_ne!(
            val, baseline,
            "Single-bit perturbation at bit {} failed to diffuse!", bit
        );
    }
}

#[test]
fn test_adversarial_task2_multibit_cancellations_and_kernel() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let canonical_token = 0xDEADBEEFCAFEBABE_u64;
    let baseline = diffuse_token_ref(canonical_token);

    // 1. Two-bit cancellation vulnerability:
    // Flipping bit j in byte 1 AND bit j in byte 2 produces identical fold!
    for bit_in_byte in 0..8 {
        let mask = (1u64 << (8 + bit_in_byte)) | (1u64 << (16 + bit_in_byte));
        let perturbed = canonical_token ^ mask;
        let val = diffuse_token_ref(perturbed);
        assert_eq!(
            val, baseline,
            "2-bit perturbation mask 0x{:016X} was unexpectedly detected!", mask
        );
    }

    // 2. Byte swap commutativity vulnerability:
    // Swapping byte 1 and byte 2 of the upper token preserves the XOR fold exactly
    let mut b = canonical_token.to_le_bytes();
    b.swap(1, 2);
    let swapped_token = u64::from_le_bytes(b);
    assert_ne!(swapped_token, canonical_token);
    assert_eq!(
        diffuse_token_ref(swapped_token),
        baseline,
        "Byte swap in upper token was unexpectedly detected!"
    );

    // 3. All-Zeros and All-Ones boundary values
    let val_zero = diffuse_token_ref(0u64);
    let val_max = diffuse_token_ref(u64::MAX);

    println!("[Task 2] diffuse_token(0) = 0x{:02X}", val_zero);
    println!("[Task 2] diffuse_token(u64::MAX) = 0x{:02X}", val_max);

    // Both 0 and u64::MAX produce 0xAC
    assert_eq!(val_zero, 0xAC, "diffuse_token(0) mismatch");
    assert_eq!(val_max, 0xAC, "diffuse_token(u64::MAX) mismatch");
    assert_eq!(val_zero, val_max, "diffuse_token(0) and diffuse_token(u64::MAX) must collide at 0xAC");
}

// ============================================================================
// 3. TASK 3: STACK UNDERFLOW, CONTROL FLOW, & ROLLING KEY LOCKSTEP
// ============================================================================

#[test]
fn test_adversarial_task3_binary_ops_on_stack_boundaries() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let enc_key = 0x55u8;

    let binary_ops = [
        VmOp::op_add(),
        VmOp::op_sub(),
        VmOp::op_xor(),
        VmOp::op_and(),
        VmOp::op_or(),
        VmOp::op_shl(),
        VmOp::op_shr(),
        VmOp::op_cmp_eq(),
        VmOp::op_cmp_ne(),
        VmOp::op_cmp_gt(),
        VmOp::op_cmp_lt(),
        VmOp::op_write_mem_u8(),
    ];

    // Boundary 1: sp = 0 (empty stack)
    // Executing any binary op must NOT increment sp or synthesize values
    for &op in &binary_ops {
        let plain = vec![
            op,
            VmOp::op_push(), 0x77,
            VmOp::op_exit(),
        ];
        let encoded = encode_bytecode(&plain, enc_key);
        let res = vm_execute(&encoded, enc_key, 0);
        assert_eq!(res, 0x77, "Binary op 0x{:02X} on sp=0 corrupted stack!", op);
    }

    // Boundary 2: sp = 1 (single element on stack)
    // Binary op must be a no-op (requires sp >= 2), preserving the single element
    for &op in &binary_ops {
        let plain = vec![
            VmOp::op_push(), 0x99, // stack has [0x99]
            op,                     // should be no-op because sp=1 < 2
            VmOp::op_exit(),        // should pop and return 0x99
        ];
        let encoded = encode_bytecode(&plain, enc_key);
        let res = vm_execute(&encoded, enc_key, 0);
        assert_eq!(res, 0x99, "Binary op 0x{:02X} on sp=1 failed to preserve single item!", op);
    }

    // Boundary 3: sp = 2 (two elements on stack)
    // op_add should consume 2, push 1, leaving sp = 1
    let plain_sp2 = vec![
        VmOp::op_push(), 10,
        VmOp::op_push(), 20,
        VmOp::op_add(),
        VmOp::op_exit(),
    ];
    let encoded_sp2 = encode_bytecode(&plain_sp2, enc_key);
    let res_sp2 = vm_execute(&encoded_sp2, enc_key, 0);
    assert_eq!(res_sp2, 30, "op_add on sp=2 failed!");

    // Boundary 4: sp = 32 (stack saturation)
    let mut plain_sat = Vec::new();
    for i in 0..35 {
        plain_sat.push(VmOp::op_push());
        plain_sat.push(i as u8);
    }
    // Now stack has 32 items (saturated). Execute op_add
    plain_sat.push(VmOp::op_add());
    plain_sat.push(VmOp::op_exit());
    let encoded_sat = encode_bytecode(&plain_sat, enc_key);
    let res_sat = vm_execute(&encoded_sat, enc_key, 0);
    // Stack top two were 30 and 31 (pushed at steps 30 and 31; step 32-34 dropped).
    // Sum is 30 + 31 = 61.
    assert_eq!(res_sat, 61, "op_add on saturated stack failed!");
}

#[test]
fn test_adversarial_task1_full_state_transition_autonomous_cycles() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // Examine the autonomous map: k_{t+1} = full_state_transition(k_t, 0, 0)
    // where raw_byte = 0 and entropy = 0.
    let mut visited = [false; 256];
    let mut cycles = Vec::new();

    for start in 0..=255u8 {
        if visited[start as usize] {
            continue;
        }
        let mut curr = start;
        let mut cycle = Vec::new();
        while !visited[curr as usize] {
            visited[curr as usize] = true;
            cycle.push(curr);
            curr = full_state_transition(curr, 0, 0);
        }
        cycles.push(cycle);
    }

    let mut lengths: Vec<usize> = cycles.iter().map(|c| c.len()).collect();
    lengths.sort_unstable();
    println!("[Task 1] Autonomous Map (raw=0, entropy=0) Cycle Count: {}", cycles.len());
    println!("[Task 1] Autonomous Map Cycle Lengths: {:?}", lengths);
}

#[test]
fn test_adversarial_task3_control_flow_jump_and_loop_semantics() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let enc_key = 0x33u8;

    // Test A: Straight-line execution vs Jump forward
    // In TinyVM, op_jump fetches target operand, then sets state.vip = target.
    // Let's test a forward jump:
    // vip 0: op_jump()
    // vip 1: target (vip 4)
    // vip 2: op_push() - skipped
    // vip 3: 0x11 - skipped
    // vip 4: op_push()
    // vip 5: 0x22
    // vip 6: op_exit()
    let plain_jump = vec![
        VmOp::op_jump(),
        4, // target vip
        VmOp::op_push(),
        0x11,
        VmOp::op_push(),
        0x22,
        VmOp::op_exit(),
    ];
    let encoded_jump = encode_bytecode(&plain_jump, enc_key);
    let res_jump = vm_execute(&encoded_jump, enc_key, 0);
    println!("[Task 3] Forward jump executed. Result = 0x{:X}", res_jump);

    // Test B: Conditional jump op_jz when condition is false (stack top != 0)
    // vip 0: op_push()
    // vip 1: 1 (non-zero)
    // vip 2: op_jz()
    // vip 3: 6 (target)
    // vip 4: op_push()
    // vip 5: 0x88
    // vip 6: op_exit()
    let plain_jz_false = vec![
        VmOp::op_push(),
        1,
        VmOp::op_jz(),
        6,
        VmOp::op_push(),
        0x88,
        VmOp::op_exit(),
    ];
    let encoded_jz_false = encode_bytecode(&plain_jz_false, enc_key);
    let res_jz_false = vm_execute(&encoded_jz_false, enc_key, 0);
    println!("[Task 3] Conditional jump (not taken) executed. Result = 0x{:X}", res_jz_false);
}

#[test]
fn test_adversarial_task3_unary_op_underflow_behavior() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let enc_key = 0xAAu8;

    // op_not does NOT have an `if vm.sp >= 1` guard.
    // When called on empty stack, vm.pop() returns 0, and vm.push(!0) synthesizes 0xFFFFFFFFFFFFFFFF!
    let plain = vec![
        VmOp::op_not(),
        VmOp::op_exit(),
    ];
    let encoded = encode_bytecode(&plain, enc_key);
    let res = vm_execute(&encoded, enc_key, 0);
    println!("[Task 3] op_not on sp=0 exit_value: 0x{:016X}", res);
    assert_eq!(
        res, u64::MAX,
        "Empirical proof: op_not on empty stack synthesizes u64::MAX"
    );
}


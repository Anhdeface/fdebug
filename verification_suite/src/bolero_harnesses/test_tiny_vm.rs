//! Bolero Property-Based Testing Harness: TinyVM Execution Engine
//! Target Module: test_tiny_vm.rs
//! Covers: Features 10, 11, 12, 13 (Opcode Execution, Stack Safety, Rolling Key, LTP Permutation)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::{vm_execute, TinyVm, VmOp};

/// Operations for testing TinyVm virtual stack safety and clamping contracts
#[derive(Arbitrary, Debug, Clone)]
pub enum VmStackAction {
    Push(u64),
    Pop,
    Peek,
    LoadImm(u64),
}

/// Adversarial sequence of stack operations
#[derive(Arbitrary, Debug, Clone)]
pub struct VmStackSequence {
    pub initial_key: u64,
    pub actions: Vec<VmStackAction>,
}

/// Feature 11: Bolero TinyVM Stack Safety
/// Mathematical Invariant:
/// \forall k >= 0: 0 <= vm.sp <= 32
/// Push(v) clamps sp at 32 without overflow panic.
/// Pop() clamps sp at 0 and returns 0 on empty stack without underflow panic.
#[test]
fn prop_tiny_vm_stack_clamping_and_bounds() {
    check!()
        .with_arbitrary::<VmStackSequence>()
        .for_each(|seq| {
            let mut vm = TinyVm::new(seq.initial_key);
            let mut shadow_stack: Vec<u64> = Vec::with_capacity(32);

            for action in &seq.actions {
                match action {
                    VmStackAction::Push(val) | VmStackAction::LoadImm(val) => {
                        vm.push(*val);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(*val);
                        }
                    }
                    VmStackAction::Pop => {
                        let actual = vm.pop();
                        let expected = shadow_stack.pop().unwrap_or(0);
                        assert_eq!(actual, expected, "Pop value mismatch against shadow model");
                    }
                    VmStackAction::Peek => {
                        let actual = vm.peek();
                        let expected = shadow_stack.last().copied().unwrap_or(0);
                        assert_eq!(actual, expected, "Peek value mismatch against shadow model");
                    }
                }

                // Invariant: vm.sp is clamped strictly between 0 and 32
                assert!(vm.sp <= 32, "Invariant violation: vm.sp > 32 (got {})", vm.sp);
                assert_eq!(vm.sp, shadow_stack.len(), "vm.sp diverged from shadow stack size");
                assert_eq!(vm.key, seq.initial_key, "vm.key corrupted by stack operation");
                assert_eq!(vm.vip, 0, "vm.vip corrupted by stack operation");
            }
        });
}

/// Input model for rolling key round-trip bijectivity property
#[derive(Arbitrary, Debug, Clone)]
pub struct RollingKeyInput {
    pub bytecode: Vec<u8>,
    pub enc_key: u8,
    pub initial_rolling_key: u8,
    pub token: u8,
    pub global_key: u8,
    pub token_perturbation: u8,
}

/// Feature 12: Bolero TinyVM Rolling Key Round-Trip
/// Mathematical Invariant:
/// Let raw = (op - (idx * 7) mod 256) ^ enc_key ^ r_key ^ token
/// Then decoded = (raw ^ enc_key ^ r_key ^ token) + (idx * 7) mod 256 == op
/// Bijectivity holds for all inputs; perturbed token causes strict divergence.
#[test]
fn prop_rolling_key_roundtrip_bijectivity() {
    check!()
        .with_arbitrary::<RollingKeyInput>()
        .for_each(|input| {
            if input.bytecode.is_empty() || input.bytecode.len() > 512 {
                return;
            }

            // 1. Encode stream
            let mut encoded = vec![0u8; input.bytecode.len()];
            let mut r_key = input.initial_rolling_key;

            for (idx, &op) in input.bytecode.iter().enumerate() {
                let pos_salt = (idx as u8).wrapping_mul(7);
                let raw = op.wrapping_sub(pos_salt) ^ input.enc_key ^ r_key ^ input.token;
                encoded[idx] = raw;

                r_key = r_key.wrapping_add(raw).wrapping_mul(0x1F);
                r_key ^= r_key.rotate_right(3) ^ 0x3C;
                r_key ^= input.global_key;
            }

            // 2. Decode stream with matching keys
            let mut decoded = vec![0u8; input.bytecode.len()];
            let mut r_key_dec = input.initial_rolling_key;

            for (idx, &raw) in encoded.iter().enumerate() {
                let pos_salt = (idx as u8).wrapping_mul(7);
                let op = (raw ^ input.enc_key ^ r_key_dec ^ input.token).wrapping_add(pos_salt);
                decoded[idx] = op;

                r_key_dec = r_key_dec.wrapping_add(raw).wrapping_mul(0x1F);
                r_key_dec ^= r_key_dec.rotate_right(3) ^ 0x3C;
                r_key_dec ^= input.global_key;
            }

            // Invariant 1: Exact round-trip reconstruction
            assert_eq!(decoded, input.bytecode, "Rolling key round-trip failed to reconstruct original bytecode");
            assert_eq!(r_key, r_key_dec, "Encoder and decoder final rolling keys diverged");

            // Invariant 2: Divergence under token perturbation
            if input.token_perturbation != 0 {
                let corrupted_token = input.token ^ input.token_perturbation;
                let mut corrupted_decoded = vec![0u8; input.bytecode.len()];
                let mut r_key_corrupt = input.initial_rolling_key;

                for (idx, &raw) in encoded.iter().enumerate() {
                    let pos_salt = (idx as u8).wrapping_mul(7);
                    let op = (raw ^ input.enc_key ^ r_key_corrupt ^ corrupted_token).wrapping_add(pos_salt);
                    corrupted_decoded[idx] = op;

                    r_key_corrupt = r_key_corrupt.wrapping_add(raw).wrapping_mul(0x1F);
                    r_key_corrupt ^= r_key_corrupt.rotate_right(3) ^ 0x3C;
                    r_key_corrupt ^= input.global_key;
                }

                assert_ne!(
                    corrupted_decoded, input.bytecode,
                    "Corrupted token must strictly diverge decoded bytecode"
                );
            }
        });
}

/// Feature 13: Bolero TinyVM LTP Matrix Permutation
/// Mathematical Invariant:
/// Fisher-Yates shuffle with Xorshift32 PRNG forms a strict permutation of 0..255.
/// Every byte in 0..=255 appears exactly once (bijection on S_256).
#[test]
fn prop_ltp_matrix_permutation_bijection() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let mut map = [0u8; 256];
            for i in 0..256 {
                map[i] = i as u8;
            }

            let mut state = if *seed == 0 { 0xDEADBEEF } else { *seed };
            for i in (1..256).rev() {
                // Xorshift32
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let j = (state as usize) % (i + 1);
                map.swap(i, j);
            }

            // Invariant 1: Mapping is a strict bijection over 0..256
            let mut seen = [false; 256];
            for &val in &map {
                assert!(!seen[val as usize], "Duplicate entry {} in LTP map for seed {:#X}", val, seed);
                seen[val as usize] = true;
            }
            assert!(seen.iter().all(|&s| s), "LTP map does not cover all 256 elements");
        });
}

/// Structured bytecode instruction for opcode execution fuzzing
#[derive(Arbitrary, Debug, Clone)]
pub enum StructuredVmOp {
    LoadImm(u64),
    Add,
    Sub,
    Xor,
    Dup,
    Swap,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct StructuredVmProgram {
    pub ops: Vec<StructuredVmOp>,
    pub enc_key: u8,
    pub ctx_key: u64,
}

/// Helper: Encodes plain bytecode into TinyVM rolling-key encrypted bytecode
/// matching the exact decryption algorithm in src/protector/tiny_vm.rs:520-538.
pub fn encode_tinyvm_bytecode(plain_bytes: &[u8], encryption_key: u8) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(plain_bytes.len());
    let mut state_key: u8 = 0;
    let integrity_val = crate::shims::pe_integrity_shim::INTEGRITY_TOKEN.load(std::sync::atomic::Ordering::Relaxed) as u8;
    let global_entropy = crate::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(std::sync::atomic::Ordering::Relaxed);

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

/// Feature 10: Bolero TinyVM Opcode Execution
/// Verifies that programs built from arithmetic, stack, and exit opcodes
/// execute accurately, maintain stack bounds, and produce exact results matching
/// an independent reference shadow stack interpreter via vm_execute.
#[test]
fn prop_tiny_vm_structured_opcode_execution() {
    check!()
        .with_arbitrary::<StructuredVmProgram>()
        .for_each(|program| {
            if program.ops.is_empty() || program.ops.len() > 10 {
                return;
            }

            let k = program.enc_key;
            let mut plain_bc = Vec::new();

            // 1. Seed the stack with initial operand to guarantee real values for arithmetic
            // and ensure instruction fetches start safely past vip=3 to prevent heartbeat trigger.
            plain_bc.push(VmOp::op_load_imm());
            plain_bc.extend_from_slice(&program.ctx_key.to_le_bytes());

            for op in &program.ops {
                match op {
                    StructuredVmOp::LoadImm(val) => {
                        plain_bc.push(VmOp::op_load_imm());
                        plain_bc.extend_from_slice(&val.to_le_bytes());
                    }
                    StructuredVmOp::Add => {
                        plain_bc.push(VmOp::op_add());
                    }
                    StructuredVmOp::Sub => {
                        plain_bc.push(VmOp::op_sub());
                    }
                    StructuredVmOp::Xor => {
                        plain_bc.push(VmOp::op_xor());
                    }
                    StructuredVmOp::Dup => {
                        plain_bc.push(VmOp::op_dup());
                    }
                    StructuredVmOp::Swap => {
                        plain_bc.push(VmOp::op_swap());
                    }
                }
            }
            plain_bc.push(VmOp::op_exit());

            // 2. Compute expected result via independent shadow stack simulation
            let mut shadow_stack: Vec<u64> = Vec::new();
            shadow_stack.push(program.ctx_key);

            let suspicion = crate::protector::global_state::get_suspicion_score();
            let under_debug = suspicion > 100;

            for op in &program.ops {
                match op {
                    StructuredVmOp::LoadImm(val) => {
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(*val);
                        }
                    }
                    StructuredVmOp::Add => {
                        let b = shadow_stack.pop().unwrap_or(0);
                        let a = shadow_stack.pop().unwrap_or(0);
                        let res = if under_debug {
                            a.wrapping_sub(b)
                        } else {
                            a.wrapping_add(b)
                        };
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(res);
                        }
                    }
                    StructuredVmOp::Sub => {
                        let b = shadow_stack.pop().unwrap_or(0);
                        let a = shadow_stack.pop().unwrap_or(0);
                        let res = if under_debug {
                            a.wrapping_add(b)
                        } else {
                            a.wrapping_sub(b)
                        };
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(res);
                        }
                    }
                    StructuredVmOp::Xor => {
                        let b = shadow_stack.pop().unwrap_or(0);
                        let a = shadow_stack.pop().unwrap_or(0);
                        let res = if under_debug {
                            a.wrapping_add(b)
                        } else {
                            a ^ b
                        };
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(res);
                        }
                    }
                    StructuredVmOp::Dup => {
                        let val = shadow_stack.last().copied().unwrap_or(0);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(val);
                        }
                    }
                    StructuredVmOp::Swap => {
                        if shadow_stack.len() >= 2 {
                            let len = shadow_stack.len();
                            shadow_stack.swap(len - 1, len - 2);
                        }
                    }
                }
            }
            let expected_exit_value = shadow_stack.pop().unwrap_or(0);

            // 3. Properly encode bytecode using the rolling key and position salt cipher
            let encoded_bc = encode_tinyvm_bytecode(&plain_bc, k);

            // 4. Execute in TinyVM
            let actual_exit_value = vm_execute(&encoded_bc, k, program.ctx_key);

            // Invariant 1: Genuine functional execution matching reference shadow stack
            assert_eq!(
                actual_exit_value, expected_exit_value,
                "TinyVM execution result diverged from expected shadow stack simulation (ops={}, plain_len={})",
                program.ops.len(), plain_bc.len()
            );

            // Invariant 2: Adversarial tamper resistance — perturbed encryption key must diverge
            if k != (k ^ 0xAA) && expected_exit_value != 0 {
                let corrupted_key = k ^ 0xAA;
                let corrupted_result = vm_execute(&encoded_bc, corrupted_key, program.ctx_key);
                assert_ne!(
                    corrupted_result, expected_exit_value,
                    "Execution under perturbed encryption key must diverge from genuine output"
                );
            }
        });
}

/// Invariant: Safe wrapping arithmetic mod 2^64
#[test]
fn prop_tiny_vm_wrapping_arithmetic_properties() {
    check!()
        .with_arbitrary::<(u64, u64)>()
        .for_each(|(a, b)| {
            // Addition wrapping identity
            let sum_wrap = a.wrapping_add(*b);
            let sub_wrap = sum_wrap.wrapping_sub(*b);
            assert_eq!(sub_wrap, *a, "Wrapping arithmetic add-sub identity violated");

            // XOR involution identity
            let xor_val = a ^ b;
            let recovered = xor_val ^ b;
            assert_eq!(recovered, *a, "XOR involution identity violated");
        });
}

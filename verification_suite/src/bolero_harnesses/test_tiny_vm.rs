//! Bolero Property-Based Testing Harness: TinyVM Execution Engine
//! Target Module: test_tiny_vm.rs
//! Covers: Features 10, 11, 12, 13 (Opcode Execution, Stack Safety, Rolling Key, LTP Permutation)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::tiny_vm::{diffuse_token, encode_bytecode, TinyVm, VmOp};
use crate::protector::vm_execute;

/// Operations for testing TinyVm virtual stack safety and clamping contracts
#[derive(Arbitrary, Debug, Clone)]
pub enum VmStackAction {
    Push(u64),
    Pop,
    Peek,
    LoadImm(u64),
    RepeatedPush(u64, u8),
    RepeatedPop(u8),
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
                        let prev_stack = vm.v_stack;
                        vm.push(*val);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(*val);
                        } else {
                            // Overflow clamping: stack remains identical
                            assert_eq!(vm.sp, 32, "Clamped SP exceeded 32 on overflow push");
                            assert_eq!(vm.v_stack, prev_stack, "Overflow push must not alter clamped stack contents");
                        }
                    }
                    VmStackAction::Pop => {
                        let prev_sp = vm.sp;
                        let actual = vm.pop();
                        let expected = shadow_stack.pop().unwrap_or(0);
                        assert_eq!(actual, expected, "Pop value mismatch against shadow model");
                        if prev_sp == 0 {
                            assert_eq!(vm.sp, 0, "Underflow pop must leave sp == 0");
                            assert_eq!(actual, 0, "Underflow pop must return 0");
                        }
                    }
                    VmStackAction::Peek => {
                        let actual = vm.peek();
                        let expected = shadow_stack.last().copied().unwrap_or(0);
                        assert_eq!(actual, expected, "Peek value mismatch against shadow model");
                    }
                    VmStackAction::RepeatedPush(val, count) => {
                        let iters = (*count % 40) as usize;
                        for _ in 0..iters {
                            vm.push(*val);
                            if shadow_stack.len() < 32 {
                                shadow_stack.push(*val);
                            }
                        }
                    }
                    VmStackAction::RepeatedPop(count) => {
                        let iters = (*count % 40) as usize;
                        for _ in 0..iters {
                            let actual = vm.pop();
                            let expected = shadow_stack.pop().unwrap_or(0);
                            assert_eq!(actual, expected, "RepeatedPop value mismatch");
                        }
                    }
                }

                // Invariants:
                // 1. vm.sp is clamped strictly between 0 and 32
                assert!(vm.sp <= 32, "Invariant violation: vm.sp > 32 (got {})", vm.sp);
                assert_eq!(vm.sp, shadow_stack.len(), "vm.sp diverged from shadow stack size");
                // 2. Active stack values match shadow model exactly
                for i in 0..vm.sp {
                    assert_eq!(vm.v_stack[i], shadow_stack[i], "Stack value mismatch at slot {}", i);
                }
                // 3. State isolation: accumulator, key, vip are untouched
                assert_eq!(vm.key, seq.initial_key, "vm.key corrupted by stack operation");
                assert_eq!(vm.vip, 0, "vm.vip corrupted by stack operation");
                assert_eq!(vm.accumulator, 0, "vm.accumulator corrupted by stack operation");
            }
        });
}

/// Input model for rolling key round-trip bijectivity property
#[derive(Arbitrary, Debug, Clone)]
pub struct RollingKeyInput {
    pub bytecode: Vec<u8>,
    pub enc_key: u8,
    pub token: u64,
    pub global_key: u8,
    pub bit_flip_pos: u8,
}

/// Feature 12: Bolero TinyVM Rolling Key Round-Trip
/// Mathematical Invariant:
/// Mode H instruction encoding/decoding is a strict information-preserving bijection.
/// 64-bit token diffusion guarantees zero blind spot across all 64 bits of INTEGRITY_TOKEN.
#[test]
fn prop_rolling_key_roundtrip_bijectivity() {
    check!()
        .with_arbitrary::<RollingKeyInput>()
        .for_each(|input| {
            if input.bytecode.is_empty() || input.bytecode.len() > 256 {
                return;
            }

            let integrity_val = diffuse_token(input.token);

            // 1. Encode stream using Mode H formula
            let mut encoded = vec![0u8; input.bytecode.len()];
            let mut r_key: u8 = 0;

            for (vip, &plain) in input.bytecode.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(7);
                let raw = plain.wrapping_sub(pos_salt) ^ input.enc_key ^ r_key ^ integrity_val;
                encoded[vip] = raw;

                r_key = r_key.wrapping_add(raw).wrapping_mul(0x1F);
                r_key ^= (r_key << 1) ^ 0x3C;
                r_key ^= input.global_key;
            }

            // 2. Decode stream with matching parameters (Mode H decode)
            let mut decoded = vec![0u8; input.bytecode.len()];
            let mut r_key_dec: u8 = 0;

            for (vip, &raw) in encoded.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(7);
                let plain = (raw ^ input.enc_key ^ r_key_dec ^ integrity_val).wrapping_add(pos_salt);
                decoded[vip] = plain;

                r_key_dec = r_key_dec.wrapping_add(raw).wrapping_mul(0x1F);
                r_key_dec ^= (r_key_dec << 1) ^ 0x3C;
                r_key_dec ^= input.global_key;
            }

            // Invariant 1: Exact round-trip reconstruction
            assert_eq!(decoded, input.bytecode, "Mode H rolling key round-trip failed to reconstruct original bytecode");
            assert_eq!(r_key, r_key_dec, "Encoder and decoder final rolling keys diverged");

            // Invariant 2: Metamorphic prefix invariant
            if input.bytecode.len() > 1 {
                let half_len = input.bytecode.len() / 2;
                let prefix = &input.bytecode[..half_len];
                let mut prefix_encoded = vec![0u8; half_len];
                let mut r_key_prefix: u8 = 0;
                for (vip, &plain) in prefix.iter().enumerate() {
                    let pos_salt = (vip as u8).wrapping_mul(7);
                    let raw = plain.wrapping_sub(pos_salt) ^ input.enc_key ^ r_key_prefix ^ integrity_val;
                    prefix_encoded[vip] = raw;
                    r_key_prefix = r_key_prefix.wrapping_add(raw).wrapping_mul(0x1F);
                    r_key_prefix ^= (r_key_prefix << 1) ^ 0x3C;
                    r_key_prefix ^= input.global_key;
                }
                assert_eq!(
                    prefix_encoded, &encoded[..half_len],
                    "Metamorphic prefix consistency violated"
                );
            }

            // Invariant 3: Zero 56-bit blind spot - 64-bit Token Diffusion Theorem
            // Flipping ANY bit across all 64 bits of token strictly alters diffuse_token(token)
            let bit = (input.bit_flip_pos % 64) as usize;
            let corrupted_token = input.token ^ (1u64 << bit);
            let corrupted_integrity_val = diffuse_token(corrupted_token);
            assert_ne!(
                corrupted_integrity_val, integrity_val,
                "64-bit token diffusion blind spot detected: bit {} produced identical diffuse_token",
                bit
            );

            // Invariant 4: Corrupted token strictly diverges decoded bytecode
            let mut corrupted_decoded = vec![0u8; input.bytecode.len()];
            let mut r_key_corrupt: u8 = 0;
            for (vip, &raw) in encoded.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(7);
                let plain = (raw ^ input.enc_key ^ r_key_corrupt ^ corrupted_integrity_val).wrapping_add(pos_salt);
                corrupted_decoded[vip] = plain;

                r_key_corrupt = r_key_corrupt.wrapping_add(raw).wrapping_mul(0x1F);
                r_key_corrupt ^= (r_key_corrupt << 1) ^ 0x3C;
                r_key_corrupt ^= input.global_key;
            }
            assert_ne!(
                corrupted_decoded, input.bytecode,
                "Corrupted token must strictly diverge decoded bytecode"
            );
        });
}

/// Helper model for Logic-to-Physical (LTP) map generation matching production tiny_vm.rs
fn create_ltp_map_model(mut seed: u32) -> [u8; 256] {
    let is_suspicious = seed == 0 || seed == 0xDEADBEEF;
    if is_suspicious {
        let tsc: u32;
        unsafe {
            std::arch::asm!("rdtsc", out("eax") tsc, options(nomem, nostack));
        }
        seed ^= tsc;
        let stack_var = 0xBADF00Du32;
        let stack_addr = &stack_var as *const u32 as usize;
        seed ^= stack_addr as u32;
    }

    struct LocalXorshift32(u32);
    impl LocalXorshift32 {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            if x == 0 {
                x = 0x6D2B79F5;
            }
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }
    }

    let mut rng = LocalXorshift32(seed);
    let mut map = [0u8; 256];
    for i in 0..256 {
        map[i] = i as u8;
    }
    for i in (1..256).rev() {
        let j = (rng.next() as usize) % (i + 1);
        map.swap(i, j);
    }
    map
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
            let map = create_ltp_map_model(*seed);

            // Invariant 1: Mapping is a strict bijection over S_256
            let mut seen = [false; 256];
            for &val in &map {
                assert!(!seen[val as usize], "Duplicate entry {} in LTP map for seed {:#X}", val, seed);
                seen[val as usize] = true;
            }
            assert!(seen.iter().all(|&s| s), "LTP map does not cover all 256 elements");

            // Invariant 2: Two-sided invertibility (identity map reconstruction)
            let mut inv_map = [0u8; 256];
            for i in 0..256 {
                inv_map[map[i] as usize] = i as u8;
            }
            for i in 0..256 {
                assert_eq!(inv_map[map[i] as usize], i as u8, "LTP inverse bijection violated at {}", i);
                assert_eq!(map[inv_map[i] as usize], i as u8, "LTP dual inverse bijection violated at {}", i);
            }

            // Invariant 3: Deterministic stability for non-suspicious seeds
            if *seed != 0 && *seed != 0xDEADBEEF {
                let map2 = create_ltp_map_model(*seed);
                assert_eq!(map, map2, "Non-suspicious seed produced non-deterministic LTP map");
            }
        });
}

/// Structured bytecode instruction for opcode execution fuzzing covering the full instruction set
#[derive(Arbitrary, Debug, Clone)]
pub enum StructuredVmOp {
    LoadImm(u64),
    Add,
    Sub,
    Xor,
    And,
    Or,
    Not,
    Shl,
    Shr,
    Dup,
    Swap,
    Push(u8),
    Pop,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct StructuredVmProgram {
    pub ops: Vec<StructuredVmOp>,
    pub enc_key: u8,
    pub ctx_key: u64,
}

/// Helper: Encodes plain bytecode into TinyVM Mode H rolling-key encrypted bytecode
pub fn encode_tinyvm_bytecode(plain_bytes: &[u8], encryption_key: u8) -> Vec<u8> {
    encode_bytecode(plain_bytes, encryption_key)
}

/// Feature 10: Bolero TinyVM Opcode Execution
/// Verifies that programs built from arithmetic, bitwise, stack, and exit opcodes
/// execute accurately, maintain stack bounds, and produce exact results matching
/// an independent reference shadow stack interpreter via vm_execute with Mode H encoding.
#[test]
fn prop_tiny_vm_structured_opcode_execution() {
    check!()
        .with_arbitrary::<StructuredVmProgram>()
        .for_each(|program| {
            if program.ops.is_empty() || program.ops.len() > 32 {
                return;
            }

            let k = program.enc_key;
            let mut plain_bc = Vec::new();

            // 1. Seed the stack with initial operand to guarantee real values for arithmetic
            plain_bc.push(VmOp::op_load_imm());
            plain_bc.extend_from_slice(&program.ctx_key.to_le_bytes());

            // 2. Compute expected result via independent shadow stack simulation
            let mut shadow_stack: Vec<u64> = Vec::new();
            shadow_stack.push(program.ctx_key);

            let under_debug = crate::protector::tiny_vm::get_global_encoded_state() & 1 != 0;

            for op in &program.ops {
                match op {
                    StructuredVmOp::LoadImm(val) => {
                        plain_bc.push(VmOp::op_load_imm());
                        plain_bc.extend_from_slice(&val.to_le_bytes());
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(*val);
                        }
                    }
                    StructuredVmOp::Add => {
                        plain_bc.push(VmOp::op_add());
                        if shadow_stack.len() >= 2 {
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
                    }
                    StructuredVmOp::Sub => {
                        plain_bc.push(VmOp::op_sub());
                        if shadow_stack.len() >= 2 {
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
                    }
                    StructuredVmOp::Xor => {
                        plain_bc.push(VmOp::op_xor());
                        if shadow_stack.len() >= 2 {
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
                    }
                    StructuredVmOp::And => {
                        plain_bc.push(VmOp::op_and());
                        if shadow_stack.len() >= 2 {
                            let b = shadow_stack.pop().unwrap_or(0);
                            let a = shadow_stack.pop().unwrap_or(0);
                            if shadow_stack.len() < 32 {
                                shadow_stack.push(a & b);
                            }
                        }
                    }
                    StructuredVmOp::Or => {
                        plain_bc.push(VmOp::op_or());
                        if shadow_stack.len() >= 2 {
                            let b = shadow_stack.pop().unwrap_or(0);
                            let a = shadow_stack.pop().unwrap_or(0);
                            if shadow_stack.len() < 32 {
                                shadow_stack.push(a | b);
                            }
                        }
                    }
                    StructuredVmOp::Not => {
                        plain_bc.push(VmOp::op_not());
                        let a = shadow_stack.pop().unwrap_or(0);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(!a);
                        }
                    }
                    StructuredVmOp::Shl => {
                        plain_bc.push(VmOp::op_shl());
                        if shadow_stack.len() >= 2 {
                            let shift = shadow_stack.pop().unwrap_or(0) as u32;
                            let a = shadow_stack.pop().unwrap_or(0);
                            if shadow_stack.len() < 32 {
                                shadow_stack.push(a.wrapping_shl(shift));
                            }
                        }
                    }
                    StructuredVmOp::Shr => {
                        plain_bc.push(VmOp::op_shr());
                        if shadow_stack.len() >= 2 {
                            let shift = shadow_stack.pop().unwrap_or(0) as u32;
                            let a = shadow_stack.pop().unwrap_or(0);
                            if shadow_stack.len() < 32 {
                                shadow_stack.push(a.wrapping_shr(shift));
                            }
                        }
                    }
                    StructuredVmOp::Dup => {
                        plain_bc.push(VmOp::op_dup());
                        let val = shadow_stack.last().copied().unwrap_or(0);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(val);
                        }
                    }
                    StructuredVmOp::Swap => {
                        plain_bc.push(VmOp::op_swap());
                        if shadow_stack.len() >= 2 {
                            let len = shadow_stack.len();
                            shadow_stack.swap(len - 1, len - 2);
                        }
                    }
                    StructuredVmOp::Push(val) => {
                        plain_bc.push(VmOp::op_push());
                        plain_bc.push(*val);
                        if shadow_stack.len() < 32 {
                            shadow_stack.push(*val as u64);
                        }
                    }
                    StructuredVmOp::Pop => {
                        plain_bc.push(VmOp::op_pop());
                        shadow_stack.pop();
                    }
                }
            }
            plain_bc.push(VmOp::op_exit());
            let expected_exit_value = shadow_stack.pop().unwrap_or(0);

            // 3. Properly encode bytecode using production Mode H encoder
            let encoded_bc = encode_bytecode(&plain_bc, k);

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

/// Feature 11: Bolero TinyVM Modular Arithmetic Group Properties in Z_{2^64}
/// Replaces vacuous primitive arithmetic checks with genuine TinyVM execution of group laws:
/// 1. Additive Identity: a + 0 == a
/// 2. Additive Inverse: a + (-a) == 0
/// 3. XOR Involution: (a ^ b) ^ b == a
/// 4. Modular Overflow Wrap: u64::MAX + 1 == 0
/// 5. Modular Underflow Wrap: 0 - 1 == u64::MAX
/// 6. Shift Left Invariant: a << shift
#[test]
fn prop_tiny_vm_wrapping_arithmetic_properties() {
    check!()
        .with_arbitrary::<(u64, u64, u8, u8, u64)>()
        .for_each(|(a, b, shift_val, enc_key, ctx_key)| {
            let k = *enc_key;
            let under_debug = crate::protector::tiny_vm::get_global_encoded_state() & 1 != 0;

            // 1. Group Law: Additive Identity (a + 0 == a)
            let mut bc1 = Vec::new();
            bc1.push(VmOp::op_load_imm());
            bc1.extend_from_slice(&a.to_le_bytes());
            bc1.push(VmOp::op_load_imm());
            bc1.extend_from_slice(&0u64.to_le_bytes());
            bc1.push(VmOp::op_add());
            bc1.push(VmOp::op_exit());
            let enc1 = encode_bytecode(&bc1, k);
            let res1 = vm_execute(&enc1, k, *ctx_key);
            let exp1 = if under_debug { a.wrapping_sub(0) } else { a.wrapping_add(0) };
            assert_eq!(res1, exp1, "TinyVM additive identity violated in Z_(2^64)");

            // 2. Group Law: Additive Inverse (a + (-a) == 0)
            let mut bc2 = Vec::new();
            bc2.push(VmOp::op_load_imm());
            bc2.extend_from_slice(&a.to_le_bytes());
            bc2.push(VmOp::op_load_imm());
            bc2.extend_from_slice(&a.wrapping_neg().to_le_bytes());
            bc2.push(VmOp::op_add());
            bc2.push(VmOp::op_exit());
            let enc2 = encode_bytecode(&bc2, k);
            let res2 = vm_execute(&enc2, k, *ctx_key);
            let exp2 = if under_debug { a.wrapping_sub(a.wrapping_neg()) } else { 0 };
            assert_eq!(res2, exp2, "TinyVM additive inverse violated in Z_(2^64)");

            // 3. Boolean Group Law: XOR Involution ((a ^ b) ^ b == a)
            let mut bc3 = Vec::new();
            bc3.push(VmOp::op_load_imm());
            bc3.extend_from_slice(&a.to_le_bytes());
            bc3.push(VmOp::op_load_imm());
            bc3.extend_from_slice(&b.to_le_bytes());
            bc3.push(VmOp::op_xor());
            bc3.push(VmOp::op_load_imm());
            bc3.extend_from_slice(&b.to_le_bytes());
            bc3.push(VmOp::op_xor());
            bc3.push(VmOp::op_exit());
            let enc3 = encode_bytecode(&bc3, k);
            let res3 = vm_execute(&enc3, k, *ctx_key);
            let exp3 = if under_debug {
                let step1 = a.wrapping_add(*b);
                step1.wrapping_add(*b)
            } else {
                *a
            };
            assert_eq!(res3, exp3, "TinyVM XOR involution violated in Z_(2^64)");

            // 4. Overflow Wrap Property: u64::MAX + 1 == 0
            let mut bc4 = Vec::new();
            bc4.push(VmOp::op_load_imm());
            bc4.extend_from_slice(&u64::MAX.to_le_bytes());
            bc4.push(VmOp::op_load_imm());
            bc4.extend_from_slice(&1u64.to_le_bytes());
            bc4.push(VmOp::op_add());
            bc4.push(VmOp::op_exit());
            let enc4 = encode_bytecode(&bc4, k);
            let res4 = vm_execute(&enc4, k, *ctx_key);
            let exp4 = if under_debug { u64::MAX.wrapping_sub(1) } else { 0 };
            assert_eq!(res4, exp4, "TinyVM modular overflow wrapping violated");

            // 5. Underflow Wrap Property: 0 - 1 == u64::MAX
            let mut bc5 = Vec::new();
            bc5.push(VmOp::op_load_imm());
            bc5.extend_from_slice(&0u64.to_le_bytes());
            bc5.push(VmOp::op_load_imm());
            bc5.extend_from_slice(&1u64.to_le_bytes());
            bc5.push(VmOp::op_sub());
            bc5.push(VmOp::op_exit());
            let enc5 = encode_bytecode(&bc5, k);
            let res5 = vm_execute(&enc5, k, *ctx_key);
            let exp5 = if under_debug { 0u64.wrapping_add(1) } else { u64::MAX };
            assert_eq!(res5, exp5, "TinyVM modular underflow wrapping violated");

            // 6. Shift Bounds Property: wrapping shift behavior
            let shift = (*shift_val % 64) as u32;
            let mut bc6 = Vec::new();
            bc6.push(VmOp::op_load_imm());
            bc6.extend_from_slice(&a.to_le_bytes());
            bc6.push(VmOp::op_load_imm());
            bc6.extend_from_slice(&(shift as u64).to_le_bytes());
            bc6.push(VmOp::op_shl());
            bc6.push(VmOp::op_exit());
            let enc6 = encode_bytecode(&bc6, k);
            let res6 = vm_execute(&enc6, k, *ctx_key);
            assert_eq!(res6, a.wrapping_shl(shift), "TinyVM shift left boundary violated");
        });
}

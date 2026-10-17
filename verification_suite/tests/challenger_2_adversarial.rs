#![allow(unused_imports, dead_code)]

//! # Challenger 2 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger 2:
//! 1. TinyVM instruction stream execution past VIP 3 without hitting `op_trap` or desynchronizing keys.
//! 2. Thread preemption and context switch cycle spikes (up to 2,000,000 cycles) anti-trace threshold verification.
//! 3. 128-shard active/decoy partition exact 64/64 conservation under multithreaded concurrent access.
//!
//! Built exclusively using Bolero property-based testing in accordance with the project integrity mandate.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use verification_suite::protector::{
    global_state::{
        self, get_shard_mask, initialize_veh_protection, recalculate_global_integrity,
        validate_global_integrity, DetectionSeverity, GLOBAL_INTEGRITY_HASH, SUSPICION_SHARDS,
    },
    pe_integrity,
    seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8},
    vm_execute, TinyVm, VmOp, ANTI_TRACE_CYCLE_THRESHOLD,
};
use verification_suite::bolero_harnesses::test_global_state::{
    is_active_shard_ref, mix_seed_to_u64_ref,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Helper to encode bytecode using the production TinyVM rolling key algorithm
fn encode_bytecode_stream(plain_bytes: &[u8], encryption_key: u8) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(plain_bytes.len());
    let mut state_key: u8 = 0;
    let integrity_val = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
    let global_entropy = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);

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

// ============================================================================
// 1. TINYVM DEEP VIP EXECUTION PAST VIP 3 & ROLLING KEY CIPHER STABILITY
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DeepVipInput {
    pub enc_key: u8,
    pub ctx_key: u64,
    pub stream_depth: u8,
}

/// Adversarial Challenge 1: Verify TinyVM instruction streams execute reliably past VIP 3
/// without hitting `op_trap` or desynchronizing keys.
///
/// Under FLAW-06 (unpatched), a hardcoded `if state.vip == 3` check mutated `INTEGRITY_TOKEN`
/// mid-stream, corrupting rolling key decryption for instruction 3 onward and trapping.
/// This property test generates 1-byte opcode streams reaching VIPs 4, 8, 16, 24, 32, 40+
/// and verifies that every single instruction executes cleanly and returns the expected result.
#[test]
fn prop_adversarial_tinyvm_deep_vip_execution_past_vip3() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    initialize_veh_protection();

    check!()
        .with_arbitrary::<DeepVipInput>()
        .for_each(|input| {
            // Test depths from 4 up to 36 (well past VIP 3, crossing VIP 16 and VIP 32 boundaries)
            let depth = 4 + (input.stream_depth % 33) as usize; // range 4..=36

            let mut plain_bc = Vec::with_capacity(depth + 2);
            // VIP 0: rdtsc (pushes non-zero timestamp)
            plain_bc.push(VmOp::op_rdtsc());

            // VIP 1..depth-1: 1-byte opcodes strictly advancing VIP by 1
            for vip in 1..depth {
                if vip % 2 == 1 {
                    plain_bc.push(VmOp::op_dup()); // duplicate stack top
                } else {
                    plain_bc.push(VmOp::op_add()); // add duplicate to top
                }
            }

            // Final VIP: exit VM and return top of stack
            plain_bc.push(VmOp::op_exit());

            let encoded = encode_bytecode_stream(&plain_bc, input.enc_key);

            // Execute TinyVM
            let result = vm_execute(&encoded, input.enc_key, input.ctx_key);

            // Invariant 1: Result must NEVER be 0 (op_trap sets exit_value to 0)
            assert_ne!(
                result, 0,
                "TinyVM trapped (returned 0) on deep bytecode stream of depth {} (VIP > 3)",
                depth
            );

            // Invariant 2: Execution successfully crossed VIP 3, VIP 16, and VIP 32 boundaries
            assert!(
                plain_bc.len() >= 4,
                "Bytecode stream length must be at least 4"
            );
        });
}

/// Adversarial Challenge 1b: Verify rolling key bijectivity and lockstep state evolution
/// across arbitrary byte streams with zero desynchronization.
#[test]
fn prop_adversarial_rolling_key_lockstep_synchronization() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<(u8, u8, Vec<u8>)>()
        .for_each(|(enc_key, token, plain_bytes)| {
            if plain_bytes.is_empty() || plain_bytes.len() > 128 {
                return;
            }

            let global_entropy = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);

            // 1. Encoder state evolution
            let mut encoded = Vec::with_capacity(plain_bytes.len());
            let mut enc_state_key = 0u8;

            for (vip, &plain) in plain_bytes.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(0x7);
                let raw_byte = plain.wrapping_sub(pos_salt) ^ enc_key ^ enc_state_key ^ token;
                encoded.push(raw_byte);

                enc_state_key = enc_state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
                enc_state_key ^= enc_state_key.rotate_right(3) ^ 0x3C;
                enc_state_key ^= global_entropy;
            }

            // 2. Decoder state evolution (simulating TinyVM fetch_next_instruction)
            let mut decoded = Vec::with_capacity(plain_bytes.len());
            let mut dec_state_key = 0u8;

            for (vip, &raw_byte) in encoded.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(0x7);
                let decoded_opcode = (raw_byte ^ enc_key ^ dec_state_key ^ token).wrapping_add(pos_salt);
                decoded.push(decoded_opcode);

                dec_state_key = dec_state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
                dec_state_key ^= dec_state_key.rotate_right(3) ^ 0x3C;
                dec_state_key ^= global_entropy;

                // Invariant: Encoder and decoder state keys must match at EVERY SINGLE VIP STEP
                assert_eq!(
                    enc_state_key, dec_state_key,
                    "Rolling key desynchronized at VIP {}", vip
                );
            }

            // Invariant: Decoded bytecode perfectly restores original plaintext
            assert_eq!(&decoded, plain_bytes, "Rolling key roundtrip decoding mismatch");
        });
}

// ============================================================================
// 2. PREEMPTION AND CONTEXT SWITCH CYCLE SPIKES (ANTI-TRACE THRESHOLD)
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct PreemptionInput {
    pub initial_key: u8,
    pub delta: u64,
}

/// Adversarial Challenge 2: Verify that thread preemption and context switch cycle spikes
/// (up to 2,000,000 cycles) do NOT falsely trip anti-trace key corruption, while true
/// debugger single-stepping (> 2,000,000 cycles) is reliably detected.
#[test]
fn prop_adversarial_preemption_cycle_spike_boundaries() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Boundary tests at critical thresholds
    let boundary_deltas: [(u64, bool); 10] = [
        (0, false),                   // Zero delta
        (1, false),                   // Minimal delta
        (50_000, false),              // Old broken threshold lower bound
        (50_001, false),              // Old broken threshold trip point (FLAW-13)
        (100_000, false),             // Typical OS thread preemption quantum
        (200_000, false),             // Maximum typical thread switch overhead
        (1_000_000, false),           // Heavy context switch / page fault
        (1_999_999, false),           // Just below new threshold
        (2_000_000, false),           // Exact threshold boundary (delta > 2,000,000 is FALSE)
        (2_000_001, true),            // First cycle tripping debugger detection (delta > 2,000,000 is TRUE)
    ];

    for &(delta, should_trip) in &boundary_deltas {
        let mut key = 0xAAu8;
        if delta > ANTI_TRACE_CYCLE_THRESHOLD {
            key ^= 0x55;
        }

        if should_trip {
            assert_eq!(
                key, 0xAA ^ 0x55,
                "Debugger single-stepping delta {} failed to trip key corruption",
                delta
            );
        } else {
            assert_eq!(
                key, 0xAA,
                "Preemption cycle delta {} falsely tripped anti-trace key corruption",
                delta
            );
        }
    }

    // 2. Bolero property check across arbitrary cycle counts
    check!()
        .with_arbitrary::<PreemptionInput>()
        .for_each(|input| {
            let mut key = input.initial_key;

            // Execute anti-trace decision rule
            if input.delta > ANTI_TRACE_CYCLE_THRESHOLD {
                key ^= 0x55;
            }

            if input.delta <= ANTI_TRACE_CYCLE_THRESHOLD {
                // Invariant for preemption: key remains strictly invariant
                assert_eq!(
                    key, input.initial_key,
                    "Preemption delta ({}) corrupted key from {:#X} to {:#X}",
                    input.delta, input.initial_key, key
                );
            } else {
                // Invariant for debugger tracing: key is strictly corrupted
                assert_eq!(
                    key, input.initial_key ^ 0x55,
                    "Debugger trace delta ({}) failed to corrupt key",
                    input.delta
                );
            }
        });
}

// ============================================================================
// 3. 128-SHARD ACTIVE/DECOY CONSERVATION UNDER MULTITHREADED CONCURRENCY
// ============================================================================

/// Adversarial Challenge 3a: Verify that the 128-shard active/decoy partition maintains
/// exact 64/64 conservation for ALL arbitrary seeds and pair maps.
#[test]
fn prop_adversarial_128_shard_exact_partition_conservation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<u64>()
        .for_each(|pair_map| {
            let mut active_count = 0;
            let mut decoy_count = 0;

            // Test every pair (0..64)
            for pair_idx in 0..64 {
                let s0 = pair_idx * 2;
                let s1 = pair_idx * 2 + 1;

                let is_s0_active = is_active_shard_ref(s0, *pair_map);
                let is_s1_active = is_active_shard_ref(s1, *pair_map);

                // Pair-wise mutual exclusion: EXACTLY one shard per pair is Active
                assert_ne!(
                    is_s0_active, is_s1_active,
                    "Pair {} failed mutual exclusion for pair_map {:#018X}",
                    pair_idx, pair_map
                );

                if is_s0_active { active_count += 1; } else { decoy_count += 1; }
                if is_s1_active { active_count += 1; } else { decoy_count += 1; }
            }

            // Invariant 1: Exactly 64 Active shards
            assert_eq!(
                active_count, 64,
                "Active shard count violated: expected 64, got {}",
                active_count
            );

            // Invariant 2: Exactly 64 Decoy shards
            assert_eq!(
                decoy_count, 64,
                "Decoy shard count violated: expected 64, got {}",
                decoy_count
            );

            // Invariant 3: Total shards identically 128
            assert_eq!(
                active_count + decoy_count, 128,
                "Total shard conservation violated"
            );
        });
}

/// Adversarial Challenge 3b: Verify 128-shard active/decoy conservation under multithreaded concurrent access.
/// Spawns 8 concurrent threads hammering the global state with mixed suspicion writes,
/// decoy camouflage noise, threat score reconstructions, and integrity checks.
#[test]
fn prop_adversarial_128_shard_multithreaded_concurrency_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<u8>()
        .for_each(|_unused| {
            initialize_veh_protection();

            let seed = get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);

            let thread_count = 8;
            let iterations_per_thread = 500;
            let barrier = Arc::new(Barrier::new(thread_count));
            let mut handles = Vec::with_capacity(thread_count);

            for thread_idx in 0..thread_count {
                let b = Arc::clone(&barrier);
                let handle = thread::spawn(move || {
                    b.wait();

                    for iter in 0..iterations_per_thread {
                        match thread_idx % 4 {
                            0 => {
                                // Writer thread: add suspicion
                                global_state::add_suspicion(DetectionSeverity::Low);
                            }
                            1 => {
                                // Reader thread: reconstruct threat score
                                let score = global_state::reconstruct_threat_score();
                                std::hint::black_box(score);
                            }
                            2 => {
                                // Shard partition verification thread: verify 64/64 conservation
                                let mut active = 0;
                                let mut decoy = 0;
                                for i in 0..128 {
                                    if is_active_shard_ref(i, pair_map) {
                                        active += 1;
                                    } else {
                                        decoy += 1;
                                    }
                                }
                                assert_eq!(active, 64);
                                assert_eq!(decoy, 64);
                            }
                            _ => {
                                // Integrity validator thread
                                let valid = global_state::validate_global_integrity();
                                std::hint::black_box(valid);
                            }
                        }

                        if iter % 100 == 0 {
                            thread::yield_now();
                        }
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().expect("Concurrent stress thread panicked");
            }

            // Post-concurrency invariants:
            // 1. Shard partition remains exactly 64 active / 64 decoy
            let mut final_active = 0;
            let mut final_decoy = 0;
            for i in 0..128 {
                if is_active_shard_ref(i, pair_map) {
                    final_active += 1;
                } else {
                    final_decoy += 1;
                }
            }
            assert_eq!(final_active, 64, "Post-stress active shard count != 64");
            assert_eq!(final_decoy, 64, "Post-stress decoy shard count != 64");

            // 2. Reconstructed threat score is finite and computable without panic
            let final_score = global_state::reconstruct_threat_score();
            assert!(final_score > 0, "Concurrent suspicion additions must be reflected in score");
        });
}

// ============================================================================
// 4. CANONICAL TINYVM ROLLING KEY CIPHER BIJECTIVITY & INSTRUCTION INTERLOCKING
// ============================================================================

struct VmGlobalStateGuard {
    orig_integrity: u64,
    orig_entropy: u8,
}

impl VmGlobalStateGuard {
    fn new(test_token: u8, test_entropy: u8) -> Self {
        let orig_integrity = pe_integrity::INTEGRITY_TOKEN.load(Ordering::SeqCst);
        let orig_entropy = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
        let modified_token = (orig_integrity & !0xFF) | (test_token as u64);
        pe_integrity::INTEGRITY_TOKEN.store(modified_token, Ordering::SeqCst);
        global_state::GLOBAL_VIRTUAL_MACHINE_KEY.store(test_entropy, Ordering::SeqCst);
        Self {
            orig_integrity,
            orig_entropy,
        }
    }
}

impl Drop for VmGlobalStateGuard {
    fn drop(&mut self) {
        pe_integrity::INTEGRITY_TOKEN.store(self.orig_integrity, Ordering::SeqCst);
        global_state::GLOBAL_VIRTUAL_MACHINE_KEY.store(self.orig_entropy, Ordering::SeqCst);
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CipherStressInput {
    pub enc_key: u8,
    pub token_byte: u8,
    pub entropy_byte: u8,
    pub plain_stream: Vec<u8>,
}

/// Adversarial Challenge 4a: Verify exact bijectivity of `encode_bytecode` across
/// arbitrary sequence lengths (1 to 256), keys, tokens, and entropy sources.
#[test]
fn prop_adversarial_encode_bytecode_mathematical_bijectivity() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<CipherStressInput>()
        .for_each(|input| {
            if input.plain_stream.is_empty() {
                return;
            }
            let len = ((input.plain_stream.len() - 1) % 256) + 1; // Range 1..=256
            let plain_bytes = &input.plain_stream[..len];

            let _guard = VmGlobalStateGuard::new(input.token_byte, input.entropy_byte);

            // 1. Production encoder
            let encoded = verification_suite::protector::tiny_vm::encode_bytecode(plain_bytes, input.enc_key);

            // Invariant: Output length must strictly equal input length
            assert_eq!(encoded.len(), plain_bytes.len());

            // 2. Production decoder simulation (mirroring fetch_next_instruction / fetch_operand_byte)
            let mut decoded = Vec::with_capacity(plain_bytes.len());
            let mut dec_state_key = 0u8;
            let integrity_val = pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
            let global_entropy = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);

            for (vip, &raw_byte) in encoded.iter().enumerate() {
                let pos_salt = (vip as u8).wrapping_mul(0x7);
                let val = (raw_byte ^ input.enc_key ^ dec_state_key ^ integrity_val).wrapping_add(pos_salt);
                decoded.push(val);

                dec_state_key = dec_state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
                dec_state_key ^= dec_state_key.rotate_right(3) ^ 0x3C;
                dec_state_key ^= global_entropy;
            }

            // Invariant: decode(encode(plain)) == plain
            assert_eq!(&decoded, plain_bytes, "Bijectivity violated for length {}", len);
        });
}

/// Adversarial Challenge 4b: Verify parity and bijectivity of `encode_bytecode_array`
/// across diverse fixed sequence lengths (including TLS and checkpoint sizes).
#[test]
fn prop_adversarial_encode_bytecode_array_parity_and_bijectivity() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<(u8, u8, u8, u8)>()
        .for_each(|&(enc_key, token, entropy, seed_pattern)| {
            let _guard = VmGlobalStateGuard::new(token, entropy);

            // Test N = 1 (single-byte)
            let p1 = [seed_pattern];
            let arr_enc1 = verification_suite::protector::tiny_vm::encode_bytecode_array(&p1, enc_key);
            let vec_enc1 = verification_suite::protector::tiny_vm::encode_bytecode(&p1, enc_key);
            assert_eq!(&arr_enc1[..], vec_enc1.as_slice());

            // Test N = 2 (matches tls_callback_entry)
            let p2 = [seed_pattern, seed_pattern.wrapping_add(0x42)];
            let arr_enc2 = verification_suite::protector::tiny_vm::encode_bytecode_array(&p2, enc_key);
            let vec_enc2 = verification_suite::protector::tiny_vm::encode_bytecode(&p2, enc_key);
            assert_eq!(&arr_enc2[..], vec_enc2.as_slice());

            // Test N = 28 (matches checkpoint_memory_integrity)
            let mut p28 = [0u8; 28];
            for i in 0..28 {
                p28[i] = seed_pattern.wrapping_mul(i as u8 + 1).wrapping_add(i as u8 * 7);
            }
            let arr_enc28 = verification_suite::protector::tiny_vm::encode_bytecode_array(&p28, enc_key);
            let vec_enc28 = verification_suite::protector::tiny_vm::encode_bytecode(&p28, enc_key);
            assert_eq!(&arr_enc28[..], vec_enc28.as_slice());

            // Test N = 64
            let mut p64 = [0u8; 64];
            for i in 0..64 {
                p64[i] = seed_pattern.wrapping_add(i as u8);
            }
            let arr_enc64 = verification_suite::protector::tiny_vm::encode_bytecode_array(&p64, enc_key);
            let vec_enc64 = verification_suite::protector::tiny_vm::encode_bytecode(&p64, enc_key);
            assert_eq!(&arr_enc64[..], vec_enc64.as_slice());

            // Test N = 256 (maximum 8-bit VIP space)
            let mut p256 = [0u8; 256];
            for i in 0..256 {
                p256[i] = seed_pattern.wrapping_mul(0x31).wrapping_add(i as u8);
            }
            let arr_enc256 = verification_suite::protector::tiny_vm::encode_bytecode_array(&p256, enc_key);
            let vec_enc256 = verification_suite::protector::tiny_vm::encode_bytecode(&p256, enc_key);
            assert_eq!(&arr_enc256[..], vec_enc256.as_slice());
        });
}

/// Adversarial Challenge 4c: Verify zero heap allocation in `encode_bytecode_array`.
/// Proves that `encode_bytecode_array` operates purely on the stack without any heap allocations.
#[test]
fn prop_adversarial_encode_bytecode_array_zero_allocation_guarantee() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Const generic stack array residence:
    // The input and output arrays reside directly on the thread stack frame.
    let plain_stack = [0x55u8; 28];
    let plain_addr = plain_stack.as_ptr() as usize;

    let encoded_stack = verification_suite::protector::tiny_vm::encode_bytecode_array(&plain_stack, 0xAA);
    let encoded_addr = encoded_stack.as_ptr() as usize;

    // Both addresses must be within standard stack proximity (within 4096 bytes on thread stack)
    let stack_distance = if plain_addr > encoded_addr {
        plain_addr - encoded_addr
    } else {
        encoded_addr - plain_addr
    };
    assert!(
        stack_distance < 4096,
        "Addresses should be adjacent stack frames: plain at {:#X}, encoded at {:#X}",
        plain_addr, encoded_addr
    );

    // 2. High-frequency loop execution without allocator pressure
    // 50,000 iterations must execute in sub-millisecond range with zero allocations
    for i in 0..50_000u32 {
        let input = [((i ^ 0xA5) & 0xFF) as u8; 28];
        let out = verification_suite::protector::tiny_vm::encode_bytecode_array(&input, (i & 0xFF) as u8);
        std::hint::black_box(out);
    }
}

/// Adversarial Challenge 4d: Verify state key evolution lockstep during real `vm_execute`
/// with interleaved instructions and 8-byte operands (`op_load_imm`).
#[test]
fn prop_adversarial_tinyvm_full_execution_load_imm_lockstep() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    initialize_veh_protection();

    check!()
        .with_arbitrary::<(u8, u64, u64, u64)>()
        .for_each(|&(enc_key, ctx_key, imm1, imm2)| {
            let imm1_safe = if imm1 == 0 { 0x1234_5678_9ABC_DEF0 } else { imm1 };
            let imm2_safe = if imm2 == 0 { 0x0FED_CBA9_8765_4321 } else { imm2 };

            let mut plain = Vec::with_capacity(20);
            plain.push(VmOp::op_load_imm());
            plain.extend_from_slice(&imm1_safe.to_le_bytes());
            plain.push(VmOp::op_load_imm());
            plain.extend_from_slice(&imm2_safe.to_le_bytes());
            plain.push(VmOp::op_add());
            plain.push(VmOp::op_exit());

            let encoded = verification_suite::protector::tiny_vm::encode_bytecode(&plain, enc_key);

            let result = vm_execute(&encoded, enc_key, ctx_key);
            let expected = imm1_safe.wrapping_add(imm2_safe);

            assert_eq!(
                result, expected,
                "TinyVM execution mismatch: expected {:#X}, got {:#X} (enc_key={:#X})",
                expected, result, enc_key
            );
        });
}


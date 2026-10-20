#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M2_3 Stress Test Suite
//!
//! Empirical adversarial evaluation for Milestone M2 (Remediation Iteration 2):
//! 1. String Decryption across Macro-generated strings (`dynamic_str!`, `enc_string!`, `enc_str!`)
//!    and legacy/modern manual bytecodes.
//! 2. Clean State (`POISON_SEED = 0` and `POISON_SEED = seed ^ 0xCAFEBABE1337BEEF`) vs
//!    Poisoned State (`POISON_SEED = 0xDEADBEEF` and perturbed seeds).
//! 3. Two-phase execution fallback (Mode H -> Mode L upon trap).
//! 4. Mathematical invariants of `anti_trace_mutate_key` and execution budget `MAX_VM_STEPS`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use verification_suite::protector::{
    global_state::{self, POISON_SEED, GLOBAL_VIRTUAL_MACHINE_KEY},
    seed_orchestrator::get_dynamic_seed,
    pe_integrity::{self, INTEGRITY_TOKEN},
    tiny_vm::{
        anti_trace_mutate_key, diffuse_token, encode_bytecode, is_anti_trace_heartbeat_active,
        is_environment_poisoned, vm_execute, TinyVm, VmOp,
    },
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// RAII Guard to safely isolate and restore POISON_SEED across tests
struct PoisonSeedGuard {
    original: u64,
}

impl PoisonSeedGuard {
    fn new() -> Self {
        Self {
            original: POISON_SEED.load(Ordering::SeqCst),
        }
    }
}

impl Drop for PoisonSeedGuard {
    fn drop(&mut self) {
        POISON_SEED.store(self.original, Ordering::SeqCst);
    }
}

/// RAII Guard to safely isolate and restore INTEGRITY_TOKEN across tests
struct IntegrityTokenGuard {
    original: u64,
}

impl IntegrityTokenGuard {
    fn new() -> Self {
        Self {
            original: INTEGRITY_TOKEN.load(Ordering::SeqCst),
        }
    }
}

impl Drop for IntegrityTokenGuard {
    fn drop(&mut self) {
        INTEGRITY_TOKEN.store(self.original, Ordering::SeqCst);
    }
}

/// Helper to build manual legacy Mode L encoded bytecode
fn encode_manual_legacy(plain_bc: &[u8], enc_key: u8) -> Vec<u8> {
    let token_raw = INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
    let global_entropy = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);

    let mut encoded = Vec::with_capacity(plain_bc.len());
    let mut state_key = 0u8;

    for (vip, &plain) in plain_bc.iter().enumerate() {
        let pos_salt = (vip as u8).wrapping_mul(0x7);
        let raw_byte = plain.wrapping_sub(pos_salt) ^ enc_key ^ state_key ^ token_raw;
        encoded.push(raw_byte);

        state_key = state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
        state_key ^= state_key.rotate_right(3) ^ 0x3C;
        state_key ^= global_entropy;
    }
    encoded
}

// ============================================================================
// 1. STRING DECRYPTION ADVERSARIAL STRESS TESTS
// ============================================================================

#[test]
fn test_adversarial_macro_string_decryption_edge_cases() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = PoisonSeedGuard::new();
    POISON_SEED.store(0, Ordering::SeqCst);

    // 1. Basic ASCII strings
    let s_hello = fuckDebug::enc_string!("Hello, World!");
    assert_eq!(String::from_utf8_lossy(&s_hello), "Hello, World!");

    // 2. Single char
    let s_single = fuckDebug::enc_string!("X");
    assert_eq!(String::from_utf8_lossy(&s_single), "X");

    // 3. Empty string
    let s_empty = fuckDebug::enc_string!("");
    assert_eq!(String::from_utf8_lossy(&s_empty), "");

    // 4. Multi-byte UTF-8 & Emojis
    let s_crab = fuckDebug::enc_string!("🦀 Rust Anti-Debug 🚀");
    assert_eq!(String::from_utf8_lossy(&s_crab), "🦀 Rust Anti-Debug 🚀");

    // 5. Control chars and special symbols
    let s_special = fuckDebug::enc_string!("Line1\nLine2\tTabbed\r\0NullInside");
    let decoded = String::from_utf8_lossy(&s_special).into_owned();
    assert_eq!(decoded, "Line1\nLine2\tTabbed\r\0NullInside");

    // 6. Long string (>100 bytes)
    let s_long = fuckDebug::enc_string!("This is a long string designed to test that buffer encryption and reconstruction handles multi-stage iterations and larger stack buffers without truncation or buffer corruption.");
    assert_eq!(
        String::from_utf8_lossy(&s_long),
        "This is a long string designed to test that buffer encryption and reconstruction handles multi-stage iterations and larger stack buffers without truncation or buffer corruption."
    );
}

#[test]
fn test_adversarial_manual_bytecode_mode_h_and_legacy_fallback() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = PoisonSeedGuard::new();
    let _token_guard = IntegrityTokenGuard::new();

    POISON_SEED.store(0, Ordering::SeqCst);
    INTEGRITY_TOKEN.store(0xCAFEBABE1337BEEF, Ordering::SeqCst);

    let enc_key = 0x5Au8;

    // Test 1: Arithmetic sequence in Modern Mode H (using encode_bytecode)
    // [load_imm 123, load_imm 456, add, exit] -> 579
    let mut plain_h = Vec::new();
    plain_h.push(VmOp::op_load_imm());
    plain_h.extend_from_slice(&(123u64.to_le_bytes()));
    plain_h.push(VmOp::op_load_imm());
    plain_h.extend_from_slice(&(456u64.to_le_bytes()));
    plain_h.push(VmOp::op_add());
    plain_h.push(VmOp::op_exit());

    let encoded_h = encode_bytecode(&plain_h, enc_key);
    let result_h = vm_execute(&encoded_h, enc_key, 0);
    assert_eq!(result_h, 579, "Modern Mode H execution must compute 123 + 456 = 579");

    // Test 2: Arithmetic sequence in Legacy Mode L (encoded with legacy rotation)
    // [load_imm 100, load_imm 250, add, exit] -> 350
    let mut plain_l = Vec::new();
    plain_l.push(VmOp::op_load_imm());
    plain_l.extend_from_slice(&(100u64.to_le_bytes()));
    plain_l.push(VmOp::op_load_imm());
    plain_l.extend_from_slice(&(250u64.to_le_bytes()));
    plain_l.push(VmOp::op_add());
    plain_l.push(VmOp::op_exit());

    let encoded_l = encode_manual_legacy(&plain_l, enc_key);
    let result_l = vm_execute(&encoded_l, enc_key, 0);
    assert_eq!(result_l, 350, "Legacy Mode L fallback must compute 100 + 250 = 350");

    // Test 3: Legacy jumping bytecode (Mode L fallback must also synchronize jump keys)
    // [load_imm 0, jz target(vip 14), load_imm 999, exit, target: load_imm 777, exit] -> 777
    let mut jump_l = Vec::new();
    jump_l.push(VmOp::op_load_imm());
    jump_l.extend_from_slice(&(0u64.to_le_bytes())); // vip 0..9
    jump_l.push(VmOp::op_jz());                      // vip 9
    jump_l.push(21u8);                               // target operand: vip 10 -> jumps to vip 21
    jump_l.push(VmOp::op_load_imm());                // vip 11
    jump_l.extend_from_slice(&(999u64.to_le_bytes())); // vip 12..20
    jump_l.push(VmOp::op_exit());                    // vip 20
    // vip 21 target:
    jump_l.push(VmOp::op_load_imm());                // vip 21
    jump_l.extend_from_slice(&(777u64.to_le_bytes())); // vip 22..30
    jump_l.push(VmOp::op_exit());                    // vip 30

    let encoded_jump_l = encode_manual_legacy(&jump_l, enc_key);
    let result_jump_l = vm_execute(&encoded_jump_l, enc_key, 0);
    assert_eq!(result_jump_l, 777, "Legacy jump must execute target at vip=21 and return 777");
}

// ============================================================================
// 2. CLEAN VS POISONED STATE STRESS TESTS
// ============================================================================

#[test]
fn test_adversarial_clean_vs_poisoned_environment_distinction() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = PoisonSeedGuard::new();

    let dynamic_seed = get_dynamic_seed() as u64;
    let clean_veh_seed = 0xCAFEBABE1337BEEF_u64 ^ dynamic_seed;

    // Case A: Clean Uninitialized State (POISON_SEED = 0)
    POISON_SEED.store(0, Ordering::SeqCst);
    assert!(!is_environment_poisoned(), "POISON_SEED = 0 must NOT be poisoned");

    let s1 = fuckDebug::enc_string!("Clean uninitialized");
    assert_eq!(String::from_utf8_lossy(&s1), "Clean uninitialized");

    // Case B: Clean Initialized VEH State (POISON_SEED = seed ^ 0xCAFEBABE1337BEEF)
    POISON_SEED.store(clean_veh_seed, Ordering::SeqCst);
    assert!(
        !is_environment_poisoned(),
        "POISON_SEED matching clean_veh_seed must NOT be considered poisoned"
    );

    let s2 = fuckDebug::enc_string!("Clean initialized");
    assert_eq!(String::from_utf8_lossy(&s2), "Clean initialized");

    // Case C: Active Debugger Poisoning (POISON_SEED = 0xDEADBEEF)
    POISON_SEED.store(0xDEADBEEF, Ordering::SeqCst);
    assert!(
        is_environment_poisoned(),
        "POISON_SEED = 0xDEADBEEF MUST be identified as poisoned"
    );

    // Verify vm_execute aborts and returns 0 under poisoned state
    let mut plain = Vec::new();
    plain.push(VmOp::op_load_imm());
    plain.extend_from_slice(&(42u64.to_le_bytes()));
    plain.push(VmOp::op_exit());
    let enc_bytes = encode_bytecode(&plain, 0x33);

    let res_poisoned = vm_execute(&enc_bytes, 0x33, 0);
    assert_eq!(res_poisoned, 0, "vm_execute must return 0 when environment is poisoned");

    // Verify dynamic_str! returns decoy string under poisoned state
    let s_poisoned = fuckDebug::enc_string!("TopSecretSecret");
    let decrypted_poisoned = String::from_utf8_lossy(&s_poisoned);
    assert_ne!(
        decrypted_poisoned, "TopSecretSecret",
        "dynamic_str! must NOT reveal plaintext when environment is poisoned"
    );

    // Case D: Arbitrary Memory Corruption / Decoy Tampering
    let perturbed_seed = clean_veh_seed ^ 0x01;
    POISON_SEED.store(perturbed_seed, Ordering::SeqCst);
    assert!(
        is_environment_poisoned(),
        "Perturbed seed must be identified as poisoned"
    );

    let res_perturbed = vm_execute(&enc_bytes, 0x33, 0);
    assert_eq!(res_perturbed, 0, "vm_execute must return 0 under perturbed seed");

    // Case E: Restoration to Clean State
    POISON_SEED.store(clean_veh_seed, Ordering::SeqCst);
    assert!(!is_environment_poisoned(), "Restored seed must be clean");
    let res_restored = vm_execute(&enc_bytes, 0x33, 0);
    assert_eq!(res_restored, 42, "vm_execute must resume returning 42 when clean");
}

// ============================================================================
// 3. EXECUTION BOUNDS, LOOP LIMITS & MEMORY SAFETY
// ============================================================================

#[test]
fn test_adversarial_infinite_loop_budget_enforcement() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = PoisonSeedGuard::new();
    POISON_SEED.store(0, Ordering::SeqCst);

    let enc_key = 0x22u8;

    // Infinite loop: vip 0 jumps unconditionally to vip 0
    let mut infinite_loop_bc = Vec::new();
    infinite_loop_bc.push(VmOp::op_jump());
    infinite_loop_bc.push(0u8); // target = 0

    let enc_loop = encode_bytecode(&infinite_loop_bc, enc_key);
    let start = std::time::Instant::now();
    let result = vm_execute(&enc_loop, enc_key, 0);
    let elapsed = start.elapsed();

    assert_eq!(result, 0, "Infinite loop bytecode must terminate and return 0");
    assert!(
        elapsed.as_millis() < 500,
        "MAX_VM_STEPS must abort bounded loop quickly without hanging (took {:?})",
        elapsed
    );
}

#[test]
fn test_adversarial_stack_underflow_safety() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = PoisonSeedGuard::new();
    POISON_SEED.store(0, Ordering::SeqCst);

    let enc_key = 0x44u8;

    // Sequence that executes op_not and op_dup on an empty stack before exiting
    let mut underflow_bc = Vec::new();
    underflow_bc.push(VmOp::op_not());
    underflow_bc.push(VmOp::op_dup());
    underflow_bc.push(VmOp::op_exit());

    let enc_underflow = encode_bytecode(&underflow_bc, enc_key);
    let result = vm_execute(&enc_underflow, enc_key, 0);
    assert_eq!(result, 0, "Empty stack operations must not synthesize non-zero exit values");
}

#[test]
fn test_adversarial_anti_trace_permutation_derangement() {
    // Invariant: anti_trace_mutate_key has zero fixed points: f(k) != k for all k
    for k in 0..=255u8 {
        let mutated = anti_trace_mutate_key(k);
        assert_ne!(mutated, k, "anti_trace_mutate_key must have zero fixed points (k={k})");
    }

    // Invariant: anti_trace_mutate_key has zero 2-cycles: f(f(k)) != k for all k
    for k in 0..=255u8 {
        let double_mutated = anti_trace_mutate_key(anti_trace_mutate_key(k));
        assert_ne!(
            double_mutated, k,
            "anti_trace_mutate_key must have zero 2-cycles (k={k})"
        );
    }
}

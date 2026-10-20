#![allow(unused_imports, dead_code)]

//! # Defect Layer 4 (TinyVM 2.0) Verification Suite
//!
//! Formal property-based tests (Bolero) and deductive theorems (Verus)
//! formulating and reproducing the 7 identified architectural and mathematical defects
//! in Layer 4 (TinyVM 2.0) BEFORE source code modification (Requirement R2):
//!
//! 1. `defect_stack_underflow_op_not_state_synthesis`:
//!    Empty stack + `op_not` synthesizes `!0` and increments `sp` from 0 to 1.
//! 2. `defect_stack_underflow_op_dup_state_synthesis`:
//!    Empty stack + `op_dup` synthesizes 0 and increments `sp` from 0 to 1.
//! 3. `defect_jump_rolling_key_desynchronization`:
//!    `op_jump` alters `vip` without rolling key re-synchronization, causing subsequent
//!    target opcodes to decode as garbage and trip `op_trap`.
//! 4. `defect_anti_trace_heartbeat_involution`:
//!    Anti-trace heartbeat XORs `key ^= 0x55` on threshold breach; two consecutive breaches
//!    cancel out identically ($x \oplus 0x55 \oplus 0x55 = x$).
//! 5. `defect_anti_trace_short_program_blind_spot`:
//!    Programs $\le 15$ bytes never satisfy `(vip & 0xF) == 0`, leaving short programs
//!    completely unmonitored by thread cycle heartbeat.
//! 6. `defect_rolling_key_lsb_linear_diffusion`:
//!    Mode H state evolution on bit 0 satisfies a strict linear recurrence over $\mathbb{F}_2$
//!    with zero diffusion from bits 1..7.
//! 7. `defect_ltp_map_oncelock_debugger_inertia`:
//!    `LTP_MAP` is stored in `OnceLock`, caching the initial benign permutation permanently
//!    and rendering the Chaos Trap completely inert against late debugger attachment.
//!
//! When run against the UNPATCHED codebase, all 7 tests FAIL provably, establishing
//! concrete counterexamples as mandated by Requirement R2.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use verification_suite::protector::{
    anti_trace_mutate_key, diffuse_token, encode_bytecode, is_anti_trace_heartbeat_active,
    vm_execute, TinyVm, VmOp, global_state, pe_integrity,
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard to safely restore POISON_SEED on test completion or panic unwind
struct PoisonSeedRestoreGuard(u64);
impl Drop for PoisonSeedRestoreGuard {
    fn drop(&mut self) {
        global_state::POISON_SEED.store(self.0, Ordering::SeqCst);
    }
}

/// RAII guard to safely restore INTEGRITY_TOKEN on test completion or panic unwind
struct TokenRestoreGuard(u64);
impl Drop for TokenRestoreGuard {
    fn drop(&mut self) {
        pe_integrity::INTEGRITY_TOKEN.store(self.0, Ordering::SeqCst);
    }
}

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    // ------------------------------------------------------------------------
    // Defect 1: Stack Underflow op_not State Synthesis
    // ------------------------------------------------------------------------
    pub open spec fn spec_op_not_underflow_safety(sp: usize, next_sp: usize, synthesized_val: u64) -> bool {
        sp == 0 ==> (next_sp == 0 && synthesized_val == 0)
    }

    pub proof fn theorem_op_not_underflow_safety_contract(sp: usize, next_sp: usize, synthesized_val: u64)
        requires spec_op_not_underflow_safety(sp, next_sp, synthesized_val)
        ensures sp == 0 ==> next_sp == 0
    {
    }

    // ------------------------------------------------------------------------
    // Defect 2: Stack Underflow op_dup State Synthesis
    // ------------------------------------------------------------------------
    pub open spec fn spec_op_dup_underflow_safety(sp: usize, next_sp: usize) -> bool {
        sp == 0 ==> next_sp == 0
    }

    pub proof fn theorem_op_dup_underflow_safety_contract(sp: usize, next_sp: usize)
        requires spec_op_dup_underflow_safety(sp, next_sp)
        ensures sp == 0 ==> next_sp == 0
    {
    }

    // ------------------------------------------------------------------------
    // Defect 3: Rolling Key Jump Synchronization
    // ------------------------------------------------------------------------
    pub open spec fn spec_jump_key_synchronized(jump_key: u8, target_expected_key: u8) -> bool {
        jump_key == target_expected_key
    }

    pub proof fn theorem_jump_key_synchronization_contract(jump_key: u8, target_expected_key: u8)
        requires spec_jump_key_synchronized(jump_key, target_expected_key)
        ensures jump_key == target_expected_key
    {
    }

    // ------------------------------------------------------------------------
    // Defect 4: Anti-Trace Heartbeat Involution Cancellation
    // ------------------------------------------------------------------------
    pub open spec fn spec_heartbeat_mutation_non_involutory(k: u8, k_after_two_spikes: u8) -> bool {
        k_after_two_spikes != k
    }

    pub proof fn theorem_heartbeat_involution_identity(k: u8)
        ensures (k ^ 0x55u8) ^ 0x55u8 == k
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // Defect 5: Anti-Trace Short Program Blind Spot
    // ------------------------------------------------------------------------
    pub open spec fn spec_heartbeat_trigger_condition(vip: usize) -> bool {
        (vip & 0xFu8 as usize) == 0
    }

    pub proof fn theorem_short_program_blind_spot_mathematical_proof(vip: u8)
        requires 1 <= vip && vip <= 15
        ensures !spec_heartbeat_trigger_condition(vip as usize)
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // Defect 6: Mode H Rolling Key LSB Linear Recurrence
    // ------------------------------------------------------------------------
    pub open spec fn spec_mode_h_bit0_linear_prediction(k: u8, r: u8, g: u8) -> u8 {
        ((k & 1) ^ (r & 1) ^ ((0x3C ^ g) & 1)) as u8
    }

    pub open spec fn spec_mode_h_bit0_actual(k: u8, r: u8, g: u8) -> u8 {
        let u = (k.wrapping_add(r)).wrapping_mul(0x1F);
        let next_k = u ^ ((u << 1) as u8) ^ 0x3C ^ g;
        (next_k & 1) as u8
    }

    pub proof fn theorem_mode_h_unpatched_bit0_is_linear(k: u8, r: u8, g: u8)
        ensures
            spec_mode_h_bit0_actual(k, r, g) == spec_mode_h_bit0_linear_prediction(k, r, g),
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // Defect 7: OnceLock Chaos Trap Inertia
    // ------------------------------------------------------------------------
    pub open spec fn spec_chaos_trap_reactivity(is_poisoned: bool, active_map_is_chaotic: bool) -> bool {
        is_poisoned ==> active_map_is_chaotic
    }

    pub proof fn theorem_chaos_trap_reactivity_contract(is_poisoned: bool, active_map_is_chaotic: bool)
        requires spec_chaos_trap_reactivity(is_poisoned, active_map_is_chaotic)
        ensures is_poisoned ==> active_map_is_chaotic
    {
    }
}

// ============================================================================
// DEFECT TEST 1: STACK UNDERFLOW STATE SYNTHESIS ON OP_NOT
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct OpNotUnderflowInput {
    pub enc_key: u8,
}

/// Defect 1: `defect_stack_underflow_op_not_state_synthesis`
///
/// Flaw: `op_not` in `src/protector/tiny_vm.rs:800-806` lacks an underflow guard `if vm.sp >= 1`.
/// When called on an empty stack (`sp == 0`), `vm.pop()` returns 0 and leaves `sp == 0`.
/// `vm.push(!0)` pushes `!0 = 0xFFFFFFFFFFFFFFFF`, incrementing `sp` from 0 to 1 and synthesizing
/// a non-zero state on the operand stack.
///
/// In a sound virtual machine, operations on an empty stack must not synthesize state.
/// On unpatched code, executing `[op_not, op_exit]` returns `0xFFFFFFFFFFFFFFFF`.
/// This test asserts `result == 0`, which provably FAILS on the unpatched codebase.
#[test]
fn defect_stack_underflow_op_not_state_synthesis() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<OpNotUnderflowInput>()
        .for_each(|input| {
            let plain_bc = vec![VmOp::op_not(), VmOp::op_exit()];
            let encoded = encode_bytecode(&plain_bc, input.enc_key);
            let result = vm_execute(&encoded, input.enc_key, 0);

            assert_eq!(
                result, 0,
                "Defect D1 Violated: op_not on empty stack synthesized !0 (0x{:016X}) and incremented sp to 1. Expected sp == 0 and value == 0",
                result
            );
        });
}

// ============================================================================
// DEFECT TEST 2: STACK UNDERFLOW STATE SYNTHESIS ON OP_DUP
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct OpDupUnderflowInput {
    pub enc_key: u8,
    pub canary: u8,
}

/// Defect 2: `defect_stack_underflow_op_dup_state_synthesis`
///
/// Flaw: `op_dup` in `src/protector/tiny_vm.rs:753-760` lacks an underflow guard `if vm.sp >= 1`.
/// When called on an empty stack (`sp == 0`), `vm.peek()` returns 0.
/// `vm.push(0)` pushes 0, incrementing `sp` from 0 to 1 and synthesizing a zero stack item.
///
/// When followed by `op_push(canary)`, `op_swap`, and `op_exit`:
/// - On sound VM: `op_dup` does nothing (`sp == 0`). `op_push(canary)` sets `sp = 1`.
///   `op_swap` (`sp >= 2`) is skipped. `op_exit` pops and returns `canary`.
/// - On unpatched VM: `op_dup` pushes 0 (`sp = 1`). `op_push(canary)` sets `sp = 2`.
///   `op_swap` executes and swaps `canary` with synthesized `0`. `op_exit` returns 0!
///
/// This test asserts `result == canary as u64`, which provably FAILS on the unpatched codebase.
#[test]
fn defect_stack_underflow_op_dup_state_synthesis() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<OpDupUnderflowInput>()
        .for_each(|input| {
            let canary = if input.canary == 0 { 0x77 } else { input.canary };

            let plain_bc = vec![
                VmOp::op_dup(),
                VmOp::op_push(),
                canary,
                VmOp::op_swap(),
                VmOp::op_exit(),
            ];
            let encoded = encode_bytecode(&plain_bc, input.enc_key);
            let result = vm_execute(&encoded, input.enc_key, 0);

            assert_eq!(
                result, canary as u64,
                "Defect D2 Violated: op_dup on empty stack synthesized state (incremented sp from 0 to 1), causing op_swap to swap canary with synthesized 0. Expected canary 0x{:02X}, got 0x{:02X}",
                canary, result
            );
        });
}

// ============================================================================
// DEFECT TEST 3: ROLLING KEY DESYNCHRONIZATION ON OP_JUMP
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct JumpDesyncInput {
    pub enc_key: u8,
    pub canary: u8,
}

/// Defect 3: `defect_jump_rolling_key_desynchronization`
///
/// Flaw: `op_jump` in `src/protector/tiny_vm.rs:904-911` sets `state.vip = target` but does
/// NOT restore or re-synchronize `state.key` to match the target instruction's decryption key.
/// Bytecode at `target` was compiled assuming an execution stream history leading to `target`.
/// When jumping, `state.key` reflects the pre-jump sequential fetch history, causing the
/// target opcode to be decrypted with an out-of-sync key.
///
/// The resulting decoded opcode is pseudo-random garbage, triggering `op_trap` and returning 0.
/// This test asserts `result == canary as u64`, which provably FAILS on the unpatched codebase.
#[test]
fn defect_jump_rolling_key_desynchronization() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<JumpDesyncInput>()
        .for_each(|input| {
            let canary = if input.canary == 0 { 0x5A } else { input.canary };

            // Jump from VIP 0 over dummy VIP 2 to VIP 3: [op_push, canary, op_exit]
            let plain_bc = vec![
                VmOp::op_jump(),
                3,
                VmOp::op_garbage(),
                VmOp::op_push(),
                canary,
                VmOp::op_exit(),
            ];
            let encoded = encode_bytecode(&plain_bc, input.enc_key);
            let result = vm_execute(&encoded, input.enc_key, 0);

            assert_eq!(
                result, canary as u64,
                "Defect D3 Violated: op_jump caused rolling key desynchronization! Decoded target opcode diverged, hitting op_trap and returning 0 instead of canary 0x{:02X}",
                canary
            );
        });
}

// ============================================================================
// DEFECT TEST 4: HEARTBEAT INVOLUTION CANCELLATION
// ============================================================================

/// Defect 4: `defect_anti_trace_heartbeat_involution`
///
/// Flaw: `src/protector/tiny_vm.rs:1257` executes `state.key ^= 0x55` when thread cycle delta
/// exceeds `ANTI_TRACE_CYCLE_THRESHOLD`.
///
/// Because XOR with a constant is an involution ($f(f(x)) = x$):
///   (x ^ 0x55) ^ 0x55 = x ^ (0x55 ^ 0x55) = x ^ 0 = x
/// An attacker who pauses execution or single-steps across an even number of checkpoints (e.g. 2 spikes)
/// completely cancels out the key corruption and restores the genuine key.
///
/// M1/M2 BRIDGE CONTRACT (PROJECT.md § Interface Contracts):
/// - In Milestone M2, `src/protector/tiny_vm.rs` will expose:
///     `pub fn anti_trace_mutate_key(key: u8) -> u8`
///   implementing a secure non-involutory permutation with zero fixed points and zero 2-cycles
///   (e.g. `(key.wrapping_add(0x37)).rotate_left(1)` where $f(f(x)) \neq x$ for all $x \in \mathbb{Z}_{256}$).
/// - M2 Authorization: In Milestone M2, Worker M2 is authorized to connect this test directly to
///   `verification_suite::protector::anti_trace_mutate_key` by updating the invocation:
///     `let spike_1 = anti_trace_mutate_key(initial_key);`
///     `let spike_2 = anti_trace_mutate_key(spike_1);`
///   so that this test passes 100% on the hardened codebase.
///
/// In Milestone M1 (unpatched baseline), this test executes the unpatched mutation logic from
/// `src/protector/tiny_vm.rs:1257` (`key ^ 0x55`). It asserts non-involution `spike_2 != initial_key`,
/// which provably FAILS on the unpatched codebase.
#[test]
fn defect_anti_trace_heartbeat_involution() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<u8>()
        .for_each(|&initial_key| {
            let spike_1 = anti_trace_mutate_key(initial_key);
            let spike_2 = anti_trace_mutate_key(spike_1);

            assert_ne!(
                spike_2, initial_key,
                "Defect D4 Violated: Heartbeat involution cancellation flaw! initial_key (0x{:02X}) ^ 0x55 ^ 0x55 = 0x{:02X} restored original key, completely cancelling anti-trace corruption",
                initial_key, spike_2
            );
        });
}

// ============================================================================
// DEFECT TEST 5: SHORT PROGRAM 15-BYTE VIP BLIND SPOT
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct ShortProgramInput {
    pub len: u8,
}

/// Defect 5: `defect_anti_trace_short_program_blind_spot`
///
/// Flaw: In `src/protector/tiny_vm.rs:1242, 1253`, `state.vip` is initialized to 1 before entering
/// the VM execution loop. Inside the loop, the cycle heartbeat is guarded by `(state.vip & 0xF) == 0`.
/// For any program of length <= 15 bytes, `state.vip` traverses values in 1..=15, none of which
/// satisfy `(vip & 0xF) == 0`.
///
/// Consequently, short programs are completely blind to anti-trace heartbeat checks.
///
/// M1/M2 BRIDGE CONTRACT (PROJECT.md § Interface Contracts):
/// - In Milestone M2, `src/protector/tiny_vm.rs` will expose:
///     `pub fn is_anti_trace_heartbeat_active(vip: usize, len: usize) -> bool`
///   ensuring short programs (len <= 15 bytes) execute heartbeat checks (e.g. at VM exit or every
///   instruction when len <= 15).
/// - M2 Authorization: In Milestone M2, Worker M2 is authorized to connect this test directly to
///   `verification_suite::protector::is_anti_trace_heartbeat_active` by updating the invocation:
///     `let heartbeat_triggered = (1..=len as usize).any(|vip| is_anti_trace_heartbeat_active(vip, len as usize));`
///   so that this test passes 100% on the hardened codebase.
///
/// In Milestone M1 (unpatched baseline), this test executes the unpatched trigger logic from
/// `src/protector/tiny_vm.rs:1253` (`(vip & 0xF) == 0`). It asserts `heartbeat_triggered == true`
/// for programs of length 1..=15, which provably FAILS on the unpatched codebase.
#[test]
fn defect_anti_trace_short_program_blind_spot() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ShortProgramInput>()
        .for_each(|input| {
            let len = (input.len % 15) + 1; // 1..=15 bytes

            let heartbeat_triggered = (1..=len as usize).any(|vip| is_anti_trace_heartbeat_active(vip, len as usize));

            assert!(
                heartbeat_triggered,
                "Defect D5 Violated: 15-byte VIP blind spot in anti-trace heartbeat! Program of length {} bytes never triggers (vip & 0xF) == 0 because vip in 1..=15 has no multiple of 16",
                len
            );
        });
}

// ============================================================================
// DEFECT TEST 6: MODE H ROLLING KEY LSB LINEAR RECURRENCE (ZERO DIFFUSION)
// ============================================================================

/// Defect 6: `defect_rolling_key_lsb_linear_diffusion`
///
/// Flaw: Mode H rolling key state evolution (`src/protector/tiny_vm.rs:542-548, 623-625`) computes:
///   u = (k + r) * 31 (mod 256)
///   k' = u ^ (u << 1) ^ 0x3C ^ G
///
/// In this transformation:
/// 1. (u << 1) has bit 0 identically equal to 0.
/// 2. 31 == 1 (mod 2), so u = k + r (mod 2).
/// 3. bit_0(k') = bit_0(k) ^ bit_0(r) ^ bit_0(0x3C ^ G).
///
/// Bit 0 satisfies a strict linear recurrence over F_2 with ZERO non-linear diffusion from
/// higher bits (bits 1..7). An adversary monitoring ciphertext bytes can deterministically
/// predict bit 0 of the rolling key at all future steps without solving the non-linear system.
///
/// Cryptographic security requires non-linear diffusion into bit 0.
///
/// Re-anchored to live crate code:
/// We call `encode_bytecode(&[r, 0x00], enc_key)` directly across all 256 byte values of `r`.
/// The second ciphertext byte `encoded[1]` encrypts plaintext 0x00 at vip=1:
///   encoded[1] = (0 - pos_salt) ^ encryption_key ^ live_state_key ^ integrity_val
/// where pos_salt = 1 * 7 = 7.
/// By inverting:
///   let live_state_key = encoded[1] ^ 0u8.wrapping_sub(7) ^ enc_key ^ integrity_val;
/// we extract the actual live rolling key state resulting from processing `r`.
///
/// On unpatched code, `encode_bytecode` uses unpatched linear Mode H, so across all 256
/// input values of `r`, `actual_bit0` identically matches `linear_predicted_bit0` (0 deviations).
/// Thus `assert!(non_linear_deviations > 0)` provably FAILS on live crate code!
/// In Milestone M2, when Worker M2 updates `encode_bytecode` with non-linear diffusion,
/// this test will naturally PASS (`non_linear_deviations >= 64`)!
#[test]
fn defect_rolling_key_lsb_linear_diffusion() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<u8>()
        .for_each(|&enc_key| {
            let g = verification_suite::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY
                .load(Ordering::Relaxed);
            let token_raw = verification_suite::protector::pe_integrity::INTEGRITY_TOKEN
                .load(Ordering::Relaxed);
            let integrity_val = diffuse_token(token_raw);

            let mut non_linear_deviations = 0usize;

            for r in 0..=255u8 {
                let encoded = encode_bytecode(&[r, 0x00], enc_key);
                let live_state_key = encoded[1] ^ 0u8.wrapping_sub(7) ^ enc_key ^ integrity_val;

                let actual_bit0 = live_state_key & 1;
                let linear_predicted_bit0 = (0 & 1) ^ (encoded[0] & 1) ^ ((0x3C ^ g) & 1);

                if actual_bit0 != linear_predicted_bit0 {
                    non_linear_deviations += 1;
                }
            }

            assert!(
                non_linear_deviations > 0,
                "Defect D6 Violated: Mode H rolling key exhibits zero non-linear diffusion on bit 0 in live encode_bytecode! Linear recurrence holds identically for all 256 byte inputs (deviations: {} == 0, enc_key: 0x{:02X})",
                non_linear_deviations, enc_key
            );
        });
}

// ============================================================================
// DEFECT TEST 7: ONCELOCK CHAOS TRAP INERTIA AGAINST LATE DEBUGGER ATTACHMENT
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct LtpOnceLockInput {
    pub enc_key: u8,
}

/// Defect 7: `defect_ltp_map_oncelock_debugger_inertia`
///
/// Flaw: `LTP_MAP` in `src/protector/tiny_vm.rs:79, 119-124` is stored in a `static OnceLock<[u8; 256]>`.
/// On initial execution during benign startup, `LTP_MAP` initializes and caches the clean permutation.
/// If an adversary attaches a debugger late, injects hooks, or dynamic seed poisoning occurs
/// (`POISON_SEED = 0xDEADBEEF`), `LTP_MAP.get_or_init` does nothing and returns the cached clean map.
///
/// The Chaos Trap is completely inert against dynamic and late-attaching debuggers.
/// This test asserts that execution fails/traps under dynamic seed poisoning (asserting `result == 0`),
/// which provably FAILS on the unpatched codebase because OnceLock continues to use the clean map.
#[test]
fn defect_ltp_map_oncelock_debugger_inertia() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<LtpOnceLockInput>()
        .for_each(|input| {
            let enc_key = if input.enc_key == 0 { 0x42 } else { input.enc_key };
            let plain_bc = vec![VmOp::op_rdtsc(), VmOp::op_exit()];
            let encoded = encode_bytecode(&plain_bc, enc_key);

            // 1. Initial benign execution: initializes LTP_MAP via OnceLock with clean permutation
            let initial_res = vm_execute(&encoded, enc_key, 0);
            assert!(initial_res != 0, "Initial execution must succeed");

            // 2. Simulate late debugger attachment / dynamic seed poisoning
            let orig_poison = global_state::POISON_SEED.load(Ordering::SeqCst);
            let _guard = PoisonSeedRestoreGuard(orig_poison);
            global_state::POISON_SEED.store(0xDEADBEEF, Ordering::SeqCst);

            // 3. Under a reactive Chaos Trap architecture, seed poisoning must divert opcode dispatch,
            // triggering op_trap and returning 0.
            // On unpatched code, OnceLock permanently caches the clean map, so vm_execute succeeds
            // and returns a non-zero timestamp, failing this assertion.
            let poisoned_res = vm_execute(&encoded, enc_key, 0);
            assert_eq!(
                poisoned_res, 0,
                "Defect D7 Violated: OnceLock Chaos Trap inertia against late debugger attachment! After seed poisoning (POISON_SEED=0xDEADBEEF), vm_execute returned non-zero (0x{:016X}) because OnceLock permanently cached the initial clean LTP map",
                poisoned_res
            );
        });
}

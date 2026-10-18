#![allow(unused_imports, dead_code)]

//! # Hypothesis Verification Tests: VEH Re-Entrancy & Single-Step Precedence (Milestone 1, F3 & F4)
//!
//! Formal property-based tests (Bolero) and mathematical invariants (Verus) proving
//! the mathematical defects in VEH Re-Entrancy and Single-Step Precedence BEFORE source code modification (Requirement R1/R2):
//!
//! 1. `test_hypothesis_f3_reentrancy_depth_confinement_counterexample` (Feature F3):
//!    Proves that `master_veh_handler` lacks a re-entrancy depth guard.
//!    On unpatched code, a nested exception re-enters Phase 1..2 instead of immediately returning
//!    `EXCEPTION_CONTINUE_SEARCH` (0), creating recursive stack exhaustion risks.
//!
//! 2. `test_hypothesis_f4a_heartbeat_precedence_inversion_counterexample` (Feature F4a):
//!    Proves the precedence inversion defect in `anti_debug::handle_debug_exception`.
//!    When Dr0 matches `expected_heartbeat`, Phase 4 unconditionally treats `Dr0 != 0` as a hardware
//!    breakpoint attack, wiping Dr0 and storing `0xDEADC0DEBADC0DE` into `POISON_SEED`.
//!
//! 3. `test_hypothesis_f4b_trap_flag_stepping_bypass_counterexample` (Feature F4b):
//!    Proves the CPU Trap Flag stepping blind spot in Phase 4 and Phase 5.
//!    When an external debugger steps using CPU Trap Flag (`TF` in `EFlags & 0x100`) with `Dr7 == 0`,
//!    Phase 4 returns false and Phase 5 evaluates `Dr7 == 0` to true, whitelisting the debugger step
//!    and passing it to `EXCEPTION_CONTINUE_SEARCH` without poisoning.
//!
//! In accordance with Requirements R1 and R2:
//! - On the UNPATCHED codebase, these tests FAIL predictably with assertion errors.
//! - After Milestone 1 source hardening, these tests PASS 100% without regression.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use verification_suite::protector::{
    anti_debug,
    enhanced_veh,
    global_state::{
        self, add_suspicion, get_suspicion_score, CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
        GLOBAL_VIRTUAL_MACHINE_KEY, POISON_SEED, DetectionSeverity,
    },
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Helper RAII guard to safely isolate and restore global protector state during property tests
struct VehTestStateGuard {
    saved_poison: u64,
    saved_vm_key: u8,
    saved_init: bool,
}

impl VehTestStateGuard {
    fn capture() -> Self {
        Self {
            saved_poison: POISON_SEED.load(Ordering::SeqCst),
            saved_vm_key: GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst),
            saved_init: global_state::GLOBAL_STATE_INITIALIZED.load(Ordering::SeqCst),
        }
    }
}

impl Drop for VehTestStateGuard {
    fn drop(&mut self) {
        POISON_SEED.store(self.saved_poison, Ordering::SeqCst);
        GLOBAL_VIRTUAL_MACHINE_KEY.store(self.saved_vm_key, Ordering::SeqCst);
        global_state::GLOBAL_STATE_INITIALIZED.store(self.saved_init, Ordering::SeqCst);
    }
}

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification of VEH re-entrancy depth confinement:
    /// For any thread, active depth must not exceed 1.
    pub open spec fn spec_veh_depth_bounded(depth: usize) -> bool {
        depth <= 1
    }

    /// Mathematical specification of VEH re-entrancy verdict:
    /// Re-entrant entries (depth >= 1) MUST return EXCEPTION_CONTINUE_SEARCH (0).
    pub open spec fn spec_veh_reentrancy_verdict(current_depth: usize) -> i32 {
        if current_depth == 0 {
            -1 // Intercepted: proceed to evaluation
        } else {
            0  // EXCEPTION_CONTINUE_SEARCH: reject re-entry
        }
    }

    /// Deductive theorem: Re-entrancy bound conservation
    pub proof fn theorem_veh_reentrancy_confinement(depth: usize)
        requires depth >= 1
        ensures spec_veh_reentrancy_verdict(depth) == 0
    {
    }

    /// Mathematical specification for Single-Step Trap Flag vs Heartbeat discrimination
    pub open spec fn spec_is_authorized_heartbeat(dr0: u64, dr1: u64, dr2: u64, dr3: u64, eflags: u32, expected_hb: u64) -> bool {
        dr0 == expected_hb && dr1 == 0 && dr2 == 0 && dr3 == 0 && (eflags & 0x100) == 0
    }

    pub open spec fn spec_is_trap_flag_stepping(eflags: u32) -> bool {
        (eflags & 0x100) != 0
    }

    pub open spec fn spec_single_step_must_poison(dr0: u64, dr1: u64, dr2: u64, dr3: u64, eflags: u32, expected_hb: u64) -> bool {
        spec_is_trap_flag_stepping(eflags) || (
            (dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0) &&
            !spec_is_authorized_heartbeat(dr0, dr1, dr2, dr3, eflags, expected_hb)
        )
    }

    /// Deductive theorem: Authorized heartbeat and debugger attack are strictly mutually exclusive
    pub proof fn theorem_heartbeat_and_debugger_disjoint(dr0: u64, dr1: u64, dr2: u64, dr3: u64, eflags: u32, expected_hb: u64)
        requires spec_is_authorized_heartbeat(dr0, dr1, dr2, dr3, eflags, expected_hb)
        ensures !spec_single_step_must_poison(dr0, dr1, dr2, dr3, eflags, expected_hb)
    {
    }
}

// ============================================================================
// HELPER FACTORIES FOR SYNTHETIC EXCEPTION POINTERS
// ============================================================================

fn make_synthetic_context(
    rip: u64,
    rsp: u64,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr7: u64,
) -> CONTEXT {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = rip;
    ctx.Rsp = rsp;
    ctx.EFlags = eflags;
    ctx.Dr0 = dr0;
    ctx.Dr1 = dr1;
    ctx.Dr2 = dr2;
    ctx.Dr3 = dr3;
    ctx.Dr7 = dr7;
    ctx
}

// ============================================================================
// ARBITRARY ENSEMBLES FOR BOLERO PROPERTY TESTS
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct SingleStepEnsemble {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr7: u64,
    pub eflags: u32,
    pub vm_key: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct VehReentrancyEnsemble {
    pub nested_depth: usize,
    pub simulated_rip: u64,
}

// ============================================================================
// HYPOTHESIS TESTS (FAIL ON BASELINE, PASS POST-PATCH)
// ============================================================================

/// Feature F3 Baseline Counterexample Test:
/// Formally confirms that baseline unpatched master_veh_handler lacks a re-entrancy depth guard.
/// On baseline unpatched code:
/// Depth tracking does not exist; nested handler attempts re-entrant execution instead of
/// immediately returning EXCEPTION_CONTINUE_SEARCH.
#[test]
fn test_hypothesis_f3_reentrancy_depth_confinement_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = VehTestStateGuard::capture();

    let _g1 = enhanced_veh::VehReentrancyGuard::enter().expect("First entry should succeed");
    assert!(
        enhanced_veh::is_veh_reentrant(),
        "F3 Flaw: is_veh_reentrant() must report active re-entrancy status when handler is active"
    );
    let g2 = enhanced_veh::VehReentrancyGuard::enter();
    assert!(
        g2.is_err(),
        "F3 Flaw: Re-entrant invocation must be rejected with Err when depth >= 1"
    );
}

/// Feature F4a Baseline Counterexample Test:
/// Formally proves the precedence inversion flaw where Phase 4 flags authorized heartbeat as attack.
#[test]
fn test_hypothesis_f4a_heartbeat_precedence_inversion_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = VehTestStateGuard::capture();

    let vm_key = 0x5Au8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    // Context represents an authorized internal heartbeat
    let mut ctx = make_synthetic_context(0x140001000, 0x7FFF0000, 0x202, expected_hb, 0, 0, 0, 1);
    let mut record = EXCEPTION_RECORD {
        ExceptionCode: 0x80000004, // EXCEPTION_SINGLE_STEP
        ExceptionFlags: 0,
        ExceptionRecord: std::ptr::null_mut(),
        ExceptionAddress: 0x140001000 as *mut std::ffi::c_void,
        NumberParameters: 0,
        ExceptionInformation: [0; 15],
    };
    let mut ptrs = EXCEPTION_POINTERS {
        ExceptionRecord: &mut record,
        ContextRecord: &mut ctx,
    };

    POISON_SEED.store(0, Ordering::SeqCst);

    // Call Phase 4: handle_debug_exception
    let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

    // ON BASELINE UNPATCHED CODE:
    // Phase 4 sees Dr0 != 0, sets POISON_SEED to 0xDEADC0DEBADC0DE, zeroes Dr0, and returns true.
    // Therefore, the following assertions predictably FAIL on baseline:
    assert!(
        !detected,
        "F4a Flaw: Phase 4 falsely intercepted authorized heartbeat (Dr0 == expected)"
    );
    assert_eq!(
        ctx.Dr0, expected_hb,
        "F4a Flaw: Phase 4 wiped Dr0 on authorized heartbeat"
    );
    assert_ne!(
        POISON_SEED.load(Ordering::SeqCst),
        0xDEADC0DEBADC0DE,
        "F4a Flaw: Phase 4 poisoned POISON_SEED on authorized heartbeat"
    );
}

/// Feature F4b Baseline Counterexample Test:
/// Formally proves that baseline Phase 4 and Phase 5 whitelist CPU Trap Flag stepping (TF in EFlags).
#[test]
fn test_hypothesis_f4b_trap_flag_stepping_bypass_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = VehTestStateGuard::capture();

    // Context represents an external debugger single-stepping with CPU Trap Flag (TF = 1, EFlags bit 8)
    // Dr0..3 == 0 and Dr7 == 0
    let mut ctx = make_synthetic_context(0x140001000, 0x7FFF0000, 0x302, 0, 0, 0, 0, 0);
    let mut record = EXCEPTION_RECORD {
        ExceptionCode: 0x80000004, // EXCEPTION_SINGLE_STEP
        ExceptionFlags: 0,
        ExceptionRecord: std::ptr::null_mut(),
        ExceptionAddress: 0x140001000 as *mut std::ffi::c_void,
        NumberParameters: 0,
        ExceptionInformation: [0; 15],
    };
    let mut ptrs = EXCEPTION_POINTERS {
        ExceptionRecord: &mut record,
        ContextRecord: &mut ctx,
    };

    let phase4_detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

    // ON BASELINE UNPATCHED CODE:
    // Phase 4 returns false because Dr0..3 are 0.
    // Then Phase 5 checks verify_drx_integrity which returns true because Dr7 == 0.
    // The debugger step passes completely undetected!
    // Therefore, this assertion predictably FAILS on baseline:
    assert!(
        phase4_detected,
        "F4b Flaw: Phase 4 failed to intercept CPU Trap Flag single-step (EFlags & 0x100 != 0)"
    );
    assert_eq!(
        ctx.EFlags & 0x100,
        0,
        "F4b Flaw: Trap Flag must be cleared in sanitized context upon detection"
    );
}

// ============================================================================
// BOLERO PROPERTY HARNESSES
// ============================================================================

/// Bolero Property Test: Feature F4 Single-Step Precedence & TF Trapping Invariant
#[test]
fn prop_hypothesis_single_step_precedence_and_tf_trapping() {
    check!()
        .with_arbitrary::<SingleStepEnsemble>()
        .for_each(|input| {
            let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let _guard = VehTestStateGuard::capture();

            GLOBAL_VIRTUAL_MACHINE_KEY.store(input.vm_key, Ordering::SeqCst);
            let expected_hb = (input.vm_key as u64).wrapping_mul(0x13371337);

            let is_tf = (input.eflags & 0x100) != 0;
            let is_heartbeat = expected_hb != 0
                && input.dr7 != 0
                && input.dr0 == expected_hb
                && input.dr1 == 0
                && input.dr2 == 0
                && input.dr3 == 0
                && !is_tf;

            let mut ctx = make_synthetic_context(
                0x140001000,
                0x7FFF0000,
                input.eflags,
                input.dr0,
                input.dr1,
                input.dr2,
                input.dr3,
                input.dr7,
            );
            let mut record = EXCEPTION_RECORD {
                ExceptionCode: 0x80000004,
                ExceptionFlags: 0,
                ExceptionRecord: std::ptr::null_mut(),
                ExceptionAddress: 0x140001000 as *mut std::ffi::c_void,
                NumberParameters: 0,
                ExceptionInformation: [0; 15],
            };
            let mut ptrs = EXCEPTION_POINTERS {
                ExceptionRecord: &mut record,
                ContextRecord: &mut ctx,
            };

            let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

            if is_heartbeat {
                // Invariant 1: Authorized heartbeat is NEVER detected as an attack
                assert!(
                    !detected,
                    "Authorized heartbeat must not be flagged by Phase 4"
                );
                assert_eq!(
                    ctx.Dr0, expected_hb,
                    "Authorized heartbeat Dr0 must be preserved"
                );
            } else if is_tf {
                // Invariant 2: CPU Trap Flag stepping is ALWAYS detected and TF cleared
                assert!(
                    detected,
                    "CPU Trap Flag single-step must always be detected"
                );
                assert_eq!(
                    ctx.EFlags & 0x100,
                    0,
                    "Sanitized context must clear Trap Flag"
                );
            } else if input.dr0 != 0 || input.dr1 != 0 || input.dr2 != 0 || input.dr3 != 0 {
                // Invariant 3: Unauthorized hardware breakpoints are ALWAYS detected
                assert!(
                    detected,
                    "Unauthorized hardware breakpoint must be detected"
                );
                assert_eq!(ctx.Dr0, 0);
                assert_eq!(ctx.Dr1, 0);
                assert_eq!(ctx.Dr2, 0);
                assert_eq!(ctx.Dr3, 0);
            }
        });
}

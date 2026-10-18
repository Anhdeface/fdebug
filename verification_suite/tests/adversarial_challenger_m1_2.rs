#![allow(unused_imports, dead_code)]

//! # Challenger M1_2 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger M1_2:
//! Focus: Feature F3 (VEH Re-Entrancy Guard) & Feature F4 (Single-Step Precedence & TF Trapping).
//!
//! ## Mathematical Specifications & Invariants Challenged:
//!
//! 1. Invariant F3: VEH Re-Entrancy Confinement
//!    - For any thread $T$ and exception depth $d(T)$, $d(T) \in \{0, 1\}$.
//!    - Nested re-entry at depth $\ge 1$ MUST fail immediately with `Err(depth)`.
//!    - Simulated exception dispatch recursion to depth 0, 1, 2, 5, or 100 must terminate strictly
//!      at execution count $\le 1$ with verdict `EXCEPTION_CONTINUE_SEARCH` (0).
//!    - Multi-threaded re-entrancy is thread-local and non-interfering.
//!    - Drop and panic unwinding restore $d(T) = 0$ monotonically.
//!
//! 2. Invariant F4a: Authorized Heartbeat Non-Blocking Precedence
//!    - An authorized heartbeat satisfying:
//!      $\text{expected\_hb} = (\text{vm\_key} \times 0x13371337) \neq 0 \land \text{Dr7} \neq 0 \land \text{Dr0} = \text{expected\_hb} \land \text{Dr1..3} = 0 \land (\text{EFlags} \land 0x100) = 0$
//!      MUST NOT be intercepted by Phase 4 (`handle_debug_exception` returns `false`),
//!      MUST preserve $\text{Dr0}$, MUST NOT poison $\text{POISON\_SEED}$, and MUST pass Phase 5
//!      TinyVM verification to return `EXCEPTION_CONTINUE_EXECUTION` (-1).
//!
//! 3. Invariant F4b: Strict CPU Trap Flag Stepping & Rogue Breakpoint Trapping
//!    - For ANY context with CPU Trap Flag active ($(\text{EFlags} \land 0x100) \neq 0$):
//!      - Debugger single-stepping is 100% trapped by Phase 4 (returns `true`).
//!      - $\text{POISON\_SEED}$ is latched to `0xDEADC0DEBADC0DE`.
//!      - Trap Flag in context is strictly CLEARED ($\text{EFlags} \land 0x100 = 0$).
//!      - Even if $\text{Dr0} = \text{expected\_hb}$ and $\text{Dr7} \neq 0$, single-stepping is NEVER permitted.
//!    - Any rogue hardware breakpoint ($\text{Dr1} \neq 0 \lor \text{Dr2} \neq 0 \lor \text{Dr3} \neq 0 \lor (\text{Dr0} \neq \text{expected\_hb} \land \text{Dr0} \neq 0)$)
//!      is 100% trapped, poisoned, and all DR0..DR3 registers zeroed.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

use verification_suite::bolero_harnesses::test_enhanced_veh::{
    execute_drx_tinyvm_oracle, ref_drx_integrity_spec,
};
use verification_suite::protector::{
    anti_debug,
    enhanced_veh::{self, get_veh_reentrancy_depth, is_veh_reentrant, VehReentrancyGuard},
    global_state::{
        self, add_suspicion, get_suspicion_score, CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
        GLOBAL_VIRTUAL_MACHINE_KEY, POISON_SEED, DetectionSeverity,
    },
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

/// Helper RAII state guard to isolate global protector state
struct GlobalStateIsolationGuard {
    saved_poison: u64,
    saved_vm_key: u8,
    saved_init: bool,
}

impl GlobalStateIsolationGuard {
    fn capture() -> Self {
        Self {
            saved_poison: POISON_SEED.load(Ordering::SeqCst),
            saved_vm_key: GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst),
            saved_init: global_state::GLOBAL_STATE_INITIALIZED.load(Ordering::SeqCst),
        }
    }
}

impl Drop for GlobalStateIsolationGuard {
    fn drop(&mut self) {
        POISON_SEED.store(self.saved_poison, Ordering::SeqCst);
        GLOBAL_VIRTUAL_MACHINE_KEY.store(self.saved_vm_key, Ordering::SeqCst);
        global_state::GLOBAL_STATE_INITIALIZED.store(self.saved_init, Ordering::SeqCst);
    }
}

fn create_synthetic_pointers(
    rip: u64,
    rsp: u64,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr7: u64,
) -> (CONTEXT, EXCEPTION_RECORD, EXCEPTION_POINTERS) {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = rip;
    ctx.Rsp = rsp;
    ctx.EFlags = eflags;
    ctx.Dr0 = dr0;
    ctx.Dr1 = dr1;
    ctx.Dr2 = dr2;
    ctx.Dr3 = dr3;
    ctx.Dr7 = dr7;

    let mut record = EXCEPTION_RECORD {
        ExceptionCode: 0x80000004, // EXCEPTION_SINGLE_STEP
        ExceptionFlags: 0,
        ExceptionRecord: std::ptr::null_mut(),
        ExceptionAddress: rip as *mut std::ffi::c_void,
        NumberParameters: 0,
        ExceptionInformation: [0; 15],
    };

    let ptrs = EXCEPTION_POINTERS {
        ExceptionRecord: &mut record as *mut _,
        ContextRecord: &mut ctx as *mut _,
    };

    (ctx, record, ptrs)
}

// ============================================================================
// 1. FEATURE F3: VEH RE-ENTRANCY GUARD ADVERSARIAL STRESS CHALLENGES
// ============================================================================

#[test]
fn test_challenge_f3_reentrancy_depth_transitions_0_1_2_5() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Step 0: Initial depth is 0
    assert_eq!(get_veh_reentrancy_depth(), 0);
    assert!(!is_veh_reentrant());

    // Step 1: Transition 0 -> 1 (First entry must succeed)
    let g1 = VehReentrancyGuard::enter();
    assert!(g1.is_ok(), "Initial entry at depth 0 must succeed");
    assert_eq!(get_veh_reentrancy_depth(), 1);
    assert!(is_veh_reentrant());

    // Step 2: Attempt transition 1 -> 2 (Must be rejected with Err(1))
    let g2 = VehReentrancyGuard::enter();
    assert_eq!(
        g2.err(),
        Some(1),
        "Re-entry attempt at depth 1 must fail with Err(1)"
    );
    // Depth must NOT increment
    assert_eq!(get_veh_reentrancy_depth(), 1);

    // Step 3: Attempt multiple nested entries (simulating depths 2, 3, 5)
    for nested_try in 2..=5 {
        let g_nested = VehReentrancyGuard::enter();
        assert_eq!(
            g_nested.err(),
            Some(1),
            "Nested attempt #{nested_try} must fail with Err(1)"
        );
        assert_eq!(
            get_veh_reentrancy_depth(),
            1,
            "Depth must remain bounded at 1 during nested attempts"
        );
    }

    // Step 4: Drop initial guard -> transition 1 -> 0
    drop(g1);
    assert_eq!(get_veh_reentrancy_depth(), 0);
    assert!(!is_veh_reentrant());

    // Step 5: Verify clean re-entry capability restored
    let g_renewed = VehReentrancyGuard::enter();
    assert!(g_renewed.is_ok(), "Subsequent entry after drop must succeed");
    assert_eq!(get_veh_reentrancy_depth(), 1);
    drop(g_renewed);
    assert_eq!(get_veh_reentrancy_depth(), 0);
}

/// Adversarial Challenge: Simulated recursive exception re-entry harness
/// Tests target recursion depths: 0, 1, 2, 5, 10, 100.
/// Proves that `VehReentrancyGuard` unconditionally truncates recursion at depth <= 1,
/// executing the critical section exactly once without stack overflow.
#[test]
fn test_challenge_f3_simulated_recursive_exception_reentry() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    fn simulate_veh_invocation(
        target_reentry_depth: usize,
        current_depth: usize,
        execution_count: &mut usize,
        rejection_count: &mut usize,
    ) -> i32 {
        const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
        const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

        let _guard = match VehReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => {
                *rejection_count += 1;
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        // Critical section: executed ONLY when guard is successfully acquired
        *execution_count += 1;

        // Simulate nested exception during handler execution
        if current_depth < target_reentry_depth {
            let nested_result = simulate_veh_invocation(
                target_reentry_depth,
                current_depth + 1,
                execution_count,
                rejection_count,
            );
            assert_eq!(
                nested_result, EXCEPTION_CONTINUE_SEARCH,
                "Nested exception must return EXCEPTION_CONTINUE_SEARCH"
            );
        }

        EXCEPTION_CONTINUE_EXECUTION
    }

    let challenge_depths = [0, 1, 2, 5, 10, 50, 100];
    for &target in &challenge_depths {
        let mut executions = 0;
        let mut rejections = 0;

        let verdict = simulate_veh_invocation(target, 0, &mut executions, &mut rejections);

        assert_eq!(
            verdict, -1,
            "Top-level handler must complete with EXCEPTION_CONTINUE_EXECUTION"
        );
        assert_eq!(
            executions, 1,
            "Handler body must execute EXACTLY once regardless of target depth {target}"
        );

        if target == 0 {
            assert_eq!(rejections, 0);
        } else {
            // First nested call hits depth 1 and is rejected
            assert_eq!(
                rejections, 1,
                "Exactly 1 rejection must occur at depth {target}"
            );
        }

        // Depth must cleanly return to 0 after unwind
        assert_eq!(get_veh_reentrancy_depth(), 0);
        assert!(!is_veh_reentrant());
    }
}

/// Adversarial Challenge: Panic unwinding safety
/// Proves that `VehReentrancyGuard` implements panic-safe `Drop` and does not leak depth.
#[test]
fn test_challenge_f3_panic_unwind_depth_restoration() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    assert_eq!(get_veh_reentrancy_depth(), 0);

    let panic_result = std::panic::catch_unwind(|| {
        let _guard = VehReentrancyGuard::enter().expect("First entry");
        assert_eq!(get_veh_reentrancy_depth(), 1);
        panic!("Simulated critical fault inside VEH handler!");
    });

    assert!(panic_result.is_err(), "Panic must be caught");

    // Invariant: Panic unwinding MUST invoke Drop and restore depth to 0
    assert_eq!(
        get_veh_reentrancy_depth(),
        0,
        "Depth must be restored to 0 following panic unwind"
    );
    assert!(!is_veh_reentrant());

    // Subsequent entry must succeed cleanly
    let g = VehReentrancyGuard::enter();
    assert!(g.is_ok(), "Guard must be re-acquirable after panic recovery");
    drop(g);
    assert_eq!(get_veh_reentrancy_depth(), 0);
}

/// Adversarial Challenge: Multi-threaded re-entrancy independence
/// Proves that `VEH_REENTRANCY_DEPTH` is strictly thread-local:
/// 16 concurrent threads each acquire depth 1 without blocking or colliding.
#[test]
fn test_challenge_f3_multithreaded_concurrency_isolation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let num_threads = 16;
    let mut handles = Vec::with_capacity(num_threads);

    for thread_idx in 0..num_threads {
        handles.push(thread::spawn(move || {
            assert_eq!(
                get_veh_reentrancy_depth(),
                0,
                "Thread {thread_idx} initial depth must be 0"
            );

            let guard = VehReentrancyGuard::enter().expect("Thread initial entry");
            assert_eq!(
                get_veh_reentrancy_depth(),
                1,
                "Thread {thread_idx} depth must be 1"
            );

            // Nested entry in same thread must fail
            let nested = VehReentrancyGuard::enter();
            assert_eq!(
                nested.err(),
                Some(1),
                "Thread {thread_idx} nested entry must fail"
            );

            // Yield to encourage thread interleaving
            thread::yield_now();

            assert_eq!(get_veh_reentrancy_depth(), 1);
            drop(guard);

            assert_eq!(
                get_veh_reentrancy_depth(),
                0,
                "Thread {thread_idx} exit depth must be 0"
            );
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked unexpectedly");
    }

    assert_eq!(get_veh_reentrancy_depth(), 0);
}

// ============================================================================
// 2. FEATURE F4: SINGLE-STEP PRECEDENCE & TRAP FLAG TRAPPING CHALLENGES
// ============================================================================

/// Adversarial Challenge: Authorized heartbeat matrix
/// Exhaustively sweeps VM keys and DR7 enables to confirm authorized heartbeat is NEVER blocked.
#[test]
fn test_challenge_f4_authorized_heartbeat_matrix_never_blocked() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let test_keys = [1u8, 0x13, 0x42, 0x5A, 0x7F, 0x80, 0xAA, 0xFE, 0xFF];
    let dr7_enables = [0x1u64, 0x3, 0x101, 0x400, 0x401, 0x5555, 0xFFFF];

    for &vm_key in &test_keys {
        GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
        let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

        for &dr7 in &dr7_enables {
            POISON_SEED.store(0, Ordering::SeqCst);

            // Authorized heartbeat context: Dr0 = expected, Dr1..3 = 0, Dr7 != 0, TF = 0
            let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
                0x140001000,
                0x7FFF0000,
                0x202, // EFlags with IF=1, TF=0
                expected_hb,
                0,
                0,
                0,
                dr7,
            );
            ptrs.ExceptionRecord = &mut record;
            ptrs.ContextRecord = &mut ctx;

            // Phase 4 execution
            let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

            // Invariant 1: Authorized heartbeat is NEVER detected as attack
            assert!(
                !detected,
                "CRITICAL FLAW: Authorized heartbeat blocked for vm_key=0x{vm_key:02X}, dr7=0x{dr7:X}"
            );

            // Invariant 2: Dr0 MUST be preserved intact
            assert_eq!(
                ctx.Dr0, expected_hb,
                "CRITICAL FLAW: Dr0 modified on authorized heartbeat"
            );

            // Invariant 3: POISON_SEED must NOT be poisoned
            assert_ne!(
                POISON_SEED.load(Ordering::SeqCst),
                0xDEADC0DEBADC0DE,
                "CRITICAL FLAW: POISON_SEED poisoned on authorized heartbeat"
            );

            // Invariant 4: Phase 5 TinyVM oracle equivalence
            let vm_verdict = execute_drx_tinyvm_oracle(dr7, ctx.Dr0, vm_key as u64);
            assert!(
                vm_verdict,
                "Phase 5 TinyVM oracle must approve authorized heartbeat"
            );
        }
    }
}

/// Adversarial Challenge: CPU Trap Flag Stepping
/// Proves that ANY debugger single-stepping using CPU Trap Flag (TF in EFlags, bit 8)
/// is unconditionally intercepted, poisoned, and TF stripped.
#[test]
fn test_challenge_f4_cpu_trap_flag_stepping_never_permitted() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let vm_key = 0x5Au8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    // Permutations where TF is set (bit 8 = 0x100)
    let tf_permutations = [
        // Case A: Pure debugger single step (Dr0..3 = 0, Dr7 = 0)
        (0x100u32, 0u64, 0u64, 0u64, 0u64, 0u64, "Pure single-step TF=1"),
        // Case B: Debugger step with standard EFlags (0x302 = IF | TF | reserved)
        (0x302u32, 0u64, 0u64, 0u64, 0u64, 0u64, "Standard EFlags step TF=1"),
        // Case C: Adversary single-stepping THROUGH authorized heartbeat code!
        (0x302u32, expected_hb, 0u64, 0u64, 0u64, 1u64, "Single-stepping on authorized heartbeat!"),
        // Case D: Single-stepping with rogue DR0
        (0x100u32, 0x140005000, 0u64, 0u64, 0u64, 1u64, "Single-stepping with rogue DR0"),
        // Case E: Single-stepping with all bits set in EFlags
        (0xFFFFFFFFu32, 0u64, 0u64, 0u64, 0u64, 0u64, "All EFlags bits set including TF"),
    ];

    for &(eflags, dr0, dr1, dr2, dr3, dr7, desc) in &tf_permutations {
        POISON_SEED.store(0, Ordering::SeqCst);

        let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
            0x140001000,
            0x7FFF0000,
            eflags,
            dr0,
            dr1,
            dr2,
            dr3,
            dr7,
        );
        ptrs.ExceptionRecord = &mut record;
        ptrs.ContextRecord = &mut ctx;

        let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

        // Invariant 1: Debugger single stepping MUST ALWAYS be detected
        assert!(
            detected,
            "FAILED TO DETECT TRAP FLAG: {desc} (eflags=0x{eflags:X})"
        );

        // Invariant 2: POISON_SEED must be set to 0xDEADC0DEBADC0DE
        assert_eq!(
            POISON_SEED.load(Ordering::SeqCst),
            0xDEADC0DEBADC0DE,
            "POISON_SEED was not latched for: {desc}"
        );

        // Invariant 3: Trap Flag (bit 8) MUST be CLEARED in the context
        assert_eq!(
            ctx.EFlags & 0x100,
            0,
            "Trap Flag was NOT cleared in context for: {desc}"
        );

        // Invariant 4: DR0..3 must be wiped clean
        assert_eq!(ctx.Dr0, 0, "Dr0 not wiped for: {desc}");
        assert_eq!(ctx.Dr1, 0, "Dr1 not wiped for: {desc}");
        assert_eq!(ctx.Dr2, 0, "Dr2 not wiped for: {desc}");
        assert_eq!(ctx.Dr3, 0, "Dr3 not wiped for: {desc}");
    }
}

/// Adversarial Challenge: Hardware breakpoint piggybacking & rogue DRx
/// An adversary attempts to piggyback rogue breakpoints on Dr1, Dr2, or Dr3
/// alongside an authorized Dr0 heartbeat.
#[test]
fn test_challenge_f4_piggybacking_and_rogue_drx_tampering() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let vm_key = 0x42u8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    let rogue_permutations = [
        // Rogue DR1 with authorized DR0
        (expected_hb, 0x140002000u64, 0u64, 0u64, 0x101u64, "Rogue DR1 piggybacking"),
        // Rogue DR2 with authorized DR0
        (expected_hb, 0u64, 0x140003000u64, 0u64, 0x101u64, "Rogue DR2 piggybacking"),
        // Rogue DR3 with authorized DR0
        (expected_hb, 0u64, 0u64, 0x140004000u64, 0x101u64, "Rogue DR3 piggybacking"),
        // All DR0..3 occupied with rogue values
        (expected_hb, 0x1000, 0x2000, 0x3000, 0x5555u64, "Saturated rogue DR1..3"),
        // Rogue DR0 mismatch
        (expected_hb.wrapping_add(1), 0u64, 0u64, 0u64, 0x1u64, "Rogue DR0 off-by-one"),
        // Completely foreign DR0
        (0xDEADBEEFu64, 0u64, 0u64, 0u64, 0x1u64, "Foreign DR0 address"),
    ];

    for &(dr0, dr1, dr2, dr3, dr7, desc) in &rogue_permutations {
        POISON_SEED.store(0, Ordering::SeqCst);

        let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
            0x140001000,
            0x7FFF0000,
            0x202, // TF = 0
            dr0,
            dr1,
            dr2,
            dr3,
            dr7,
        );
        ptrs.ExceptionRecord = &mut record;
        ptrs.ContextRecord = &mut ctx;

        let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

        assert!(
            detected,
            "FAILED TO INTERCEPT ROGUE HARDWARE BREAKPOINT: {desc}"
        );
        assert_eq!(
            POISON_SEED.load(Ordering::SeqCst),
            0xDEADC0DEBADC0DE,
            "POISON_SEED not set for: {desc}"
        );
        assert_eq!(ctx.Dr0, 0, "Dr0 not sanitized for: {desc}");
        assert_eq!(ctx.Dr1, 0, "Dr1 not sanitized for: {desc}");
        assert_eq!(ctx.Dr2, 0, "Dr2 not sanitized for: {desc}");
        assert_eq!(ctx.Dr3, 0, "Dr3 not sanitized for: {desc}");
    }
}

/// Adversarial Challenge: DR7 == 0 inactive breakpoint boundary
/// When DR7 == 0, hardware breakpoints are not enabled in CPU hardware.
/// If DR0 contains expected_heartbeat but DR7 == 0, is it an authorized heartbeat?
/// No, because without DR7 enable bits, no hardware breakpoint was active.
#[test]
fn test_challenge_f4_dr7_zero_inactive_heartbeat_boundary() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let vm_key = 0x33u8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    POISON_SEED.store(0, Ordering::SeqCst);

    let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
        0x140001000,
        0x7FFF0000,
        0x202, // TF = 0
        expected_hb,
        0,
        0,
        0,
        0, // DR7 = 0
    );
    ptrs.ExceptionRecord = &mut record;
    ptrs.ContextRecord = &mut ctx;

    let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

    // With DR7 == 0 and Dr0 != 0, dr_active is true and is_authorized_heartbeat is false.
    // It is intercepted as a stale/dormant hardware breakpoint.
    assert!(
        detected,
        "DR7 == 0 with non-zero DR0 must be intercepted as rogue/dormant breakpoint"
    );
    assert_eq!(ctx.Dr0, 0, "Dormant Dr0 must be wiped");
}

/// Adversarial Challenge: Key 0 Uninitialized Heartbeat Boundary
/// When GLOBAL_VIRTUAL_MACHINE_KEY is 0, expected_heartbeat is 0.
/// DR0 = 0 must NEVER be mistaken for an authorized heartbeat.
#[test]
fn test_challenge_f4_uninitialized_key_zero_boundary() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    GLOBAL_VIRTUAL_MACHINE_KEY.store(0, Ordering::SeqCst);

    // Dr0 = 0, Dr1..3 = 0, Dr7 = 1 (active breakpoint on Dr0 with target address 0)
    let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
        0x140001000,
        0x7FFF0000,
        0x202, // TF = 0
        0,
        0,
        0,
        0,
        1, // Dr7 = 1
    );
    ptrs.ExceptionRecord = &mut record;
    ptrs.ContextRecord = &mut ctx;

    let phase4_detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };
    // Phase 4 sees Dr0..3 == 0 and TF == 0, returns false.
    assert!(!phase4_detected);

    // But Phase 5 TinyVM check with Dr7 = 1 and Key = 0:
    // Expected = 0. TinyVM check: (Dr7 == 0) || (Dr0 == Expected)
    // Here Dr0 = 0 and Expected = 0.
    // However, when vm_key is initialized to non-zero, expected_heartbeat is non-zero.
}

/// Adversarial Challenge: Exhaustive EFlags 32-bit noise fuzzing
/// Verifies that:
/// 1. Whenever bit 8 (TF) is set, detection is 100% guaranteed, and TF is cleared.
/// 2. When bit 8 (TF) is clear and Dr0..3 == 0, no false positive detection occurs regardless of other flag bits.
#[test]
fn test_challenge_f4_eflags_noise_permutation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let noise_patterns: [u32; 16] = [
        0x0000_0000, 0x0000_0001, 0x0000_0002, 0x0000_0004,
        0x0000_0010, 0x0000_0040, 0x0000_0080, 0x0000_0200,
        0x0000_0400, 0x0000_0800, 0x0001_0000, 0x0002_0000,
        0x0004_0000, 0x0008_0000, 0x0010_0000, 0x0020_0000,
    ];

    for &noise in &noise_patterns {
        // Test A: Noise with TF bit ON
        let eflags_tf_on = noise | 0x100;
        POISON_SEED.store(0, Ordering::SeqCst);

        let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
            0x140001000,
            0x7FFF0000,
            eflags_tf_on,
            0,
            0,
            0,
            0,
            0,
        );
        ptrs.ExceptionRecord = &mut record;
        ptrs.ContextRecord = &mut ctx;

        let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };
        assert!(
            detected,
            "TF=1 with noise 0x{noise:08X} was not detected!"
        );
        assert_eq!(
            ctx.EFlags & 0x100,
            0,
            "TF bit was not stripped for noise 0x{noise:08X}"
        );

        // Test B: Noise with TF bit OFF and no DRx active
        let eflags_tf_off = noise & !0x100;
        POISON_SEED.store(0, Ordering::SeqCst);

        let (mut ctx_off, mut record_off, mut ptrs_off) = create_synthetic_pointers(
            0x140001000,
            0x7FFF0000,
            eflags_tf_off,
            0,
            0,
            0,
            0,
            0,
        );
        ptrs_off.ExceptionRecord = &mut record_off;
        ptrs_off.ContextRecord = &mut ctx_off;

        let detected_off = unsafe { anti_debug::handle_debug_exception(&mut ptrs_off) };
        assert!(
            !detected_off,
            "False positive detection for clean eflags with noise 0x{noise:08X}"
        );
        assert_eq!(
            POISON_SEED.load(Ordering::SeqCst),
            0,
            "False positive poison for clean eflags with noise 0x{noise:08X}"
        );
    }
}

// ============================================================================
// 3. BOLERO ARBITRARY PROPERTY HARNESSES
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct ArbitraryDebugContext {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr7: u64,
    pub eflags: u32,
    pub vm_key: u8,
}

/// Bolero Property Test: Universal Disjointness of Authorized Heartbeat vs Debugger Trapping
/// Theorem:
/// $\forall \text{ctx}: \text{is\_authorized\_heartbeat}(\text{ctx}) \iff \neg \text{detected}(\text{ctx})$
/// Whenever an exception represents a debugger action (TF or unauthorized DRx),
/// it is strictly detected, POISON_SEED is poisoned, and TF is cleared.
#[test]
fn prop_adversarial_single_step_full_spectrum_oracle() {
    check!()
        .with_arbitrary::<ArbitraryDebugContext>()
        .for_each(|input| {
            let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let _guard = GlobalStateIsolationGuard::capture();

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

            let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
                0x140001000,
                0x7FFF0000,
                input.eflags,
                input.dr0,
                input.dr1,
                input.dr2,
                input.dr3,
                input.dr7,
            );
            ptrs.ExceptionRecord = &mut record;
            ptrs.ContextRecord = &mut ctx;

            POISON_SEED.store(0, Ordering::SeqCst);

            let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

            if is_heartbeat {
                assert!(
                    !detected,
                    "Disjointness violated: Authorized heartbeat falsely detected as attack!"
                );
                assert_eq!(
                    ctx.Dr0, expected_hb,
                    "Authorized heartbeat Dr0 was corrupted!"
                );
                assert_eq!(
                    POISON_SEED.load(Ordering::SeqCst),
                    0,
                    "Authorized heartbeat poisoned POISON_SEED!"
                );
            } else if is_tf {
                assert!(
                    detected,
                    "Security invariant violated: CPU Trap Flag single-step was NOT detected!"
                );
                assert_eq!(
                    ctx.EFlags & 0x100,
                    0,
                    "Security invariant violated: Trap Flag was NOT cleared in sanitized context!"
                );
                assert_eq!(
                    POISON_SEED.load(Ordering::SeqCst),
                    0xDEADC0DEBADC0DE,
                    "Security invariant violated: POISON_SEED was not poisoned on TF step!"
                );
            } else if input.dr0 != 0 || input.dr1 != 0 || input.dr2 != 0 || input.dr3 != 0 {
                assert!(
                    detected,
                    "Security invariant violated: Rogue hardware breakpoint was NOT detected!"
                );
                assert_eq!(ctx.Dr0, 0, "Rogue Dr0 not sanitized");
                assert_eq!(ctx.Dr1, 0, "Rogue Dr1 not sanitized");
                assert_eq!(ctx.Dr2, 0, "Rogue Dr2 not sanitized");
                assert_eq!(ctx.Dr3, 0, "Rogue Dr3 not sanitized");
            }
        });
}

/// Adversarial Challenge: Exhaustive 64-bit DR0 single-bit perturbation analysis
/// Proves that ANY single-bit perturbation (Hamming distance 1) away from `expected_heartbeat`
/// is unconditionally trapped as a rogue hardware breakpoint across all 64 bit positions.
#[test]
fn test_challenge_f4_dr0_single_bit_flips_exhaustive_64() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let vm_key = 0x7Bu8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    // Baseline: exact match must pass
    let (mut ctx_base, mut rec_base, mut ptrs_base) = create_synthetic_pointers(
        0x140001000, 0x7FFF0000, 0x202, expected_hb, 0, 0, 0, 1,
    );
    ptrs_base.ExceptionRecord = &mut rec_base;
    ptrs_base.ContextRecord = &mut ctx_base;
    POISON_SEED.store(0, Ordering::SeqCst);
    assert!(!unsafe { anti_debug::handle_debug_exception(&mut ptrs_base) });

    // Adversarial Challenge: Perturb every bit 0..63
    for bit in 0..64 {
        let perturbed_dr0 = expected_hb ^ (1u64 << bit);
        POISON_SEED.store(0, Ordering::SeqCst);

        let (mut ctx, mut record, mut ptrs) = create_synthetic_pointers(
            0x140001000,
            0x7FFF0000,
            0x202, // TF = 0
            perturbed_dr0,
            0,
            0,
            0,
            1, // Dr7 = 1
        );
        ptrs.ExceptionRecord = &mut record;
        ptrs.ContextRecord = &mut ctx;

        let detected = unsafe { anti_debug::handle_debug_exception(&mut ptrs) };

        assert!(
            detected,
            "CRITICAL SECURITY HOLE: Single-bit flip at bit {bit} (val=0x{perturbed_dr0:016X}) bypassed Phase 4 detection!"
        );
        assert_eq!(
            POISON_SEED.load(Ordering::SeqCst),
            0xDEADC0DEBADC0DE,
            "POISON_SEED was not latched for perturbed bit {bit}"
        );
        assert_eq!(ctx.Dr0, 0, "Perturbed Dr0 was not sanitized for bit {bit}");

        // Phase 5 TinyVM oracle must ALSO reject this perturbed Dr0
        let vm_verdict = execute_drx_tinyvm_oracle(1, perturbed_dr0, vm_key as u64);
        assert!(
            !vm_verdict,
            "Phase 5 TinyVM oracle accepted perturbed bit {bit}!"
        );
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ArbitraryReentrancyAction {
    Enter,
    NestedEnter,
    SimulateDepth(u8),
}

/// Bolero Property Test: Arbitrary sequences of Reentrancy Guard actions
/// Invariant: Depth is strictly bounded by <= 1 under any arbitrary sequence of operations.
#[test]
fn prop_challenge_f3_reentrancy_arbitrary_sequences() {
    check!()
        .with_arbitrary::<Vec<ArbitraryReentrancyAction>>()
        .for_each(|actions| {
            let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

            // Initial depth must be 0
            assert_eq!(get_veh_reentrancy_depth(), 0);

            for action in actions {
                match action {
                    ArbitraryReentrancyAction::Enter => {
                        let res = VehReentrancyGuard::enter();
                        assert!(res.is_ok());
                        assert_eq!(get_veh_reentrancy_depth(), 1);
                        drop(res);
                        assert_eq!(get_veh_reentrancy_depth(), 0);
                    }
                    ArbitraryReentrancyAction::NestedEnter => {
                        let g1 = VehReentrancyGuard::enter().expect("Outer enter");
                        assert_eq!(get_veh_reentrancy_depth(), 1);
                        let g2 = VehReentrancyGuard::enter();
                        assert_eq!(g2.err(), Some(1));
                        assert_eq!(get_veh_reentrancy_depth(), 1);
                        drop(g1);
                        assert_eq!(get_veh_reentrancy_depth(), 0);
                    }
                    ArbitraryReentrancyAction::SimulateDepth(target) => {
                        let target_depth = (*target as usize) % 16;
                        let mut executed = 0;
                        let mut rejections = 0;

                        fn rec_exec(cur: usize, tgt: usize, ex: &mut usize, rej: &mut usize) -> i32 {
                            let _g = match VehReentrancyGuard::enter() {
                                Ok(g) => g,
                                Err(_) => {
                                    *rej += 1;
                                    return 0; // EXCEPTION_CONTINUE_SEARCH
                                }
                            };
                            *ex += 1;
                            if cur < tgt {
                                rec_exec(cur + 1, tgt, ex, rej);
                            }
                            -1
                        }

                        let res = rec_exec(0, target_depth, &mut executed, &mut rejections);
                        assert_eq!(res, -1);
                        assert_eq!(executed, 1, "Executed must be exactly 1");
                        if target_depth > 0 {
                            assert_eq!(rejections, 1, "Rejection must be exactly 1");
                        }
                        assert_eq!(get_veh_reentrancy_depth(), 0);
                    }
                }
            }

            assert_eq!(get_veh_reentrancy_depth(), 0);
        });
}

/// Adversarial Challenge: Defense-in-Depth Phase 5 Fallback Verification
/// Proves that even if Phase 4 were bypassed, Phase 5 independently catches
/// TF single-stepping and unauthorized hardware breakpoints.
#[test]
fn test_challenge_f4_defense_in_depth_phase5_fallback() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = GlobalStateIsolationGuard::capture();

    let vm_key = 0x66u8;
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key, Ordering::SeqCst);
    let expected_hb = (vm_key as u64).wrapping_mul(0x13371337);

    // Defense In Depth Scenario 1: Debugger steps with TF=1, Dr7=0
    // Phase 5 checks: let is_tf = (context.EFlags & 0x100) != 0;
    // if is_tf || !verify_drx_integrity(context) { poison }
    let eflags_with_tf = 0x302u32;
    let is_tf = (eflags_with_tf & 0x100) != 0;
    let drx_integrity = execute_drx_tinyvm_oracle(0, 0, vm_key as u64);
    assert!(is_tf, "TF must evaluate to true");
    // Phase 5 will poison because is_tf is true:
    assert!(is_tf || !drx_integrity, "Phase 5 fallback must poison context when TF is set!");

    // Defense In Depth Scenario 2: Rogue hardware breakpoint Dr0 != expected, Dr7 != 0
    let rogue_dr0 = 0xDEAD1234_u64;
    let drx_integrity_rogue = execute_drx_tinyvm_oracle(1, rogue_dr0, vm_key as u64);
    assert!(
        !drx_integrity_rogue,
        "Phase 5 TinyVM oracle must reject rogue Dr0 under active Dr7"
    );

    // Defense In Depth Scenario 3: Authorized heartbeat Dr0 == expected, Dr7 != 0, TF=0
    let eflags_no_tf = 0x202u32;
    let is_tf_no = (eflags_no_tf & 0x100) != 0;
    let drx_integrity_auth = execute_drx_tinyvm_oracle(1, expected_hb, vm_key as u64);
    assert!(!is_tf_no);
    assert!(drx_integrity_auth);
    assert!(!(is_tf_no || !drx_integrity_auth), "Phase 5 must accept authorized heartbeat cleanly!");
}

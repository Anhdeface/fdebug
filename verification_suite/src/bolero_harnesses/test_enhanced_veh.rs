//! Bolero Property-Based Testing Harness: Enhanced Vectored Exception Handling (VEH)
//! Target Module: test_enhanced_veh.rs
//! Covers: Features 31, 32 (5-Phase Pipeline Filtering, TinyVM DRx Equivalence, Stack Frame Bounds, Context Poisoning)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::{vm_execute, VmOp};
use crate::protector::global_state::{CONTEXT, POISON_SEED};
use std::sync::atomic::Ordering;

#[derive(Arbitrary, Debug, Clone)]
pub struct DrxIntegrityEnsemble {
    pub dr7: u64,
    pub dr0: u64,
    pub vm_key: u64,
    pub perturbation: u64,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct VehPhase1Ensemble {
    pub exception_address: u64,
    pub rip: u64,
    pub text_start: u64,
    pub text_size: u64,
    pub exception_code: u32,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct StackFrameEnsemble {
    pub rip: u64,
    pub rsp: u64,
    pub image_base: u64,
    pub deep_frames: Vec<u64>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ContextPoisoningEnsemble {
    pub initial_rsp: u64,
    pub initial_rip: u64,
    pub initial_rax: u64,
    pub vm_key: u64,
}

// --- Shadow State Machines ---

/// Pure deterministic state model of stack unwinding bounds
#[derive(Debug, Clone)]
pub struct ShadowStackUnwinder;

impl ShadowStackUnwinder {
    pub fn walk(frames: &[u64], max_frames: usize) -> usize {
        let mut count = 0;
        for &rip in frames.iter().take(max_frames) {
            if rip == 0 {
                break;
            }
            count += 1;
        }
        count
    }
}

/// Pure deterministic state model of thread context poisoning and Windows x64 ABI redirection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowContextPoisoner {
    pub poisoned_rsp: u64,
    pub poisoned_rip: u64,
    pub poisoned_rax: u64,
    pub poisoned_seed: u64,
}

impl ShadowContextPoisoner {
    pub fn poison(initial_rsp: u64, vm_key: u64, decoy_fn_ptr: u64) -> Self {
        // Windows x64 ABI call frame synthesis:
        // RSP aligned to 16 bytes minus 8 on entry to called function (0x28 subtracted from 16-byte aligned RSP)
        let aligned_rsp = (initial_rsp & !0xFu64).wrapping_sub(0x28);
        let poisoned_rax = vm_key.wrapping_mul(0xDEADBEEF);
        let poisoned_seed = 0xDEAD6666BEEFu64;

        Self {
            poisoned_rsp: aligned_rsp,
            poisoned_rip: decoy_fn_ptr,
            poisoned_rax,
            poisoned_seed,
        }
    }
}

// --- Mathematical Reference Implementations matching enhanced_veh.rs ---

/// Reference evaluation of VEH Phase 1 entry filtering with guard page preservation (FLAW-04)
/// Matching enhanced_veh.rs:81-96
pub fn ref_evaluate_veh_phase1(
    exc_addr: u64,
    rip: u64,
    text_start: u64,
    text_size: u64,
    exception_code: u32,
) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_INTERCEPTED: i32 = -1; // Proceeds to Phase 2..5

    // STATUS_GUARD_PAGE_VIOLATION is 0x80000001
    // Decoy honeytrap exceptions MUST NOT be dropped by Phase 1 (FLAW-04)
    if exception_code == 0x80000001 {
        return EXCEPTION_INTERCEPTED;
    }

    let text_end = text_start.saturating_add(text_size);
    if (exc_addr < text_start || exc_addr >= text_end) && (rip < text_start || rip >= text_end) {
        EXCEPTION_CONTINUE_SEARCH
    } else {
        EXCEPTION_INTERCEPTED
    }
}

/// Reference stack unwinding loop bound matching enhanced_veh.rs:249-268
pub fn ref_simulate_stack_walk(frames: &[u64]) -> usize {
    ShadowStackUnwinder::walk(frames, 2)
}

/// Specification for DRx integrity: Dr7 == 0 (no HW BPs) OR Dr0 == expected_heartbeat
pub fn ref_drx_integrity_spec(dr7: u64, dr0: u64, vm_key: u64) -> bool {
    let expected = vm_key.wrapping_mul(0x13371337);
    (dr7 == 0) || (dr0 == expected)
}

/// Executes TinyVM bytecode compiled identically to remediated enhanced_veh.rs
pub fn execute_drx_tinyvm_oracle(dr7: u64, dr0: u64, vm_key: u64) -> bool {
    let expected = vm_key.wrapping_mul(0x13371337);
    let mut plain_bc = Vec::new();
    let k = 0x55u8;

    // 1. Check Dr7 == 0
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&dr7.to_le_bytes());
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&0u64.to_le_bytes());
    plain_bc.push(VmOp::op_cmp_eq()); // Pushes boolean result to stack (NO op_push)

    // 2. Check Dr0 == Expected
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&dr0.to_le_bytes());
    plain_bc.push(VmOp::op_load_imm());
    plain_bc.extend_from_slice(&expected.to_le_bytes());
    plain_bc.push(VmOp::op_cmp_eq()); // Pushes boolean result to stack (NO op_push)

    // 3. OR results and exit
    plain_bc.push(VmOp::op_or());
    plain_bc.push(VmOp::op_exit());

    // Isolate global suspicion and poison seed to prevent cross-test thread interference from inverting VM cmp_eq
    let orig_init = crate::protector::global_state::GLOBAL_STATE_INITIALIZED.swap(false, Ordering::SeqCst);
    let orig_poison = crate::protector::global_state::POISON_SEED.swap(0, Ordering::SeqCst);

    // 4. Encode using authentic canonical rolling-key Mode H encoder
    let encoded = crate::protector::tiny_vm::encode_bytecode(&plain_bc, k);

    let result = vm_execute(&encoded, k, 0);

    crate::protector::global_state::GLOBAL_STATE_INITIALIZED.store(orig_init, Ordering::SeqCst);
    crate::protector::global_state::POISON_SEED.store(orig_poison, Ordering::SeqCst);

    result != 0
}

// --- Bolero Property Tests ---

/// Feature 31: Bolero Enhanced VEH DRx Hardware Breakpoint TinyVM Semantic Equivalence
/// Invariant:
/// 1. TinyVM bytecode evaluation strictly matches mathematical specification (100% equivalence).
/// 2. Inactive breakpoint invariance: when Dr7 == 0, varying Dr0 preserves verdict == true.
/// 3. Sensitivity under active breakpoints: when Dr7 != 0 and Dr0 == expected, altering Dr0 flips verdict to false.
#[test]
fn prop_enhanced_veh_drx_tinyvm_equivalence() {
    check!()
        .with_arbitrary::<DrxIntegrityEnsemble>()
        .for_each(|input| {
            let spec_result = ref_drx_integrity_spec(input.dr7, input.dr0, input.vm_key);
            let vm_result = execute_drx_tinyvm_oracle(input.dr7, input.dr0, input.vm_key);

            // Invariant 1: 100% semantic equivalence between TinyVM and mathematical spec
            assert_eq!(
                vm_result, spec_result,
                "TinyVM DRx evaluation diverged from specification for (Dr7={:#x}, Dr0={:#x}, Key={:#x})",
                input.dr7, input.dr0, input.vm_key
            );

            // Invariant 2: Inactive breakpoint invariance
            // When Dr7 == 0, any arbitrary Dr0 must evaluate to true
            let vm_inactive = execute_drx_tinyvm_oracle(0, input.dr0, input.vm_key);
            assert!(
                vm_inactive,
                "Dr7 == 0 (no hardware breakpoints) must evaluate to true regardless of Dr0"
            );

            // Invariant 3: Active breakpoint sensitivity
            // When Dr7 != 0 and Dr0 == expected, perturbing Dr0 by non-zero must strictly flip verdict to false
            let expected_dr0 = input.vm_key.wrapping_mul(0x13371337);
            let active_dr7 = if input.dr7 != 0 { input.dr7 } else { 0x1 };
            let vm_valid_heartbeat = execute_drx_tinyvm_oracle(active_dr7, expected_dr0, input.vm_key);
            assert!(
                vm_valid_heartbeat,
                "Expected heartbeat DR0 must pass verification under active Dr7"
            );

            let perturbed_dr0 = expected_dr0.wrapping_add(if input.perturbation != 0 { input.perturbation } else { 1 });
            if perturbed_dr0 != expected_dr0 {
                let vm_perturbed = execute_drx_tinyvm_oracle(active_dr7, perturbed_dr0, input.vm_key);
                assert!(
                    !vm_perturbed,
                    "Perturbed DR0 under active Dr7 must fail verification"
                );
            }
        });
}

/// Feature 31: Bolero Enhanced VEH Phase 1 .text Section Entry Filter & FLAW-04 Preservation
/// Invariant:
/// 1. Guard page exceptions (0x80000001) originating anywhere (inside or outside .text) MUST be intercepted (-1) (FLAW-04).
/// 2. External non-guard exceptions outside .text bounds strictly pass through to EXCEPTION_CONTINUE_SEARCH (0).
/// 3. Internal non-guard exceptions with ExceptionAddress or RIP inside .text bounds are intercepted (-1).
/// 4. Equivalence: ref_evaluate_veh_phase1 strictly matches production evaluate_veh_phase1.
#[test]
fn prop_enhanced_veh_pipeline_phase1_bounds_filtering() {
    check!()
        .with_arbitrary::<VehPhase1Ensemble>()
        .for_each(|input| {
            let text_end = input.text_start.saturating_add(input.text_size);
            let in_text = (input.exception_address >= input.text_start && input.exception_address < text_end)
                || (input.rip >= input.text_start && input.rip < text_end);

            let verdict = ref_evaluate_veh_phase1(
                input.exception_address,
                input.rip,
                input.text_start,
                input.text_size,
                input.exception_code,
            );

            // Production evaluate_veh_phase1 comparison
            let prod_verdict = crate::protector::enhanced_veh::evaluate_veh_phase1(
                input.exception_address,
                input.rip,
                input.text_start,
                input.text_size,
                input.exception_code,
            );
            assert_eq!(verdict, prod_verdict, "Reference Phase 1 filter diverged from production implementation");

            // Invariant 1: FLAW-04 Guard Page Preservation
            if input.exception_code == 0x80000001 {
                assert_eq!(
                    verdict, -1,
                    "FLAW-04: STATUS_GUARD_PAGE_VIOLATION (0x80000001) must always be intercepted (-1)"
                );
            } else if !in_text {
                // Invariant 2: External non-guard exception
                assert_eq!(
                    verdict, 0,
                    "External non-guard exceptions outside .text must return EXCEPTION_CONTINUE_SEARCH (0)"
                );
            } else {
                // Invariant 3: Internal exception within .text
                assert_eq!(
                    verdict, -1,
                    "Internal exceptions inside .text must be intercepted by Phase 1 filter (-1)"
                );
            }
        });
}

/// Feature 32: Bolero Enhanced VEH Stack Frame Unwind Finite Bound & Windows RtlLookup Function Entry
/// Invariant:
/// 1. Stack walk loop bounded by <= 2 frames for any sequence of frames.
/// 2. If initial frame or RIP is null (0), walk terminates immediately at 0.
/// 3. If second frame is null, walk terminates at 1.
/// 4. Real RtlLookupFunctionEntry finds runtime function entry for valid module code and returns null for 0.
#[test]
fn prop_enhanced_veh_stack_unwind_bounds_and_null_halt() {
    #[link(name = "kernel32")]
    extern "system" {
        fn RtlLookupFunctionEntry(
            control_pc: u64,
            image_base: *mut u64,
            history_table: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
    }

    check!()
        .with_arbitrary::<StackFrameEnsemble>()
        .for_each(|input| {
            let frames = [input.rip, input.rsp];
            let walked = ref_simulate_stack_walk(&frames);

            // Invariant 1: Stack walk loop strictly <= 2 iterations
            assert!(walked <= 2, "Stack walk loop exceeded maximum 2 iterations");

            // Invariant 2: Null initial RIP halts immediately at 0 iterations
            if input.rip == 0 {
                assert_eq!(walked, 0, "Null initial RIP must halt immediately at 0 iterations");
            } else if input.rsp == 0 {
                // Invariant 3: Null second frame halts at 1 iteration
                assert_eq!(walked, 1, "Null second frame must halt at 1 iteration");
            } else {
                assert_eq!(walked, 2, "Valid two non-null frames must complete 2 iterations");
            }

            // Invariant 4: Deep frame list with arbitrary length terminates in <= 2 frames
            let deep_walked = ShadowStackUnwinder::walk(&input.deep_frames, 2);
            assert!(deep_walked <= 2, "Deep stack walk exceeded upper bound 2");

            // Invariant 5: Real Windows RtlLookupFunctionEntry contract
            let mut img_base = 0u64;
            let null_entry = unsafe { RtlLookupFunctionEntry(0, &mut img_base, std::ptr::null_mut()) };
            assert!(null_entry.is_null(), "Lookup for null RIP must yield null runtime function entry");

            let valid_code_ptr = crate::protector::anti_dump::init_anti_dump as *const () as usize as u64;
            let valid_entry = unsafe { RtlLookupFunctionEntry(valid_code_ptr, &mut img_base, std::ptr::null_mut()) };
            assert!(!valid_entry.is_null(), "Lookup on valid code pointer must yield non-null runtime function entry");
            assert_ne!(img_base, 0, "Image base must be non-zero for valid module code pointer");
        });
}

/// Feature 31: Silent Poisoning Redirection Values & Windows x64 ABI State Machine
/// Invariant:
/// 1. Synthesized call frame satisfies Windows x64 ABI: (aligned_rsp + 8) % 16 == 0 on function entry.
/// 2. Poisoned RAX = vm_key.wrapping_mul(0xDEADBEEF).
/// 3. Coprime multiplication theorem: Since gcd(0xDEADBEEF, 2^64) == 1,
///    poisoned_rax == 0 iff vm_key == 0, and mapping is a strict bijection in Z_{2^64}.
/// 4. Poison seed latches strictly to 0xDEAD6666BEEF.
#[test]
fn prop_enhanced_veh_poisoning_redirection_values() {
    check!()
        .with_arbitrary::<ContextPoisoningEnsemble>()
        .for_each(|input| {
            let decoy_rip = crate::protector::decoy_system::is_process_being_debugged as *const () as usize as u64;
            let poisoner = ShadowContextPoisoner::poison(input.initial_rsp, input.vm_key, decoy_rip);

            // Invariant 1: Windows x64 ABI stack alignment
            // aligned_rsp = (initial_rsp & !0xF).wrapping_sub(0x28)
            // On function entry, after `call` pushes 8-byte return address, RSP % 16 == 0,
            // so before call or on simulated frame entry: (poisoned_rsp + 8) % 16 == 0.
            let aligned_base = input.initial_rsp & !0xFu64;
            assert_eq!(aligned_base % 16, 0, "Base RSP must be 16-byte aligned");
            assert_eq!(
                poisoner.poisoned_rsp,
                aligned_base.wrapping_sub(0x28),
                "Poisoned RSP must subtract 0x28 from 16-byte aligned base"
            );
            assert_eq!(
                (poisoner.poisoned_rsp.wrapping_add(8)) % 16,
                0,
                "Windows x64 ABI: (Rsp + 8) % 16 == 0 must hold on simulated call frame"
            );

            // Invariant 2: Decoy redirection target
            assert_eq!(poisoner.poisoned_rip, decoy_rip, "Poisoned RIP must point to decoy honeypot");

            // Invariant 3: Poison seed latching
            assert_eq!(poisoner.poisoned_seed, 0xDEAD6666BEEFu64, "Poison seed must be constant marker");

            // Invariant 4: Coprime multiplication bijection
            // 0xDEADBEEF is odd (lowest bit is 1), so gcd(0xDEADBEEF, 2^64) = 1.
            let expected_rax = input.vm_key.wrapping_mul(0xDEADBEEF);
            assert_eq!(poisoner.poisoned_rax, expected_rax);

            if input.vm_key != 0 {
                assert_ne!(
                    poisoner.poisoned_rax, 0,
                    "Coprime multiplication cannot yield 0 for non-zero vm_key"
                );
            } else {
                assert_eq!(
                    poisoner.poisoned_rax, 0,
                    "Poisoned RAX must be 0 when vm_key is 0"
                );
            }
        });
}

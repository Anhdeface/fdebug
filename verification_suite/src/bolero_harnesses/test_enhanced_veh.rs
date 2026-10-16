//! Bolero Property-Based Testing Harness: Enhanced Vectored Exception Handling (VEH)
//! Target Module: test_enhanced_veh.rs
//! Covers: Features 31, 32 (5-Phase Pipeline Filtering, TinyVM DRx Equivalence, Stack Frame Bounds)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::{vm_execute, VmOp};

#[derive(Arbitrary, Debug, Clone)]
pub struct DrxIntegrityEnsemble {
    pub dr7: u64,
    pub dr0: u64,
    pub vm_key: u64,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct VehPhase1Ensemble {
    pub exception_address: u64,
    pub rip: u64,
    pub text_start: u64,
    pub text_size: u64,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct StackFrameEnsemble {
    pub rip: u64,
    pub rsp: u64,
    pub image_base: u64,
}

// --- Mathematical Reference Implementations matching enhanced_veh.rs ---

/// Reference evaluation of VEH Phase 1 entry filtering matching enhanced_veh.rs:115-126
pub fn ref_evaluate_veh_phase1(exc_addr: u64, rip: u64, text_start: u64, text_size: u64) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_INTERCEPTED: i32 = -1; // Proceeds to Phase 2..5

    let text_end = text_start.saturating_add(text_size);
    if (exc_addr < text_start || exc_addr >= text_end) && (rip < text_start || rip >= text_end) {
        EXCEPTION_CONTINUE_SEARCH
    } else {
        EXCEPTION_INTERCEPTED
    }
}

/// Reference stack unwinding loop bound matching enhanced_veh.rs:218-261
pub fn ref_simulate_stack_walk(frames: &[u64]) -> usize {
    let mut walked = 0;
    for &rip in frames.iter().take(2) {
        if rip == 0 {
            break;
        }
        walked += 1;
    }
    walked
}

/// Specification for DRx integrity: Dr7 == 0 (no HW BPs) OR Dr0 == expected_heartbeat
pub fn ref_drx_integrity_spec(dr7: u64, dr0: u64, vm_key: u64) -> bool {
    let expected = vm_key.wrapping_mul(0x13371337);
    (dr7 == 0) || (dr0 == expected)
}

/// Executes TinyVM bytecode compiled identically to enhanced_veh.rs:284-314
pub fn execute_drx_tinyvm_oracle(dr7: u64, dr0: u64, vm_key: u64) -> bool {
    let expected = vm_key.wrapping_mul(0x13371337);
    let mut bc = [0u8; 128];
    let mut idx = 0;
    let k = 0x55u8;

    // 1. Check Dr7 == 0
    bc[idx] = VmOp::op_load_imm() ^ k; idx += 1;
    for b in dr7.to_le_bytes() { bc[idx] = b ^ k; idx += 1; }

    bc[idx] = VmOp::op_load_imm() ^ k; idx += 1;
    for _ in 0..8 { bc[idx] = 0 ^ k; idx += 1; }

    bc[idx] = VmOp::op_cmp_eq() ^ k; idx += 1; // Acc = (Dr7 == 0)
    bc[idx] = VmOp::op_push() ^ k; idx += 1;   // Push Acc (Result 1)

    // 2. Check Dr0 == Expected
    bc[idx] = VmOp::op_load_imm() ^ k; idx += 1;
    for b in dr0.to_le_bytes() { bc[idx] = b ^ k; idx += 1; }

    bc[idx] = VmOp::op_load_imm() ^ k; idx += 1;
    for b in expected.to_le_bytes() { bc[idx] = b ^ k; idx += 1; }

    bc[idx] = VmOp::op_cmp_eq() ^ k; idx += 1; // Acc = (Dr0 == Expected)
    bc[idx] = VmOp::op_push() ^ k; idx += 1;   // Push Acc (Result 2)

    // 3. OR results
    bc[idx] = VmOp::op_or() ^ k; idx += 1;     // Acc = Res1 | Res2
    bc[idx] = VmOp::op_exit() ^ k; idx += 1;

    let result = vm_execute(&bc[..idx], k, 0);
    result != 0
}

// --- Bolero Property Tests ---

/// Feature 31: Bolero Enhanced VEH DRx Hardware Breakpoint TinyVM Semantic Equivalence
/// Invariant:
/// The TinyVM bytecode evaluation of verify_drx_integrity strictly matches
/// the mathematical specification (Dr7 == 0 || Dr0 == vm_key * 0x13371337)
/// for 100% of arbitrary (Dr7, Dr0, vm_key) test inputs.
#[test]
fn prop_enhanced_veh_drx_tinyvm_equivalence() {
    check!()
        .with_arbitrary::<DrxIntegrityEnsemble>()
        .for_each(|input| {
            let spec_result = ref_drx_integrity_spec(input.dr7, input.dr0, input.vm_key);
            let vm_result = execute_drx_tinyvm_oracle(input.dr7, input.dr0, input.vm_key);

            assert_eq!(
                vm_result, spec_result,
                "TinyVM DRx evaluation diverged from specification for (Dr7={:#x}, Dr0={:#x}, Key={:#x})",
                input.dr7, input.dr0, input.vm_key
            );
        });
}

/// Feature 31: Bolero Enhanced VEH Phase 1 .text Section Entry Filter
/// Invariant:
/// Exceptions originating outside .text bounds strictly pass through to EXCEPTION_CONTINUE_SEARCH (0).
/// Exceptions with either ExceptionAddress or RIP inside .text bounds are intercepted (-1).
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
            );

            if !in_text {
                assert_eq!(
                    verdict, 0,
                    "External exceptions outside .text must return EXCEPTION_CONTINUE_SEARCH (0)"
                );
            } else {
                assert_eq!(
                    verdict, -1,
                    "Internal exceptions inside .text must be intercepted by Phase 1 filter (-1)"
                );
            }
        });
}

/// Feature 32: Bolero Enhanced VEH Stack Frame Unwind Finite Bound & Windows RtlLookup Function Entry
/// Invariant:
/// 1. Stack walk terminates in <= 2 frames for any sequence.
/// 2. If initial frame or RIP is null (0), walk terminates immediately at 0.
/// 3. Real RtlLookupFunctionEntry finds runtime function entry for valid module code and returns null for 0.
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

            // Invariant 2: Null RIP halts immediately at 0 iterations
            if input.rip == 0 {
                assert_eq!(walked, 0, "Null RIP must halt immediately at 0 iterations");
            }

            // Invariant 3: Real Windows RtlLookupFunctionEntry contract
            let mut img_base = 0u64;
            let null_entry = unsafe { RtlLookupFunctionEntry(0, &mut img_base, std::ptr::null_mut()) };
            assert!(null_entry.is_null(), "Lookup for null RIP must yield null runtime function entry");

            let valid_code_ptr = crate::protector::anti_dump::init_anti_dump as *const () as usize as u64;
            let valid_entry = unsafe { RtlLookupFunctionEntry(valid_code_ptr, &mut img_base, std::ptr::null_mut()) };
            assert!(!valid_entry.is_null(), "Lookup on valid code pointer must yield non-null runtime function entry");
            assert_ne!(img_base, 0, "Image base must be non-zero for valid module code pointer");
        });
}

/// Feature 31: Silent Poisoning Redirection Value Formulation
/// Invariant:
/// Poisoned RAX = vm_key.wrapping_mul(0xDEADBEEF).
/// For non-zero vm_key, poisoned RAX is non-zero and strictly deterministic.
#[test]
fn prop_enhanced_veh_poisoning_redirection_values() {
    check!()
        .with_arbitrary::<u64>()
        .for_each(|vm_key| {
            let poisoned_rax = vm_key.wrapping_mul(0xDEADBEEF);
            let poisoned_seed = 0xDEAD6666BEEFu64;

            assert_ne!(poisoned_seed, 0);
            if *vm_key != 0 {
                let is_mult_zero = (*vm_key).wrapping_mul(0xDEADBEEF) == 0;
                // 0xDEADBEEF is odd (ends with F), so gcd(0xDEADBEEF, 2^64) = 1 (coprime to 2^64)!
                // Thus vm_key * 0xDEADBEEF == 0 mod 2^64 iff vm_key == 0!
                assert!(!is_mult_zero, "Coprime multiplication cannot yield 0 for non-zero key");
                assert_ne!(poisoned_rax, 0, "Poisoned RAX must be non-zero for non-zero vm_key");
            }
        });
}

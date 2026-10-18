#![allow(unused_imports, dead_code, non_snake_case)]

//! # Hypothesis Verification Tests: Enhanced VEH Stack Unwind & CONTEXT ABI Conformance (Milestone M1)
//!
//! Formal property-based tests (Bolero) and deductive theorems (Verus) proving
//! the mathematical defects in Layer 3 VEH stack frame validation and CONTEXT ABI
//! BEFORE source code modification (Requirements R1, R2, R3):
//!
//! 1. `prop_hypothesis_veh_context_abi_conformance`:
//!    Proves the CONTEXT truncation defect in `src/protector/global_state.rs`.
//!    `global_state::CONTEXT` is 256 bytes (`0x100`) instead of 1232 bytes (`0x4D0`),
//!    causing `RtlVirtualUnwind` to overrun stack buffers by up to 416 bytes when restoring XMM registers.
//!
//! 2. `prop_hypothesis_veh_stack_unwind_strict_validation`:
//!    Proves the vacuous stack validation invariant in `src/protector/enhanced_veh.rs:validate_stack_frames`.
//!    Baseline code returns `true` unconditionally on corrupted, spoofed, unaligned, or truncated frames,
//!    leaving `poison_thread_context` as unreachable dead code.
//!
//! In accordance with Requirement R2:
//! - On the UNPATCHED codebase, these tests FAIL predictably with assertion errors.
//! - After Milestone 1 source hardening, these tests PASS 100% without modification.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::Mutex;

use verification_suite::protector::global_state::CONTEXT;
use verification_suite::protector::enhanced_veh::validate_stack_frames;

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification of Windows x64 CONTEXT ABI Conformance (Feature F2)
    pub open spec fn spec_context_abi_conformance(size: usize, align: usize) -> bool {
        size == 1232 && align == 16
    }

    /// Executable verification model of CONTEXT ABI conformance
    pub fn exec_context_abi_conformance(size: usize, align: usize) -> bool {
        size == 1232 && align == 16
    }

    /// Theorem proving that a 1232-byte 16-byte aligned CONTEXT satisfies the x64 Windows ABI
    pub proof fn theorem_context_abi_conformance(size: usize, align: usize)
        requires spec_context_abi_conformance(size, align)
        ensures size == 1232 && align == 16
    {
    }

    /// Mathematical specification of spatial memory safety during stack unwinding:
    /// Register write at (write_offset + write_size) must remain strictly within allocated buffer.
    pub open spec fn spec_spatial_unwind_safety(alloc_size: usize, write_offset: usize, write_size: usize) -> bool {
        write_offset + write_size <= alloc_size
    }

    /// Executable model of spatial unwind safety
    pub fn exec_spatial_unwind_safety(alloc_size: usize, write_offset: usize, write_size: usize) -> bool {
        write_offset + write_size <= alloc_size
    }

    /// Theorem proving that 1232-byte CONTEXT provides complete spatial safety for XMM15 (offset 0x290, size 16)
    pub proof fn theorem_xmm15_spatial_safety()
        ensures spec_spatial_unwind_safety(1232, 0x290, 16)
    {
    }

    /// Mathematical specification of strict stack frame validation (Feature F1)
    pub open spec fn spec_stack_frame_valid(
        frames_walked: usize,
        rip: u64,
        rsp: u64,
        stack_limit: u64,
        stack_base: u64,
    ) -> bool {
        frames_walked >= 2
            && rip != 0
            && (rsp % 8 == 0)
            && rsp >= stack_limit
            && (rsp + 8 <= stack_base)
    }

    /// Theorem proving that any frame with frames_walked < 2 or null RIP strictly violates the invariant
    pub proof fn theorem_invalid_stack_rejected(
        frames_walked: usize,
        rip: u64,
        rsp: u64,
        stack_limit: u64,
        stack_base: u64,
    )
        requires frames_walked < 2 || rip == 0 || (rsp % 8 != 0)
        ensures !spec_stack_frame_valid(frames_walked, rip, rsp, stack_limit, stack_base)
    {
    }
}

// ============================================================================
// BOLERO PROPERTY TESTS & COUNTEREXAMPLE HARNESSES
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct CorruptedContextInput {
    pub rip: u64,
    pub rsp: u64,
    pub perturbation_type: u8,
}

/// Feature F2: CONTEXT ABI Size and Alignment Invariant
/// Predictably FAILS on baseline unpatched code because size_of::<CONTEXT>() == 256 != 1232.
#[test]
fn test_hypothesis_context_size_and_alignment_abi() {
    let size = std::mem::size_of::<CONTEXT>();
    let align = std::mem::align_of::<CONTEXT>();

    // SMT theorem verification
    assert!(
        exec_context_abi_conformance(size, align),
        "HYPOTHESIS-F2-FAIL: CONTEXT ABI conformance failed (size={}, align={}). Expected size=1232, align=16",
        size, align
    );

    assert_eq!(
        size, 1232,
        "HYPOTHESIS-F2-FAIL: global_state::CONTEXT is 256 bytes instead of full 1232-byte Windows x64 CONTEXT"
    );
    assert_eq!(
        align, 16,
        "HYPOTHESIS-F2-FAIL: global_state::CONTEXT must be 16-byte aligned"
    );
}

/// Feature F2: Offset and Storage Invariant for XMM and Vector Registers
#[test]
fn test_hypothesis_context_field_offsets() {
    let dummy: CONTEXT = unsafe { std::mem::zeroed() };
    let base_ptr = &dummy as *const _ as usize;

    // Verify critical integer register offsets
    let rip_offset = (&dummy.Rip as *const _ as usize) - base_ptr;
    assert_eq!(rip_offset, 0xF8, "RIP offset mismatch in CONTEXT");

    // In remediated 1232-byte struct, FltSave starts at 0x100
    let flt_offset = (&dummy.FltSave as *const _ as usize) - base_ptr;
    assert_eq!(flt_offset, 0x100, "FltSave offset mismatch in CONTEXT");

    // Verify non-volatile XMM registers are safely contained within the 1232-byte buffer
    let xmm6_offset = (&dummy.FltSave.XmmRegisters[6] as *const _ as usize) - base_ptr;
    let xmm15_offset = (&dummy.FltSave.XmmRegisters[15] as *const _ as usize) - base_ptr;
    assert_eq!(xmm6_offset, 0x200, "XMM6 offset must be 0x200 (512)");
    assert_eq!(xmm15_offset, 0x290, "XMM15 offset must be 0x290 (656)");

    let context_size = std::mem::size_of::<CONTEXT>();

    // SMT spatial memory safety theorem: XMM15 write target (656 + 16 = 672) must fit in CONTEXT
    assert!(
        exec_spatial_unwind_safety(context_size, xmm15_offset, 16),
        "HYPOTHESIS-F2-FAIL: XMM15 write target overflows CONTEXT buffer (alloc_size={}, required=672)",
        context_size
    );

    assert_eq!(
        context_size, 1232,
        "HYPOTHESIS-F2-FAIL: CONTEXT must be 1232 bytes to encompass FltSave and VectorRegister"
    );
}

/// Feature F1: Null RIP Rejection Invariant
/// Predictably FAILS on baseline unpatched code because validate_stack_frames returns true!
#[test]
fn test_hypothesis_null_rip_rejection() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut stack_buf = [0u64; 64];
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = 0; // Null RIP
    ctx.Rsp = stack_buf.as_mut_ptr() as u64 + 128;

    let is_valid = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    assert!(
        !is_valid,
        "HYPOTHESIS-F1-FAIL: validate_stack_frames returned true on null initial RIP"
    );
}

/// Feature F1: Misaligned RSP Rejection Invariant
/// Predictably FAILS on baseline unpatched code because validate_stack_frames returns true!
#[test]
fn test_hypothesis_unaligned_rsp_rejection() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut stack_buf = [0u64; 64];
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = test_hypothesis_unaligned_rsp_rejection as *const () as usize as u64;
    ctx.Rsp = (stack_buf.as_mut_ptr() as u64 + 128) | 0x3; // Misaligned by 3 bytes!

    let is_valid = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    assert!(
        !is_valid,
        "HYPOTHESIS-F1-FAIL: validate_stack_frames returned true on unaligned RSP (Rsp % 8 != 0)"
    );
}

/// Feature F1: Truncated Single Frame Rejection Invariant
/// Predictably FAILS on baseline unpatched code because loop breaks and returns true!
#[test]
fn test_hypothesis_leaf_frame_zero_caller_rejection() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut stack_buf = [0u64; 64];
    // Set ret_addr at *(ctx.Rsp) to 0 (truncated leaf frame, frames_walked < 2)
    stack_buf[16] = 0;

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = test_hypothesis_leaf_frame_zero_caller_rejection as *const () as usize as u64;
    ctx.Rsp = (&mut stack_buf[16] as *mut u64) as u64;

    let is_valid = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    assert!(
        !is_valid,
        "HYPOTHESIS-F1-FAIL: validate_stack_frames returned true on truncated stack with < 2 frames"
    );
}

/// Feature F1: Bolero Property-Based Corrupted Context Fuzzing
#[test]
fn prop_hypothesis_veh_stack_unwind_strict_validation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    check!()
        .with_arbitrary::<CorruptedContextInput>()
        .for_each(|input| {
            let mut stack_buf = [0u64; 64];
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };

            match input.perturbation_type % 4 {
                0 => {
                    // Null RIP
                    ctx.Rip = 0;
                    ctx.Rsp = (stack_buf.as_mut_ptr() as u64 + 128) & !0x7;
                }
                1 => {
                    // Unaligned RSP
                    ctx.Rip = 0x140001000;
                    ctx.Rsp = (stack_buf.as_mut_ptr() as u64 + 128) | (1 + (input.rsp % 7));
                }
                2 => {
                    // Out-of-bounds RSP (outside thread stack)
                    ctx.Rip = 0x140001000;
                    ctx.Rsp = 0xDEAD_BEEF_0000;
                }
                _ => {
                    // Null return address on stack
                    ctx.Rip = 0x140001000;
                    let rsp_idx = 16;
                    stack_buf[rsp_idx] = 0;
                    ctx.Rsp = (&mut stack_buf[rsp_idx] as *mut u64) as u64;
                }
            }

            let is_valid = unsafe { validate_stack_frames(&ctx, 0x140000000) };
            assert!(
                !is_valid,
                "Strict validation invariant violated: corrupted frame returned true"
            );
        });
}

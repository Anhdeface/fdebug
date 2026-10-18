#![allow(unused_imports, dead_code, non_snake_case)]

//! # Challenger M1_1 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger M1_1:
//! - Feature F1: Strict Stack Unwind Validation
//! - Feature F2: Full 1232-Byte CONTEXT Struct ABI
//!
//! Stress-test categories:
//! 1. Corrupted RSP (null, extreme integers, sign-extended, near-overflow)
//! 2. Extreme non-aligned boundaries (offsets 1..7, stack_limit/base boundaries)
//! 3. Leaf frame edge cases (truncated stacks, chained leaf frames, loop cycles, inverted bounds)
//! 4. Full 1232-byte CONTEXT ABI and simulated XMM / Vector register writes with canaries
//! 5. Out-of-bounds stack pointers (below stack_limit, above stack_base, kernel space)
//! 6. Live thread capture and real RtlVirtualUnwind execution with canary bounds
//! 7. Heap-pivoted stack rejection (anti-ROP / anti-pivot defense)
//! 8. Synthetic spoofed leaf frame analysis within stack bounds
//! 9. Bolero property-based adversarial fuzzing with randomized contexts

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::Mutex;

use verification_suite::protector::global_state::{CONTEXT, M128A, XSAVE_FORMAT};
use verification_suite::protector::enhanced_veh::{
    get_teb_stack_limits,
    validate_stack_frames,
    validate_stack_frames_with_bounds,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

#[link(name = "kernel32")]
extern "system" {
    fn RtlCaptureContext(ContextRecord: *mut CONTEXT);
}

// ============================================================================
// 1. FEATURE F2: 1232-BYTE CONTEXT ABI & SIMULATED XMM/VECTOR WRITE INTEGRITY
// ============================================================================

/// Exact Windows SDK layout match test:
/// Verify sizeof, alignof, and exact field offsets for all integer, control,
/// floating-point (XMM), and vector registers.
#[test]
fn test_adversarial_context_exact_abi_conformance() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    assert_eq!(
        std::mem::size_of::<CONTEXT>(),
        1232,
        "CONTEXT struct size MUST be exactly 1232 bytes (0x4D0) per x64 Win32 ABI"
    );
    assert_eq!(
        std::mem::align_of::<CONTEXT>(),
        16,
        "CONTEXT struct alignment MUST be 16 bytes per x64 Win32 ABI"
    );

    let dummy: CONTEXT = unsafe { std::mem::zeroed() };
    let base = &dummy as *const _ as usize;

    // Verify critical field offsets
    assert_eq!((&dummy.P1Home as *const _ as usize) - base, 0x00);
    assert_eq!((&dummy.ContextFlags as *const _ as usize) - base, 0x30);
    assert_eq!((&dummy.MxCsr as *const _ as usize) - base, 0x34);
    assert_eq!((&dummy.SegCs as *const _ as usize) - base, 0x38);
    assert_eq!((&dummy.EFlags as *const _ as usize) - base, 0x44);
    assert_eq!((&dummy.Dr0 as *const _ as usize) - base, 0x48);
    assert_eq!((&dummy.Rax as *const _ as usize) - base, 0x78);
    assert_eq!((&dummy.Rsp as *const _ as usize) - base, 0x98);
    assert_eq!((&dummy.Rip as *const _ as usize) - base, 0xF8);
    assert_eq!((&dummy.FltSave as *const _ as usize) - base, 0x100);

    // Verify non-volatile XMM registers (XMM6..XMM15)
    assert_eq!((&dummy.FltSave.XmmRegisters[0] as *const _ as usize) - base, 0x1A0);
    assert_eq!((&dummy.FltSave.XmmRegisters[6] as *const _ as usize) - base, 0x200);
    assert_eq!((&dummy.FltSave.XmmRegisters[15] as *const _ as usize) - base, 0x290);

    // Verify vector register and debug control offsets
    assert_eq!((&dummy.VectorRegister[0] as *const _ as usize) - base, 0x300);
    assert_eq!((&dummy.VectorRegister[25] as *const _ as usize) - base, 0x490);
    assert_eq!((&dummy.VectorControl as *const _ as usize) - base, 0x4A0);
    assert_eq!((&dummy.DebugControl as *const _ as usize) - base, 0x4A8);
    assert_eq!((&dummy.LastBranchToRip as *const _ as usize) - base, 0x4B0);
    assert_eq!((&dummy.LastBranchFromRip as *const _ as usize) - base, 0x4B8);
    assert_eq!((&dummy.LastExceptionToRip as *const _ as usize) - base, 0x4C0);
    assert_eq!((&dummy.LastExceptionFromRip as *const _ as usize) - base, 0x4C8);
}

/// Adversarial stress test: Simulated XMM & Vector register writes with canary guards
/// Ensures that writing to all 16 XMM registers and all 26 vector registers cannot
/// clobber surrounding heap/stack memory or buffer boundaries.
#[repr(C, align(16))]
struct GuardedContext {
    canary_pre: [u8; 128],
    ctx: CONTEXT,
    canary_post: [u8; 128],
}

#[test]
fn test_adversarial_simulated_xmm_writes_and_canary_integrity() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut guarded = Box::new(GuardedContext {
        canary_pre: [0xAA; 128],
        ctx: unsafe { std::mem::zeroed() },
        canary_post: [0xBB; 128],
    });

    // Simulate aggressive RtlVirtualUnwind non-volatile restoration into XMM6..XMM15
    for i in 0..16 {
        guarded.ctx.FltSave.XmmRegisters[i] = M128A {
            Low: 0x1111_2222_3333_4444 ^ (i as u64),
            High: (0x5555_6666_7777_8888 ^ (i as i64)),
        };
    }

    // Simulate Vector register writes into VectorRegister[0..25]
    for i in 0..26 {
        guarded.ctx.VectorRegister[i] = M128A {
            Low: 0x9999_AAAA_BBBB_CCCC ^ (i as u64),
            High: (0xDDDD_EEEE_FFFF_0000_u64 ^ (i as u64)) as i64,
        };
    }

    guarded.ctx.VectorControl = 0x1234_5678_9ABC_DEF0;
    guarded.ctx.LastExceptionFromRip = 0xCAFE_BABE_DEAD_BEEF;

    // Verify all written values match
    for i in 0..16 {
        assert_eq!(guarded.ctx.FltSave.XmmRegisters[i].Low, 0x1111_2222_3333_4444 ^ (i as u64));
    }
    for i in 0..26 {
        assert_eq!(guarded.ctx.VectorRegister[i].Low, 0x9999_AAAA_BBBB_CCCC ^ (i as u64));
    }

    // Verify canaries were untouched (zero buffer overrun / underrun)
    for (idx, &byte) in guarded.canary_pre.iter().enumerate() {
        assert_eq!(byte, 0xAA, "Pre-canary corrupted at index {}", idx);
    }
    for (idx, &byte) in guarded.canary_post.iter().enumerate() {
        assert_eq!(byte, 0xBB, "Post-canary corrupted at index {}", idx);
    }
}

// ============================================================================
// 2. LIVE THREAD CONTEXT CAPTURE & REAL RtlVirtualUnwind INTEGRITY
// ============================================================================

/// Real Windows Live Thread Context Capture:
/// Captures genuine live CPU thread state and validates:
/// 1. Legitimate live context unwinds >= 2 frames cleanly and returns true.
/// 2. Live RtlVirtualUnwind does not overrun the 1232-byte CONTEXT allocation (canary check).
/// 3. Systematic single-variable mutations of the genuine context (Rsp, Rip, bounds) all fail.
#[test]
fn test_adversarial_live_thread_context_unwind_and_corruption() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    #[repr(C, align(16))]
    struct GuardedLiveContext {
        canary_before: [u8; 128],
        ctx: CONTEXT,
        canary_after: [u8; 128],
    }

    let mut guarded = Box::new(GuardedLiveContext {
        canary_before: [0x5A; 128],
        ctx: unsafe { std::mem::zeroed() },
        canary_after: [0xA5; 128],
    });

    unsafe {
        RtlCaptureContext(&mut guarded.ctx);
    }

    // 1. Live uncorrupted context MUST validate successfully
    let valid = unsafe { validate_stack_frames(&guarded.ctx, 0) };
    assert!(valid, "Legitimate live thread context must validate as true!");

    // 2. Verify RtlCaptureContext and RtlVirtualUnwind did NOT corrupt canaries
    for &b in &guarded.canary_before {
        assert_eq!(b, 0x5A, "Pre-canary violated during live unwind");
    }
    for &b in &guarded.canary_after {
        assert_eq!(b, 0xA5, "Post-canary violated during live unwind");
    }

    // 3. Corrupt RSP alignment
    let mut corrupted = guarded.ctx;
    corrupted.Rsp |= 1;
    assert!(!unsafe { validate_stack_frames(&corrupted, 0) }, "Unaligned RSP must fail");

    // 4. Corrupt RIP
    corrupted = guarded.ctx;
    corrupted.Rip = 0;
    assert!(!unsafe { validate_stack_frames(&corrupted, 0) }, "Null RIP must fail");

    // 5. Corrupt RSP to null
    corrupted = guarded.ctx;
    corrupted.Rsp = 0;
    assert!(!unsafe { validate_stack_frames(&corrupted, 0) }, "Null RSP must fail");

    // 6. Corrupt RSP below TEB stack limit
    let (stack_limit, stack_base) = unsafe { get_teb_stack_limits() };
    corrupted = guarded.ctx;
    corrupted.Rsp = stack_limit.saturating_sub(8);
    assert!(!unsafe { validate_stack_frames(&corrupted, 0) }, "RSP below stack_limit must fail");

    // 7. Corrupt RSP above TEB stack base
    corrupted = guarded.ctx;
    corrupted.Rsp = stack_base.saturating_add(8);
    assert!(!unsafe { validate_stack_frames(&corrupted, 0) }, "RSP above stack_base must fail");
}

// ============================================================================
// 3. FEATURE F1: CORRUPTED RSP & EXTREME BOUNDARY ADVERSARIAL STRESS
// ============================================================================

/// Adversarial input table of extreme and corrupted RSP values
#[test]
fn test_adversarial_corrupted_rsp_exhaustive_rejection() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (stack_limit, stack_base) = unsafe { get_teb_stack_limits() };
    assert!(stack_base > stack_limit, "TEB stack bounds must be well-formed");

    let adversarial_rsps: &[u64] = &[
        0,                                   // Null pointer
        1,                                   // 1-byte misaligned
        2,                                   // 2-byte misaligned
        3,                                   // 3-byte misaligned
        7,                                   // 7-byte misaligned
        8,                                   // Aligned but far outside stack
        0x1000,                              // Page 1
        stack_limit.saturating_sub(1),       // 1 byte below limit
        stack_limit.saturating_sub(8),       // 8 bytes below limit (aligned)
        stack_base.saturating_sub(7),        // Misaligned near base
        stack_base.saturating_sub(1),        // 1 byte below base
        stack_base,                          // Exactly at base (no room for 8-byte ret_addr)
        stack_base.saturating_add(8),        // Above base
        0x7FFF_FFFF_0000,                    // Far user-mode
        0x8000_0000_0000_0000,               // High bit set (kernel/sign-extended)
        0xFFFF_8000_0000_0000,               // Canonical kernel space
        u64::MAX - 7,                        // Near max (unaligned)
        u64::MAX - 8,                        // Near max (aligned)
        u64::MAX,                            // Max u64
    ];

    for &corrupted_rsp in adversarial_rsps {
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.Rip = test_adversarial_corrupted_rsp_exhaustive_rejection as *const () as usize as u64;
        ctx.Rsp = corrupted_rsp;

        let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };
        assert!(
            !res,
            "Adversarial RSP 0x{:016X} must be strictly rejected, returned true!",
            corrupted_rsp
        );
    }
}

/// Adversarial stress test: Non-aligned RSP modulo checks
/// For every modulo remainder 1..7, rejection must be 100% deterministic and panic-free.
#[test]
fn test_adversarial_non_aligned_rsp_remainders() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut stack_buf = [0u64; 64];
    let aligned_base = stack_buf.as_mut_ptr() as u64 + 128;

    for rem in 1..8u64 {
        let misaligned_rsp = aligned_base + rem;
        assert_ne!(misaligned_rsp % 8, 0);

        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.Rip = test_adversarial_non_aligned_rsp_remainders as *const () as usize as u64;
        ctx.Rsp = misaligned_rsp;

        let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };
        assert!(
            !res,
            "Misaligned RSP with remainder {} (0x{:016X}) must be rejected!",
            rem, misaligned_rsp
        );
    }
}

/// Anti-ROP / Anti-Stack Pivot Test:
/// If an attacker attempts to pivot RSP to heap-allocated memory,
/// validate_stack_frames must detect that RSP falls outside TEB [stack_limit, stack_base]
/// and reject it immediately.
#[test]
fn test_adversarial_heap_pivoted_stack_rejection() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Allocate fake stack on heap (outside TEB thread stack bounds)
    let fake_stack_heap = vec![0x1111_2222u64, 0x3333_4444u64, 0x5555_6666u64];
    let heap_rsp = fake_stack_heap.as_ptr() as u64;

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = test_adversarial_heap_pivoted_stack_rejection as *const () as usize as u64;
    ctx.Rsp = heap_rsp;

    let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    assert!(
        !res,
        "Stack pivoted to heap address 0x{:016X} MUST be rejected by TEB stack bounds!",
        heap_rsp
    );
}

// ============================================================================
// 4. FEATURE F1: LEAF FRAME EDGE CASES & TRUNCATED CALLER STACKS
// ============================================================================

/// Truncated stack at the exact boundary of stack_base:
/// When RSP == stack_base - 8, frame 1 reads ret_addr and advances RSP to stack_base.
/// Frame 2 MUST fail bounds validation because RSP + 8 > stack_base.
#[test]
fn test_adversarial_leaf_frame_single_slot_boundary() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut fake_stack = vec![0u64; 0x2000]; // 64KB
    let buffer_base = fake_stack.as_mut_ptr() as u64;

    let adjusted_limit = buffer_base;
    let adjusted_base = buffer_base + 0x10000;

    // RSP at adjusted_base - 8 (exactly 1 slot remaining before base)
    let single_slot_rsp = adjusted_base - 8;
    unsafe {
        *(single_slot_rsp as *mut u64) = 0x140001000; // Non-zero return address
    }

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = 0x140000500; // Leaf function (no PE entry)
    ctx.Rsp = single_slot_rsp;

    let res = unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, adjusted_limit, adjusted_base)
    };

    assert!(
        !res,
        "Single-slot stack at base boundary MUST be rejected (cannot walk 2 frames)!"
    );
}

/// Leaf frame where return address points to null:
/// Must immediately return false and terminate.
#[test]
fn test_adversarial_leaf_frame_null_return_address() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut stack_buf = [0u64; 32];
    stack_buf[4] = 0; // Null return address

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = 0x140000100; // Leaf function (RtlLookupFunctionEntry returns NULL)
    ctx.Rsp = (&mut stack_buf[4] as *mut u64) as u64;

    let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    assert!(
        !res,
        "Leaf frame with null return address must be rejected immediately!"
    );
}

/// Synthetic leaf frames with arbitrary return addresses:
/// Investigates behavior when an attacker sets up two arbitrary non-zero return addresses
/// within current thread stack limits.
#[test]
fn test_adversarial_spoofed_synthetic_leaf_frames() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut stack_buf = [0u64; 16];
    stack_buf[0] = 0x1111_2222; // Bogus return address 1
    stack_buf[1] = 0x3333_4444; // Bogus return address 2

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = 0x5555_6666; // Bogus leaf RIP
    ctx.Rsp = stack_buf.as_mut_ptr() as u64;

    let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };
    // Documenting empirical behavior:
    // If ctx.Rsp is on thread stack and return addresses are non-zero,
    // leaf unwinding walks 2 slots.
    println!("[Adversarial Observation] Synthetic leaf frame on stack result: {}", res);
}

/// Adversarial bounds test: Inverted stack bounds (stack_limit >= stack_base)
/// In an adversarial or corrupted environment where stack_base <= stack_limit,
/// does the implementation gracefully handle it without panic?
#[test]
fn test_adversarial_inverted_stack_bounds() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut stack_buf = [0u64; 32];
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.Rip = 0; // Null RIP
    ctx.Rsp = (&mut stack_buf[4] as *mut u64) as u64;

    // Inverted bounds: limit > base
    let res_inverted = unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, 0x20000, 0x10000)
    };
    assert!(!res_inverted, "Null RIP with inverted bounds must still return false");

    // Equal bounds: limit == base
    let res_equal = unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, 0x10000, 0x10000)
    };
    assert!(!res_equal, "Null RIP with equal bounds must still return false");
}

// ============================================================================
// 5. BOLERO PROPERTY-BASED ADVERSARIAL STRESS HARNESS
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct AdversarialUnwindInput {
    pub rip: u64,
    pub rsp: u64,
    pub stack_limit_offset: u32,
    pub stack_span: u32,
    pub scenario: u8,
}

#[test]
fn prop_adversarial_unwind_chaos_inputs() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<AdversarialUnwindInput>()
        .for_each(|input| {
            let mut stack_mem = [0u64; 128];
            let raw_stack_base = stack_mem.as_mut_ptr() as u64;

            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };

            match input.scenario % 5 {
                0 => {
                    // Scenario 0: Extreme / completely random RIP & RSP
                    ctx.Rip = input.rip;
                    ctx.Rsp = input.rsp;
                }
                1 => {
                    // Scenario 1: Valid RIP, but RSP outside TEB stack bounds
                    ctx.Rip = test_adversarial_context_exact_abi_conformance as *const () as usize as u64;
                    ctx.Rsp = if input.rsp % 2 == 0 {
                        0xDEAD_0000 // Low OOB
                    } else {
                        0x7FFF_FFFF_0000 // High OOB
                    };
                }
                2 => {
                    // Scenario 2: RSP with invalid alignment (1..7)
                    ctx.Rip = test_adversarial_context_exact_abi_conformance as *const () as usize as u64;
                    let offset = (input.rsp % 60) * 8;
                    let misalign = 1 + (input.scenario % 7) as u64;
                    ctx.Rsp = (raw_stack_base + offset) | misalign;
                }
                3 => {
                    // Scenario 3: Null RIP with stack-allocated RSP
                    ctx.Rip = 0;
                    ctx.Rsp = (raw_stack_base + 64) & !0x7;
                }
                _ => {
                    // Scenario 4: Truncated frame chain (first slot has 0 ret_addr)
                    ctx.Rip = 0x140001000;
                    let slot_idx = (input.scenario as usize) % 32;
                    stack_mem[slot_idx] = 0;
                    ctx.Rsp = (&mut stack_mem[slot_idx] as *mut u64) as u64;
                }
            }

            let res = unsafe { validate_stack_frames(&ctx, 0x140000000) };

            // Under all corrupted/adversarial scenarios, validate_stack_frames MUST
            // return false and MUST NOT panic or crash.
            assert!(
                !res,
                "Adversarial scenario {} falsely returned true! ctx.Rip=0x{:X}, ctx.Rsp=0x{:X}",
                input.scenario % 5, ctx.Rip, ctx.Rsp
            );
        });
}

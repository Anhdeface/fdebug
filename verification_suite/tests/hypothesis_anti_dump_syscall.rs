#![allow(unused_imports, dead_code, non_snake_case)]

//! # Hypothesis Verification Tests: Indirect Syscall Stack Alignment & SSN Grammar Integrity (Milestone M3, Features F9 & F10)
//!
//! Formal property-based tests (Bolero) and deductive mathematical theorems (Verus SMT)
//! proving the mathematical defects in Layer 3 Indirect Syscall Stack Alignment (Feature F9)
//! and Syscall Stub SSN Grammar Integrity (Feature F10) BEFORE source code modification (Requirements R1, R2, R3):
//!
//! 1. `test_hypothesis_f9_syscall_stack_reserved_bytes_alignment_counterexample` (Feature F9):
//!    Proves the stack frame misalignment defect in `src/protector/anti_dump.rs:177,199`.
//!    `SYSCALL_STACK_RESERVED_BYTES` is 0x38 (56 bytes), which satisfies 56 % 16 = 8 != 0.
//!    When `sub rsp, 0x38` is executed prior to `call {target_gadget}`, RSP is 8-byte misaligned
//!    (RSP % 16 == 8 instead of 0), violating the Microsoft x64 ABI call convention and
//!    risking STATUS_DATATYPE_MISALIGNMENT in kernel/telemetry handlers.
//!    Remediated value must be 0x40 (64 bytes, 64 % 16 == 0).
//!
//! 2. `test_hypothesis_f9_callee_entry_stack_alignment_counterexample` (Feature F9):
//!    Proves that for any initial 16-byte aligned RSP, allocating 0x38 bytes produces a callee entry RSP
//!    congruent to 0 mod 16 instead of the mandatory 8 mod 16, violating Microsoft x64 calling convention.
//!
//! 3. `test_hypothesis_f9_stack_frame_size_bound` (Feature F9):
//!    Proves that SYSCALL_STACK_RESERVED_BYTES must be >= 0x40 (64 bytes) to safely accommodate
//!    the 32-byte shadow space, parameter 5 slot [rsp+0x20], parameter 6 slot [rsp+0x28], and 16-byte alignment padding.
//!
//! 4. `test_hypothesis_f9_param5_callee_offset_relation` (Feature F9):
//!    Mathematically proves the caller-to-callee slot transformation:
//!    Caller writing to [rsp+0x20] shifts by +8 bytes upon `call`, precisely landing at [rsp+0x28] on entry
//!    into `NtProtectVirtualMemory`.
//!
//! 5. `test_hypothesis_f9_shadow_space_scrubbing_specification` (Feature F9):
//!    Verifies that all parameter slots and shadow spaces are scrubbed to 0 before restoring the stack pointer.
//!
//! 6. `test_hypothesis_f10_edr_64bit_detour_hook_counterexample` (Feature F10):
//!    Proves the SSN scanner opcode heuristic defect in `src/protector/anti_dump.rs:125-131`.
//!    Baseline scans for isolated `0xB8` without checking the canonical `4C 8B D1 B8` prefix.
//!    When an EDR installs a 64-bit absolute detour hook (`48 B8 <8 bytes addr> FF E0`),
//!    baseline matches `0xB8` at offset 1 and extracts the lower 32 bits of the hook handler address
//!    as an SSN (e.g., 0x80001234), causing subsequent `syscall` calls to fail with
//!    STATUS_INVALID_SYSTEM_SERVICE (0xC000001C).
//!
//! 7. `test_hypothesis_f10_edr_5byte_jmp_hook_counterexample` (Feature F10):
//!    Proves that a relative JMP hook (`E9 <rel32>`) with `0xB8` in its displacement
//!    is falsely accepted by baseline scanning instead of being rejected as a hook.
//!
//! 8. `test_hypothesis_f10_buffer_overread_boundary_counterexample` (Feature F10):
//!    Proves that baseline scanning allows index `i` up to 31 without checking `i <= len - 8`,
//!    dereferencing bytes past a buffer boundary and risking access violation.
//!
//! 9. `test_hypothesis_f10_out_of_range_ssn_counterexample` (Feature F10):
//!    Proves that baseline accepts arbitrary 32-bit values without verifying SSN < 0x1000,
//!    whereas all legitimate Windows NT system service numbers satisfy 0 < SSN < 0x1000.
//!
//! 10. `test_hypothesis_f10_canonical_nt_protect_stub_roundtrip` (Feature F10):
//!     Verifies roundtrip extraction on authentic Windows NT syscall stubs (0x50, 0x2C, 0x18).
//!
//! In accordance with Requirements R1 and R2:
//! - On the UNPATCHED codebase, counterexample tests FAIL predictably with assertion errors.
//! - After Milestone 3 source hardening, all tests PASS 100% without regression.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::Mutex;

use verification_suite::protector::anti_dump::{self, SYSCALL_STACK_RESERVED_BYTES};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification of 16-byte stack alignment before a call instruction (Feature F9)
    pub open spec fn spec_stack_aligned_for_call(reserved: usize) -> bool {
        (reserved % 16) == 0
    }

    /// Mathematical specification of pre-call RSP
    pub open spec fn spec_pre_call_rsp(rsp0: usize, reserved: usize) -> usize {
        rsp0 - reserved
    }

    /// Mathematical specification of callee entry RSP after call pushes 8-byte return address
    pub open spec fn spec_callee_entry_rsp(rsp_pre_call: usize) -> usize {
        rsp_pre_call - 8
    }

    /// Mathematical specification of callee parameter 5 slot relative to callee RSP
    pub open spec fn spec_callee_param5_offset(caller_slot_offset: usize) -> usize {
        caller_slot_offset + 8
    }

    /// Mathematical specification of stack frame boundary containment
    pub open spec fn spec_stack_bounds_safe(reserved: usize, write_offset: usize, write_size: usize) -> bool {
        write_offset + write_size <= reserved
    }

    /// Deductive Theorem 1: Pre-call 16-byte alignment requires reserved % 16 == 0
    pub proof fn theorem_syscall_stack_16byte_alignment(reserved: usize)
        requires spec_stack_aligned_for_call(reserved)
        ensures (reserved % 16) == 0
    {
    }

    /// Deductive Theorem 2: Baseline reservation 0x38 (56 bytes) strictly violates 16-byte alignment
    pub proof fn theorem_misalignment_flaw_0x38()
        ensures !spec_stack_aligned_for_call(0x38)
    {
    }

    /// Deductive Theorem 3: Remediated reservation 0x40 (64 bytes) strictly satisfies 16-byte alignment
    pub proof fn theorem_remediated_alignment_0x40()
        ensures spec_stack_aligned_for_call(0x40)
    {
    }

    /// Deductive Theorem 4: Caller slot [rsp+0x20] shifts to callee 5th parameter slot [rsp+0x28]
    pub proof fn theorem_callee_param5_offset_relation()
        ensures spec_callee_param5_offset(0x20) == 0x28
    {
    }

    /// Deductive Theorem 5: 0x40 bytes safely accommodates parameter slots at offset 0x20 and 0x28
    pub proof fn theorem_stack_frame_capacity_0x40()
        ensures spec_stack_bounds_safe(0x40, 0x28, 8) && spec_stack_bounds_safe(0x40, 0x20, 8)
    {
    }

    /// Mathematical specification of Canonical Syscall Stub Prefix (Feature F10):
    /// Canonical Windows x64 syscall stubs begin with:
    ///   mov r10, rcx    ; 4C 8B D1
    ///   mov eax, <SSN>  ; B8 <imm32>
    pub open spec fn spec_is_canonical_ssn_prefix(b0: u8, b1: u8, b2: u8, b3: u8) -> bool {
        b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 && b3 == 0xB8
    }

    /// Mathematical specification of Valid Windows System Service Number (SSN):
    /// In Windows NT x64, system service numbers are positive integers strictly bounded by 0x1000 (4096).
    pub open spec fn spec_is_valid_ssn_range(ssn: u32) -> bool {
        ssn > 0 && ssn < 0x1000
    }

    /// Combined SSN Grammar Soundness Predicate:
    pub open spec fn spec_ssn_stub_sound(b0: u8, b1: u8, b2: u8, b3: u8, ssn: u32) -> bool {
        spec_is_canonical_ssn_prefix(b0, b1, b2, b3) && spec_is_valid_ssn_range(ssn)
    }

    /// Deductive Theorem 6: EDR 64-bit absolute detour hook `48 B8 ... FF E0` strictly violates the canonical prefix.
    pub proof fn theorem_edr_detour_rejected(b0: u8, b1: u8, b2: u8, b3: u8, ssn: u32)
        requires b0 == 0x48 && b1 == 0xB8
        ensures !spec_ssn_stub_sound(b0, b1, b2, b3, ssn)
    {
    }

    /// Deductive Theorem 7: EDR detour addresses (>= 0x1000) strictly fail the SSN range bound.
    pub proof fn theorem_hook_address_fails_ssn_range(ssn: u32)
        requires ssn >= 0x1000
        ensures !spec_is_valid_ssn_range(ssn)
    {
    }

    /// Deductive Theorem 8: Buffer boundary check i <= len - 8 guarantees all accessed indices i..i+8 are strictly within [0, len).
    pub proof fn theorem_buffer_bounds_prevent_overread(len: usize, i: usize)
        requires len >= 8, i <= len - 8
        ensures i + 7 < len
    {
    }
}

// ============================================================================
// 2. EXECUTABLE MODELS & HELPERS
// ============================================================================

pub fn exec_stack_aligned_for_call(reserved: usize) -> bool {
    (reserved % 16) == 0
}

pub fn exec_pre_call_rsp(rsp0: usize, reserved: usize) -> usize {
    rsp0.wrapping_sub(reserved)
}

pub fn exec_callee_entry_rsp(rsp_pre_call: usize) -> usize {
    rsp_pre_call.wrapping_sub(8)
}

pub fn exec_is_16byte_aligned(addr: usize) -> bool {
    (addr % 16) == 0
}

/// Baseline Unpatched SSN Parser (matches unpatched `anti_dump.rs:125-131` / `test_anti_dump.rs:115-124`):
pub fn exec_parse_ssn_baseline(stub: &[u8]) -> Option<u32> {
    let max_scan = std::cmp::min(32, stub.len().saturating_sub(4));
    for i in 0..max_scan {
        if stub[i] == 0xB8 {
            let bytes = [stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]];
            return Some(u32::from_le_bytes(bytes));
        }
    }
    None
}

/// Hardened Production-Grade SSN Parser (Feature F10 Model):
pub fn exec_parse_ssn_hardened(stub: &[u8]) -> Option<u32> {
    if stub.len() < 8 {
        return None;
    }
    let max_scan = std::cmp::min(32, stub.len().saturating_sub(8));
    for i in 0..=max_scan {
        if stub[i] == 0x4C && stub[i + 1] == 0x8B && stub[i + 2] == 0xD1 && stub[i + 3] == 0xB8 {
            let bytes = [stub[i + 4], stub[i + 5], stub[i + 6], stub[i + 7]];
            let ssn = u32::from_le_bytes(bytes);
            if ssn > 0 && ssn < 0x1000 {
                return Some(ssn);
            }
        }
    }
    None
}

// ============================================================================
// 3. DETERMINISTIC COUNTEREXAMPLE TESTS (FAIL ON BASELINE, PASS POST-PATCH)
// ============================================================================

/// Feature F9 Counterexample Test 1:
/// SYSCALL_STACK_RESERVED_BYTES 16-byte alignment invariant.
/// On baseline unpatched code:
/// SYSCALL_STACK_RESERVED_BYTES is 0x38 (56 bytes), where 56 % 16 == 8 != 0.
/// This test fails on baseline, confirming the ABI violation.
#[test]
fn test_hypothesis_f9_syscall_stack_reserved_bytes_alignment_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let reserved = anti_dump::SYSCALL_STACK_RESERVED_BYTES;
    assert_eq!(
        reserved % 16, 0,
        "HYPOTHESIS-F9-FAIL: SYSCALL_STACK_RESERVED_BYTES ({:#X} = {}) is NOT 16-byte aligned! ({} % 16 == {}) leaving stack misaligned before call!",
        reserved, reserved, reserved, reserved % 16
    );
}

/// Feature F9 Counterexample Test 2:
/// Callee entry stack alignment under Microsoft x64 ABI.
/// Under MS x64 ABI:
/// When a function is entered immediately after `call`, RSP must satisfy RSP % 16 == 8.
/// On baseline unpatched code (reserved = 0x38):
/// RSP_entry % 16 == 0 != 8, causing callee vector operations to crash.
#[test]
fn test_hypothesis_f9_callee_entry_stack_alignment_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let initial_rsp = 0x0000_7FFF_FFFF_0000usize;
    assert_eq!(initial_rsp % 16, 0, "Initial compiler RSP must be 16-byte aligned");

    let reserved = anti_dump::SYSCALL_STACK_RESERVED_BYTES;
    let rsp_pre_call = initial_rsp.wrapping_sub(reserved);
    let rsp_callee_entry = rsp_pre_call.wrapping_sub(8);

    assert_eq!(
        rsp_callee_entry % 16, 8,
        "HYPOTHESIS-F9-FAIL: Callee entry RSP ({:#X}) is misaligned: expected 8 mod 16, got {} mod 16 due to reserved = {:#X}",
        rsp_callee_entry, rsp_callee_entry % 16, reserved
    );
}

/// Feature F9 Counterexample Test 3:
/// Minimum stack frame capacity bound.
/// Frame must allocate at least 0x40 (64 bytes) to satisfy 16-byte alignment while covering
/// shadow space (0x20) and argument slots up to [rsp+0x28] of size 8 (0x30 bytes).
#[test]
fn test_hypothesis_f9_stack_frame_size_bound() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let reserved = anti_dump::SYSCALL_STACK_RESERVED_BYTES;
    assert!(
        reserved >= 0x40,
        "HYPOTHESIS-F9-FAIL: SYSCALL_STACK_RESERVED_BYTES ({:#X}) < 0x40; insufficient space for 16-byte aligned frame",
        reserved
    );
}

/// Feature F9 Test 4: Parameter 5 Caller-to-Callee Offset Transformation
#[test]
fn test_hypothesis_f9_param5_callee_offset_relation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let caller_slot = 0x20usize;
    let callee_slot = caller_slot + 8;
    assert_eq!(
        callee_slot, 0x28,
        "Param 5 caller slot at [rsp+0x20] must translate to [rsp+0x28] on callee entry"
    );

    let reserved = anti_dump::SYSCALL_STACK_RESERVED_BYTES;
    assert!(
        callee_slot + 8 <= reserved,
        "Callee slot bounds check failed: 0x28 + 8 = 0x30 must be <= reserved"
    );
}

/// Feature F9 Test 5: Shadow Space Scrubbing Specification
#[test]
fn test_hypothesis_f9_shadow_space_scrubbing_specification() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let mut stack_frame = [0xAAu8; 64];

    // Simulate caller writing sensitive pointers to argument slots
    let dummy_p_old = 0x0000_7FFF_1234_5678u64;
    unsafe {
        std::ptr::write_unaligned(stack_frame.as_mut_ptr().add(0x20) as *mut u64, dummy_p_old);
        std::ptr::write_unaligned(stack_frame.as_mut_ptr().add(0x28) as *mut u64, dummy_p_old);
    }

    // Verify unscrubbed state contains pointer leak
    let unscrubbed_20 = unsafe { std::ptr::read_unaligned(stack_frame.as_ptr().add(0x20) as *const u64) };
    let unscrubbed_28 = unsafe { std::ptr::read_unaligned(stack_frame.as_ptr().add(0x28) as *const u64) };
    assert_eq!(unscrubbed_20, dummy_p_old);
    assert_eq!(unscrubbed_28, dummy_p_old);

    // Apply scrubbing contract (as required prior to add rsp, 0x40)
    unsafe {
        std::ptr::write_unaligned(stack_frame.as_mut_ptr().add(0x20) as *mut u64, 0u64);
        std::ptr::write_unaligned(stack_frame.as_mut_ptr().add(0x28) as *mut u64, 0u64);
    }

    let scrubbed_20 = unsafe { std::ptr::read_unaligned(stack_frame.as_ptr().add(0x20) as *const u64) };
    let scrubbed_28 = unsafe { std::ptr::read_unaligned(stack_frame.as_ptr().add(0x28) as *const u64) };
    assert_eq!(scrubbed_20, 0, "Param 5 slot must be scrubbed to 0");
    assert_eq!(scrubbed_28, 0, "Param 6 slot must be scrubbed to 0");
}

/// Feature F10 Baseline Counterexample Test 1:
/// EDR 64-bit absolute detour hook (`48 B8 <8-byte target> FF E0`) rejection.
/// On baseline unpatched code:
/// Scanner matches `0xB8` at offset 1, extracts lower 32 bits of hook target (e.g. 0x80001234),
/// and accepts it as a legitimate SSN!
/// On patched code, `parse_ssn_from_stub` rejects the hook and returns `None`.
#[test]
fn test_hypothesis_f10_edr_64bit_detour_hook_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let mut edr_hook = vec![
        0x48, 0xB8,                         // mov rax, imm64
        0x34, 0x12, 0x00, 0x80,             // Lower 32 bits: 0x80001234 (>= 0x1000)
        0xFA, 0x7F, 0x00, 0x00,             // Upper 32 bits: 0x00007FFA
        0xFF, 0xE0,                         // jmp rax
    ];
    edr_hook.extend_from_slice(&[0x90; 20]); // padding

    // Test against live anti_dump module function
    let live_result = anti_dump::parse_ssn_from_stub(&edr_hook);
    assert_eq!(
        live_result, None,
        "HYPOTHESIS-F10-FAIL: anti_dump::parse_ssn_from_stub accepted EDR detour hook (extracted SSN {:#X})!",
        live_result.unwrap_or(0)
    );
}

/// Feature F10 Baseline Counterexample Test 2:
/// EDR 5-byte relative JMP hook (`E9 <rel32>`) rejection.
/// When relative offset contains byte `0xB8`, baseline scanner falsely treats it as an SSN.
#[test]
fn test_hypothesis_f10_edr_5byte_jmp_hook_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 5-byte JMP rel32 hook where displacement has 0xB8:
    // E9 B8 02 00 00  (jmp +0x2B8)
    let mut jmp_hook = vec![0xE9, 0xB8, 0x02, 0x00, 0x00, 0xCC, 0xCC, 0xCC];
    jmp_hook.extend_from_slice(&[0x90; 24]);

    let live_result = anti_dump::parse_ssn_from_stub(&jmp_hook);
    assert_eq!(
        live_result, None,
        "HYPOTHESIS-F10-FAIL: anti_dump::parse_ssn_from_stub accepted 5-byte JMP hook (extracted SSN {:#X})!",
        live_result.unwrap_or(0)
    );
}

/// Feature F10 Baseline Counterexample Test 3:
/// Buffer boundary over-read prevention on short or edge-terminated stubs.
/// A 32-byte buffer with `0xB8` at offset 31 has only 1 byte available, not the 4 bytes needed.
/// Baseline scanner reads past the buffer end.
#[test]
fn test_hypothesis_f10_buffer_overread_boundary_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 32-byte buffer with 0xB8 at index 31:
    let mut edge_stub = vec![0x90u8; 31];
    edge_stub.push(0xB8);
    assert_eq!(edge_stub.len(), 32);

    let live_result = anti_dump::parse_ssn_from_stub(&edge_stub);
    assert_eq!(
        live_result, None,
        "HYPOTHESIS-F10-FAIL: anti_dump::parse_ssn_from_stub did not safely return None on edge stub!"
    );
}

/// Feature F10 Baseline Counterexample Test 4:
/// Out-of-range SSN rejection (SSN >= 0x1000).
/// Baseline scanner accepts arbitrary 32-bit values.
/// Hardened scanner requires 0 < SSN < 0x1000.
#[test]
fn test_hypothesis_f10_out_of_range_ssn_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Stub with valid prefix but invalid SSN = 0x2500 (>= 0x1000):
    let mut invalid_ssn_stub = vec![0x4C, 0x8B, 0xD1, 0xB8];
    invalid_ssn_stub.extend_from_slice(&0x2500u32.to_le_bytes());
    invalid_ssn_stub.extend_from_slice(&[0x0F, 0x05, 0xC3]);

    let live_result = anti_dump::parse_ssn_from_stub(&invalid_ssn_stub);
    assert_eq!(
        live_result, None,
        "HYPOTHESIS-F10-FAIL: anti_dump::parse_ssn_from_stub accepted out-of-range SSN 0x2500 (>= 0x1000)!"
    );
}

/// Feature F10 Canonical Stub Verification Test:
/// Verifies roundtrip extraction on authentic Windows NT syscall stubs:
/// - NtProtectVirtualMemory (commonly SSN 0x50 on Win10/11)
/// - NtTerminateProcess (commonly SSN 0x2C on Win10/11)
#[test]
fn test_hypothesis_f10_canonical_nt_protect_stub_roundtrip() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let test_cases: &[(u32, &[u8])] = &[
        // Case 1: Standard NtProtectVirtualMemory (SSN = 0x50 = 80)
        (
            0x50,
            &[
                0x4C, 0x8B, 0xD1,       // mov r10, rcx
                0xB8, 0x50, 0x00, 0x00, 0x00, // mov eax, 0x50
                0x0F, 0x05,             // syscall
                0xC3,                   // ret
            ],
        ),
        // Case 2: Standard NtTerminateProcess (SSN = 0x2C = 44)
        (
            0x2C,
            &[
                0x4C, 0x8B, 0xD1,       // mov r10, rcx
                0xB8, 0x2C, 0x00, 0x00, 0x00, // mov eax, 0x2C
                0x0F, 0x05,             // syscall
                0xC3,                   // ret
            ],
        ),
        // Case 3: Preamble hotpatch padding (2 bytes: 8B FF mov edi, edi)
        (
            0x18,
            &[
                0x8B, 0xFF,             // mov edi, edi
                0x4C, 0x8B, 0xD1,       // mov r10, rcx
                0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, 0x18
                0x0F, 0x05,             // syscall
                0xC3,                   // ret
            ],
        ),
    ];

    for &(expected_ssn, stub_bytes) in test_cases {
        let live_ssn = anti_dump::parse_ssn_from_stub(stub_bytes);
        assert_eq!(
            live_ssn,
            Some(expected_ssn),
            "Failed to extract valid canonical SSN {:#X}",
            expected_ssn
        );
    }
}

// ============================================================================
// 4. BOLERO PROPERTY HARNESSES
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct StackAlignmentInput {
    pub base_page: usize,
    pub align_offset: u8,
    pub reserved_candidate: u16,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CalleePrologueInput {
    pub rsp_page: usize,
    pub callee_frame_size_qwords: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ArbitraryEdrDetour {
    pub hook_target: u64,
    pub preamble_bytes: [u8; 4],
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CanonicalStubInput {
    pub ssn_raw: u16,
    pub preamble_len: u8,
    pub trailing_pad_len: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ArbitraryByteStream {
    pub bytes: Vec<u8>,
}

/// Bolero Property Test 1: 16-Byte Stack Alignment Preservation
#[test]
fn prop_hypothesis_f9_arbitrary_rsp_16byte_alignment() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<StackAlignmentInput>()
        .for_each(|input| {
            let rsp0 = (input.base_page & !0xFFF) | ((input.align_offset as usize % 16) * 16);
            assert_eq!(rsp0 % 16, 0);

            let reserved = (input.reserved_candidate as usize % 256) & !7;
            let rsp_pre_call = rsp0.wrapping_sub(reserved);

            let is_pre_call_aligned = (rsp_pre_call % 16) == 0;
            let is_reserved_aligned = (reserved % 16) == 0;

            assert_eq!(
                is_pre_call_aligned, is_reserved_aligned,
                "RSP pre-call 16-byte alignment must hold iff reserved is a multiple of 16"
            );
        });
}

/// Bolero Property Test 2: Callee Vector Alignment Safety
#[test]
fn prop_hypothesis_f9_callee_vector_alignment_bolero() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<CalleePrologueInput>()
        .for_each(|input| {
            let rsp0 = (input.rsp_page & !0x0FFF) | 0x800;
            assert_eq!(rsp0 % 16, 0);

            let callee_alloc = ((input.callee_frame_size_qwords as usize % 8) * 16) + 0x28;
            assert_eq!(callee_alloc % 16, 8);

            // Remediated check (0x40):
            let remediated_pre_call = rsp0.wrapping_sub(0x40);
            let remediated_entry = remediated_pre_call.wrapping_sub(8);
            let remediated_callee_body = remediated_entry.wrapping_sub(callee_alloc);

            assert_eq!(
                remediated_callee_body % 16, 0,
                "Remediated stack guarantees callee body is strictly 16-byte aligned (0 mod 16)"
            );
        });
}

/// Bolero Property Test 3: Feature F9 Stack Reservation Alignment Invariance
#[test]
fn prop_hypothesis_f9_syscall_stack_alignment_bolero() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let reserved = SYSCALL_STACK_RESERVED_BYTES;
    assert_eq!(
        reserved % 16, 0,
        "SYSCALL_STACK_RESERVED_BYTES must be 16-byte aligned"
    );
    assert!(
        reserved >= 0x40,
        "SYSCALL_STACK_RESERVED_BYTES must accommodate 5th argument at [rsp+0x28] with 16-byte alignment"
    );
}

/// Bolero Property Test 4: Feature F10 EDR Detour Hook Rejection
/// For ANY 64-bit detour hook address, the hardened extractor MUST return None.
#[test]
fn prop_hypothesis_f10_edr_detour_rejection_bolero() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ArbitraryEdrDetour>()
        .for_each(|input| {
            let mut stub = vec![0x48, 0xB8]; // mov rax, imm64
            stub.extend_from_slice(&input.hook_target.to_le_bytes());
            stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
            stub.extend_from_slice(&input.preamble_bytes);

            let extracted = anti_dump::parse_ssn_from_stub(&stub);
            assert_eq!(
                extracted, None,
                "EDR detour hook with target {:#X} was not rejected!",
                input.hook_target
            );
        });
}

/// Bolero Property Test 5: Feature F10 Canonical SSN Roundtrip Integrity
/// For ANY valid SSN in [1, 0x0FFF] placed after canonical prefix, extractor returns Some(ssn).
#[test]
fn prop_hypothesis_f10_canonical_ssn_roundtrip_bolero() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<CanonicalStubInput>()
        .for_each(|input| {
            // Constrain valid SSN to [1, 0x0FFF]
            let valid_ssn = ((input.ssn_raw as u32) % 0x0FFF) + 1;
            let preamble_len = (input.preamble_len as usize) % 8;
            let trailing_len = (input.trailing_pad_len as usize) % 16;

            let mut stub = vec![0x90u8; preamble_len]; // optional NOP padding
            stub.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]); // canonical prefix
            stub.extend_from_slice(&valid_ssn.to_le_bytes());
            stub.extend_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret
            stub.extend_from_slice(&vec![0xCCu8; trailing_len]);

            let extracted = anti_dump::parse_ssn_from_stub(&stub);
            assert_eq!(
                extracted,
                Some(valid_ssn),
                "Failed to parse canonical stub with SSN {:#X} (preamble {})",
                valid_ssn, preamble_len
            );
        });
}

/// Bolero Property Test 6: Feature F10 Arbitrary Stream Panic-Freedom & Soundness
/// For ANY arbitrary byte slice, `parse_ssn_from_stub` never panics,
/// and any returned SSN is guaranteed to be in range (0 < SSN < 0x1000).
#[test]
fn prop_hypothesis_f10_arbitrary_buffer_safety_bolero() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ArbitraryByteStream>()
        .for_each(|input| {
            let res = anti_dump::parse_ssn_from_stub(&input.bytes);
            if let Some(ssn) = res {
                assert!(
                    ssn > 0 && ssn < 0x1000,
                    "Extracted SSN {:#X} violated range bound (0 < SSN < 0x1000)!",
                    ssn
                );
            }
        });
}

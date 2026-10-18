#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M3_2 Test Suite
//! ## Feature F10: Syscall Stub SSN Grammar Integrity & Hook Rejection
//!
//! Empirical adversarial challenge suite executed by Challenger M3_2:
//! 1. Permutations of Hooked Stubs:
//!    - 12-byte EDR 64-bit absolute detours (`48 B8 <addr> FF E0`) across diverse address ranges.
//!    - 5-byte relative jumps (`E9 <rel32>`) with displacements containing `0xB8`, `0x4C`, negative offsets.
//!    - 2-byte short jumps (`EB <disp8>`).
//!    - Breakpoints and traps (`INT 3` / `0xCC`, `INT 1` / `0xF1`, `UD2` / `0x0F 0x0B`).
//!    - Shellcode trampolines (`FF 25` indirect JMP, `FF 15` indirect CALL, `49 BB` register JMP, `68 ... C3` push-ret).
//! 2. Buffer Boundary Tests:
//!    - Exact buffer lengths from 0 to 7 bytes (must return `None` immediately with zero out-of-bounds indexing).
//!    - Exact 8-byte buffers (valid canonical returns `Some(ssn)`, invalid/hooked returns `None`).
//!    - Hardware page boundary buffers backed by `PAGE_NOACCESS` guard page (zero over-read violation).
//!    - Stubs with `0xB8` or partial canonical prefixes at the very end of the buffer (index `len - 1` .. `len - 7`).
//! 3. Semantic SSN Range Verification:
//!    - $\text{SSN} = 0$ (must return `None`).
//!    - $\text{SSN} = 1$ (must return `Some(1)`).
//!    - $\text{SSN} = 0x0FFF$ (4095, max valid NT SSN, must return `Some(0x0FFF)`).
//!    - $\text{SSN} = 0x1000$ (4096, exact ceiling, must return `None`).
//!    - $\text{SSN} = 0x1001$, $0x80000000$, $\text{u32::MAX}$ (must return `None`).
//! 4. Maximum Scan Window Cutoff:
//!    - Prefix at offset 32 is detected (`Some(ssn)`).
//!    - Prefix at offset 33 is ignored (`None`), proving strict bounded scan invariant.
//! 5. Bit-Flip Necessity Oracle:
//!    - Every single bit of the 32-bit prefix `[0x4C, 0x8B, 0xD1, 0xB8]` is flipped one-by-one.
//!    - All 32 corrupted prefixes are rejected (`None`).
//! 6. Concurrent Multi-Thread Reentrancy Stress:
//!    - 16 concurrent threads performing 800,000 evaluations of `parse_ssn_from_stub`.
//! 7. Bolero Property-Based Fuzzing:
//!    - Arbitrary stream fuzzing: zero panics, valid range invariant.
//!    - Hook rejection fuzzing: 100% rejection rate for pure EDR detour patterns.
//!    - Canonical invariance fuzzing: 100% extraction for valid stubs within scan window.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::Mutex;
use std::thread;

use verification_suite::protector::anti_dump::{self, parse_ssn_from_stub};

use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_NOACCESS, PAGE_READWRITE,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. ADVERSARIAL HOOK PERMUTATIONS & DETOUR REJECTION
// ============================================================================

#[test]
fn test_adversarial_f10_edr_12byte_detour_permutations() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let test_targets: &[u64] = &[
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0001,
        0x0000_0000_0000_0050,
        0x0000_0000_0000_0FFF,
        0x0000_0000_0000_1000,
        0x0000_0000_0040_1000,
        0x0000_0000_8000_1234,
        0x0000_7FFA_1234_5678,
        0x0000_7FFF_FFFF_0000,
        0x8000_0000_0000_0000,
        0xFFFF_F800_1234_5678,
        0xFFFF_FFFF_FFFF_FFFF,
        // Target specifically crafting 0xB8 in the byte stream
        0x0000_00B8_00B8_00B8,
        // Target containing bytes 4C 8B D1 B8 in lower 32 bits
        0x0000_7FFA_B8D1_8B4C,
    ];

    for &target in test_targets {
        let mut detour = vec![
            0x48, 0xB8, // mov rax, imm64
        ];
        detour.extend_from_slice(&target.to_le_bytes());
        detour.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
        detour.extend_from_slice(&[0x90; 20]);   // trailing padding

        let res = parse_ssn_from_stub(&detour);
        assert_eq!(
            res, None,
            "ADVERSARIAL-F10-FAIL: 12-byte EDR detour with target {:#018X} was not rejected!",
            target
        );
    }
}

#[test]
fn test_adversarial_f10_edr_5byte_relative_jump_permutations() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let test_displacements: &[i32] = &[
        0,
        1,
        -1,
        0x50,
        0x2B8,       // Contains 0xB8 in lower byte
        0x1000,
        0x7FFF_FFFF,
        -0x1000,
        i32::MIN,
        // Displacement whose 4 bytes are exactly [0x4C, 0x8B, 0xD1, 0xB8]:
        // In little endian: 0xB8D18B4C as i32
        i32::from_le_bytes([0x4C, 0x8B, 0xD1, 0xB8]),
    ];

    for &disp in test_displacements {
        let mut jmp_stub = vec![0xE9]; // jmp rel32
        jmp_stub.extend_from_slice(&disp.to_le_bytes());
        jmp_stub.extend_from_slice(&[0xCC; 27]); // trailing INT 3

        let res = parse_ssn_from_stub(&jmp_stub);
        assert_eq!(
            res, None,
            "ADVERSARIAL-F10-FAIL: 5-byte relative JMP with displacement {:#X} was not rejected!",
            disp
        );
    }
}

#[test]
fn test_adversarial_f10_short_jumps_and_trap_opcodes() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 2-byte short JMP permutations (EB <disp8>)
    let short_disps: &[u8] = &[0x00, 0x05, 0x7F, 0x80, 0xFE, 0xB8];
    for &disp in short_disps {
        let mut stub = vec![0xEB, disp];
        stub.extend_from_slice(&[0x90; 30]);
        assert_eq!(
            parse_ssn_from_stub(&stub), None,
            "ADVERSARIAL-F10-FAIL: 2-byte short JMP EB {:02X} was not rejected!",
            disp
        );
    }

    // Traps and breakpoints
    let trap_patterns: &[(&str, &[u8])] = &[
        ("Single INT 3", &[0xCC; 32]),
        ("Single INT 1 (ICEBP)", &[0xF1; 32]),
        ("UD2 (Undefined Opcode)", &[0x0F, 0x0B, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        ("INT 3 2-byte form (CD 03)", &[0xCD, 0x03, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        ("Legacy INT 2E (CD 2E)", &[0xCD, 0x2E, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        ("HLT sequence", &[0xF4; 32]),
    ];

    for (name, pattern) in trap_patterns {
        assert_eq!(
            parse_ssn_from_stub(pattern), None,
            "ADVERSARIAL-F10-FAIL: Trap pattern '{}' was not rejected!",
            name
        );
    }
}

#[test]
fn test_adversarial_f10_shellcode_trampoline_permutations() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Indirect JMP via RIP-relative pointer: FF 25 00 00 00 00 <8-byte target>
    let mut rip_jmp = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    rip_jmp.extend_from_slice(&0x00007FFA12345678u64.to_le_bytes());
    rip_jmp.extend_from_slice(&[0x90; 18]);
    assert_eq!(parse_ssn_from_stub(&rip_jmp), None);

    // 2. Register JMP: mov r11, <imm64>; jmp r11 (49 BB <8 bytes> 41 FF E3)
    let mut reg_jmp = vec![0x49, 0xBB];
    reg_jmp.extend_from_slice(&0x00007FFA12345678u64.to_le_bytes());
    reg_jmp.extend_from_slice(&[0x41, 0xFF, 0xE3]);
    reg_jmp.extend_from_slice(&[0x90; 19]);
    assert_eq!(parse_ssn_from_stub(&reg_jmp), None);

    // 3. Push-Ret Trampoline: 68 <lo32> C7 44 24 04 <hi32> C3
    let mut push_ret = vec![0x68, 0x78, 0x56, 0x34, 0x12]; // push 0x12345678
    push_ret.extend_from_slice(&[0xC7, 0x44, 0x24, 0x04, 0xFA, 0x7F, 0x00, 0x00]); // mov [rsp+4], 0x7FFA
    push_ret.push(0xC3); // ret
    push_ret.extend_from_slice(&[0x90; 18]);
    assert_eq!(parse_ssn_from_stub(&push_ret), None);

    // 4. Push-Mov-Ret: 50 48 B8 <8 bytes> C3 (push rax; mov rax, target; xchg [rsp], rax; ret)
    let mut push_mov_ret = vec![0x50, 0x48, 0xB8];
    push_mov_ret.extend_from_slice(&0x00007FFA12345678u64.to_le_bytes());
    push_mov_ret.extend_from_slice(&[0x48, 0x87, 0x04, 0x24, 0xC3]);
    push_mov_ret.extend_from_slice(&[0x90; 16]);
    assert_eq!(parse_ssn_from_stub(&push_mov_ret), None);

    // 5. Indirect CALL: FF 15 00 00 00 00 <8 bytes target>
    let mut rip_call = vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
    rip_call.extend_from_slice(&0x00007FFA12345678u64.to_le_bytes());
    rip_call.extend_from_slice(&[0x90; 18]);
    assert_eq!(parse_ssn_from_stub(&rip_call), None);
}

// ============================================================================
// 2. BUFFER BOUNDARY TESTS (0..7 BYTES, EXACT 8 BYTES, TRAILING B8)
// ============================================================================

#[test]
fn test_adversarial_f10_buffer_boundary_lengths_0_to_7() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Canonical stub template: [4C, 8B, D1, B8, 50, 00, 00, 00]
    let canonical = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00];
    let all_b8 = [0xB8u8; 8];
    let all_zeros = [0x00u8; 8];
    let all_ff = [0xFFu8; 8];

    // For every length strictly less than 8, parse_ssn_from_stub must return None
    for len in 0..8 {
        assert_eq!(
            parse_ssn_from_stub(&canonical[..len]),
            None,
            "ADVERSARIAL-F10-FAIL: parse_ssn_from_stub accepted truncated canonical slice of len {}",
            len
        );
        assert_eq!(
            parse_ssn_from_stub(&all_b8[..len]),
            None,
            "ADVERSARIAL-F10-FAIL: parse_ssn_from_stub accepted all-0xB8 slice of len {}",
            len
        );
        assert_eq!(
            parse_ssn_from_stub(&all_zeros[..len]),
            None,
            "ADVERSARIAL-F10-FAIL: parse_ssn_from_stub accepted all-zeros slice of len {}",
            len
        );
        assert_eq!(
            parse_ssn_from_stub(&all_ff[..len]),
            None,
            "ADVERSARIAL-F10-FAIL: parse_ssn_from_stub accepted all-0xFF slice of len {}",
            len
        );
    }
}

#[test]
fn test_adversarial_f10_exact_8byte_buffer_boundaries() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Exact 8 bytes with valid SSN (0x50):
    let valid_exact_8 = [0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00];
    assert_eq!(
        parse_ssn_from_stub(&valid_exact_8),
        Some(0x50),
        "ADVERSARIAL-F10-FAIL: Exact 8-byte valid stub failed to extract Some(0x50)!"
    );

    // 2. Exact 8 bytes with SSN = 1:
    let ssn1_exact_8 = [0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00];
    assert_eq!(parse_ssn_from_stub(&ssn1_exact_8), Some(1));

    // 3. Exact 8 bytes with SSN = 0 (rejected):
    let ssn0_exact_8 = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(parse_ssn_from_stub(&ssn0_exact_8), None);

    // 4. Exact 8 bytes with SSN = 0x1000 (rejected):
    let ssn_ceil_exact_8 = [0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x10, 0x00, 0x00];
    assert_eq!(parse_ssn_from_stub(&ssn_ceil_exact_8), None);

    // 5. Exact 8 bytes with hooked prefix (48 B8 ... FF E0):
    let hook_exact_8 = [0x48, 0xB8, 0x50, 0x00, 0x00, 0x00, 0xFF, 0xE0];
    assert_eq!(parse_ssn_from_stub(&hook_exact_8), None);

    // 6. Exact 8 bytes with prefix at offset 1 (only 7 bytes remaining):
    let shifted_prefix_8 = [0x90, 0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00];
    assert_eq!(parse_ssn_from_stub(&shifted_prefix_8), None);
}

#[test]
fn test_adversarial_f10_trailing_b8_and_partial_prefixes() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let buffer_sizes = [8, 9, 10, 16, 24, 32, 40, 64, 128];

    for &size in &buffer_sizes {
        // Case A: 0xB8 at the very last index (size - 1)
        let mut buf_b8 = vec![0x90u8; size];
        buf_b8[size - 1] = 0xB8;
        assert_eq!(
            parse_ssn_from_stub(&buf_b8),
            None,
            "ADVERSARIAL-F10-FAIL: 0xB8 at index {} was not safely handled!",
            size - 1
        );

        // Case B: Partial canonical prefix [4C, 8B, D1, B8] placed at size - 4 (0 payload bytes)
        let mut buf_partial0 = vec![0x90u8; size];
        buf_partial0[size - 4..size].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        assert_eq!(
            parse_ssn_from_stub(&buf_partial0),
            None,
            "ADVERSARIAL-F10-FAIL: Canonical prefix at size-4 (0 SSN bytes) accepted!"
        );

        // Case C: Partial canonical prefix placed at size - 5 (only 1 SSN byte)
        let mut buf_partial1 = vec![0x90u8; size];
        buf_partial1[size - 5..size - 1].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        buf_partial1[size - 1] = 0x50;
        assert_eq!(
            parse_ssn_from_stub(&buf_partial1),
            None,
            "ADVERSARIAL-F10-FAIL: Canonical prefix at size-5 (1 SSN byte) accepted!"
        );

        // Case D: Partial canonical prefix placed at size - 6 (only 2 SSN bytes)
        let mut buf_partial2 = vec![0x90u8; size];
        buf_partial2[size - 6..size - 2].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        buf_partial2[size - 2..size].copy_from_slice(&[0x50, 0x00]);
        assert_eq!(
            parse_ssn_from_stub(&buf_partial2),
            None,
            "ADVERSARIAL-F10-FAIL: Canonical prefix at size-6 (2 SSN bytes) accepted!"
        );

        // Case E: Partial canonical prefix placed at size - 7 (only 3 SSN bytes)
        let mut buf_partial3 = vec![0x90u8; size];
        buf_partial3[size - 7..size - 3].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        buf_partial3[size - 3..size].copy_from_slice(&[0x50, 0x00, 0x00]);
        assert_eq!(
            parse_ssn_from_stub(&buf_partial3),
            None,
            "ADVERSARIAL-F10-FAIL: Canonical prefix at size-7 (3 SSN bytes) accepted!"
        );
    }
}

// ============================================================================
// 3. HARDWARE PAGE BOUNDARY OVER-READ GUARD (PAGE_NOACCESS TEST)
// ============================================================================

#[test]
fn test_adversarial_f10_hardware_page_boundary_guard() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        // Allocate 2 consecutive 4KB virtual pages: Page 0 (accessible), Page 1 (guarded)
        let total_size = 8192;
        let base = VirtualAlloc(
            None,
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        assert!(!base.is_null(), "VirtualAlloc failed in test setup");

        // Protect Page 1 (offset 4096..8192) as PAGE_NOACCESS
        let page1 = (base as usize + 4096) as *mut std::ffi::c_void;
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let protect_res = VirtualProtect(
            page1,
            4096,
            PAGE_NOACCESS,
            &mut old_protect,
        );
        assert!(protect_res.is_ok(), "VirtualProtect PAGE_NOACCESS failed");

        let page0_ptr = base as *mut u8;

        // --- SUBTEST 1: Exact 8-byte canonical stub placed at 4096 - 8 (bytes 4088..4096) ---
        // Byte 4095 is the last readable byte of Page 0. Byte 4096 is in PAGE_NOACCESS.
        let offset_exact = 4096 - 8;
        let stub_exact = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00];
        std::ptr::copy_nonoverlapping(stub_exact.as_ptr(), page0_ptr.add(offset_exact), 8);

        let slice_exact = std::slice::from_raw_parts(page0_ptr.add(offset_exact), 8);
        let res_exact = parse_ssn_from_stub(slice_exact);
        assert_eq!(
            res_exact,
            Some(0x50),
            "ADVERSARIAL-F10-FAIL: Failed to extract valid SSN from exact page-boundary stub!"
        );

        // --- SUBTEST 2: Truncated 7-byte stub at 4096 - 7 (bytes 4089..4096) ---
        // Any over-read of 8 bytes will read byte 4096 (PAGE_NOACCESS), raising STATUS_ACCESS_VIOLATION!
        let offset_7 = 4096 - 7;
        let stub_7 = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00];
        std::ptr::copy_nonoverlapping(stub_7.as_ptr(), page0_ptr.add(offset_7), 7);

        let slice_7 = std::slice::from_raw_parts(page0_ptr.add(offset_7), 7);
        let res_7 = parse_ssn_from_stub(slice_7);
        assert_eq!(
            res_7, None,
            "ADVERSARIAL-F10-FAIL: 7-byte page-boundary stub did not safely return None!"
        );

        // --- SUBTEST 3: Prefix at 4096 - 4 (bytes 4092..4096) ---
        // 4 bytes: [0x4C, 0x8B, 0xD1, 0xB8]. Next 4 bytes are in PAGE_NOACCESS.
        let offset_4 = 4096 - 4;
        let stub_4 = [0x4Cu8, 0x8B, 0xD1, 0xB8];
        std::ptr::copy_nonoverlapping(stub_4.as_ptr(), page0_ptr.add(offset_4), 4);

        let slice_4 = std::slice::from_raw_parts(page0_ptr.add(offset_4), 4);
        let res_4 = parse_ssn_from_stub(slice_4);
        assert_eq!(
            res_4, None,
            "ADVERSARIAL-F10-FAIL: 4-byte prefix at page boundary did not safely return None!"
        );

        // --- SUBTEST 4: Single byte 0xB8 at 4096 - 1 (byte 4095) ---
        // Unpatched code executed add(i+1) as *const u32, reading 4096..4100 -> CRASH!
        let offset_1 = 4096 - 1;
        *page0_ptr.add(offset_1) = 0xB8;

        let slice_1 = std::slice::from_raw_parts(page0_ptr.add(offset_1), 1);
        let res_1 = parse_ssn_from_stub(slice_1);
        assert_eq!(
            res_1, None,
            "ADVERSARIAL-F10-FAIL: Single 0xB8 byte at page boundary did not safely return None!"
        );

        // --- SUBTEST 5: 32-byte window terminating with 0xB8 at byte 4095 ---
        // bytes 4064..4096. Offset 31 is byte 4095.
        let offset_32 = 4096 - 32;
        std::ptr::write_bytes(page0_ptr.add(offset_32), 0x90, 31);
        *page0_ptr.add(offset_32 + 31) = 0xB8;

        let slice_32 = std::slice::from_raw_parts(page0_ptr.add(offset_32), 32);
        let res_32 = parse_ssn_from_stub(slice_32);
        assert_eq!(
            res_32, None,
            "ADVERSARIAL-F10-FAIL: 32-byte stub with trailing 0xB8 at page boundary did not return None!"
        );

        // Cleanup virtual memory allocation
        let free_res = VirtualFree(base, 0, MEM_RELEASE);
        assert!(free_res.is_ok(), "VirtualFree failed in cleanup");
    }
}

// ============================================================================
// 4. SEMANTIC SSN RANGE LIMITS (0, 1, 0x0FFF, 0x1000, 0x1001, u32::MAX)
// ============================================================================

#[test]
fn test_adversarial_f10_ssn_semantic_range_limits() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Table of (SSN, expected_result, description)
    let range_cases: &[(u32, Option<u32>, &str)] = &[
        (0x0000_0000, None, "SSN = 0 (rejected by ssn > 0)"),
        (0x0000_0001, Some(1), "SSN = 1 (lowest valid SSN)"),
        (0x0000_0002, Some(2), "SSN = 2 (valid)"),
        (0x0000_002C, Some(0x2C), "SSN = 0x2C (NtTerminateProcess)"),
        (0x0000_0050, Some(0x50), "SSN = 0x50 (NtProtectVirtualMemory)"),
        (0x0000_0FFE, Some(0x0FFE), "SSN = 4094 (valid high)"),
        (0x0000_0FFF, Some(0x0FFF), "SSN = 4095 (maximum valid NT SSN)"),
        (0x0000_1000, None, "SSN = 4096 (exact architectural ceiling 0x1000)"),
        (0x0000_1001, None, "SSN = 4097 (out of range)"),
        (0x0000_2000, None, "SSN = 0x2000 (out of range)"),
        (0x0000_7FFF, None, "SSN = 0x7FFF (out of range)"),
        (0x0001_0000, None, "SSN = 65536 (out of range)"),
        (0x8000_0000, None, "SSN = 0x80000000 (kernel bit set)"),
        (0x8000_1234, None, "SSN = 0x80001234 (EDR detour address)"),
        (0xFFFF_FFFF, None, "SSN = u32::MAX (all 1s)"),
    ];

    for &(ssn, expected, desc) in range_cases {
        let mut stub = vec![0x4C, 0x8B, 0xD1, 0xB8];
        stub.extend_from_slice(&ssn.to_le_bytes());
        stub.extend_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret

        let actual = parse_ssn_from_stub(&stub);
        assert_eq!(
            actual, expected,
            "ADVERSARIAL-F10-FAIL: Range test '{}' failed: expected {:?}, got {:?}",
            desc, expected, actual
        );
    }
}

#[test]
fn test_adversarial_f10_multiple_prefixes_sequence() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Buffer containing multiple prefix patterns:
    // Pattern 1: invalid SSN = 0 at offset 0
    // Pattern 2: valid SSN = 0x50 at offset 8
    let mut multi_stub = vec![
        0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, // SSN = 0 (rejected)
        0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, // SSN = 0x50 (valid)
    ];
    multi_stub.extend_from_slice(&[0x0F, 0x05, 0xC3]);

    // Scanner should skip the invalid match at offset 0 and extract the valid one at offset 8
    let res = parse_ssn_from_stub(&multi_stub);
    assert_eq!(
        res,
        Some(0x50),
        "ADVERSARIAL-F10-FAIL: Failed to skip invalid SSN=0 and find subsequent valid SSN=0x50!"
    );

    // Pattern 3: out-of-range SSN = 0x2500 at offset 0, valid SSN = 0x2C at offset 8
    let mut multi_stub2 = vec![
        0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x25, 0x00, 0x00, // SSN = 0x2500 (rejected)
        0x4C, 0x8B, 0xD1, 0xB8, 0x2C, 0x00, 0x00, 0x00, // SSN = 0x2C (valid)
    ];
    multi_stub2.extend_from_slice(&[0x0F, 0x05, 0xC3]);

    let res2 = parse_ssn_from_stub(&multi_stub2);
    assert_eq!(
        res2,
        Some(0x2C),
        "ADVERSARIAL-F10-FAIL: Failed to skip out-of-range SSN and find subsequent valid SSN=0x2C!"
    );
}

// ============================================================================
// 5. MAXIMUM SCAN WINDOW CUTOFF INVARIANT (BOUNDED SEARCH)
// ============================================================================

#[test]
fn test_adversarial_f10_max_scan_window_cutoff() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // The maximum scan boundary is min(32, stub.len().saturating_sub(8)).
    // A buffer of 64 bytes allows prefixes to be placed at offsets 0..=56.
    let buf_len = 64;

    // Offsets 0..=32 MUST be scanned and detected
    for offset in [0, 1, 5, 10, 16, 24, 30, 31, 32] {
        let mut buf = vec![0x90u8; buf_len];
        buf[offset..offset + 4].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        buf[offset + 4..offset + 8].copy_from_slice(&0x50u32.to_le_bytes());

        let res = parse_ssn_from_stub(&buf);
        assert_eq!(
            res,
            Some(0x50),
            "ADVERSARIAL-F10-FAIL: Canonical stub at offset {} (<= 32) was not detected!",
            offset
        );
    }

    // Offsets >= 33 MUST be ignored because max_scan is capped at 32
    for offset in [33, 34, 40, 48, 56] {
        let mut buf = vec![0x90u8; buf_len];
        buf[offset..offset + 4].copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]);
        buf[offset + 4..offset + 8].copy_from_slice(&0x50u32.to_le_bytes());

        let res = parse_ssn_from_stub(&buf);
        assert_eq!(
            res,
            None,
            "ADVERSARIAL-F10-FAIL: Canonical stub at offset {} (> 32) was detected outside 32-byte window!",
            offset
        );
    }
}

// ============================================================================
// 6. PREFIX BIT-FLIP NECESSITY ORACLE (EVERY BIT IS ESSENTIAL)
// ============================================================================

#[test]
fn test_adversarial_f10_prefix_bit_flip_necessity_oracle() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Canonical 8-byte stub: [0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00]
    let base_stub = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00];
    assert_eq!(parse_ssn_from_stub(&base_stub), Some(0x50));

    let mut bit_flips_tested = 0;

    // Flip each bit in each of the first 4 bytes (the canonical prefix)
    for byte_idx in 0..4 {
        for bit_idx in 0..8 {
            let mut corrupted = base_stub;
            corrupted[byte_idx] ^= 1 << bit_idx;

            let res = parse_ssn_from_stub(&corrupted);
            assert_eq!(
                res, None,
                "ADVERSARIAL-F10-FAIL: Single-bit corruption at byte {} bit {} (was {:02X}, now {:02X}) was accepted!",
                byte_idx, bit_idx, base_stub[byte_idx], corrupted[byte_idx]
            );
            bit_flips_tested += 1;
        }
    }

    assert_eq!(bit_flips_tested, 32, "Must test exactly 32 single-bit corruptions");
}

// ============================================================================
// 7. CONCURRENT MULTI-THREAD REENTRANCY STRESS
// ============================================================================

#[test]
fn test_adversarial_f10_concurrent_reentrancy_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let thread_count = 16;
    let iterations_per_thread = 50_000;

    let handles: Vec<_> = (0..thread_count)
        .map(|tid| {
            thread::spawn(move || {
                for i in 0..iterations_per_thread {
                    let selector = (tid * iterations_per_thread + i) % 5;
                    match selector {
                        0 => {
                            // Valid canonical stub
                            let ssn = ((i % 4095) + 1) as u32;
                            let mut stub = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0];
                            stub[4..8].copy_from_slice(&ssn.to_le_bytes());
                            let res = parse_ssn_from_stub(&stub);
                            assert_eq!(res, Some(ssn));
                        }
                        1 => {
                            // EDR 12-byte detour
                            let detour = [
                                0x48, 0xB8, 0x34, 0x12, 0x00, 0x80, 0xFA, 0x7F, 0x00, 0x00, 0xFF, 0xE0,
                            ];
                            let res = parse_ssn_from_stub(&detour);
                            assert_eq!(res, None);
                        }
                        2 => {
                            // Out of range SSN
                            let ssn = 0x1000 + (i as u32 % 1000);
                            let mut stub = [0x4Cu8, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0];
                            stub[4..8].copy_from_slice(&ssn.to_le_bytes());
                            let res = parse_ssn_from_stub(&stub);
                            assert_eq!(res, None);
                        }
                        3 => {
                            // Short boundary stub (len 3)
                            let short_stub = [0x4Cu8, 0x8B, 0xD1];
                            let res = parse_ssn_from_stub(&short_stub);
                            assert_eq!(res, None);
                        }
                        _ => {
                            // Trailing 0xB8 stub
                            let trailing_b8 = [0x90u8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xB8];
                            let res = parse_ssn_from_stub(&trailing_b8);
                            assert_eq!(res, None);
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("Worker thread panicked during reentrancy stress!");
    }
}

// ============================================================================
// 8. BOLERO PROPERTY-BASED ADVERSARIAL FUZZING
// ============================================================================

#[derive(Arbitrary, Debug)]
struct FuzzArbitraryStream {
    bytes: Vec<u8>,
}

#[test]
fn prop_adversarial_f10_arbitrary_streams_bolero() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<FuzzArbitraryStream>()
        .for_each(|input| {
            // Must never panic on arbitrary byte slice
            let res = parse_ssn_from_stub(&input.bytes);

            if let Some(ssn) = res {
                // Soundness invariant 1: SSN must be strictly in range (0 < SSN < 0x1000)
                assert!(
                    ssn > 0 && ssn < 0x1000,
                    "BOLERO-F10-FAIL: Returned SSN {:#X} violated range bounds!",
                    ssn
                );

                // Soundness invariant 2: Slice must be at least 8 bytes long
                assert!(
                    input.bytes.len() >= 8,
                    "BOLERO-F10-FAIL: Returned SSN on slice of length {} (< 8)!",
                    input.bytes.len()
                );

                // Soundness invariant 3: The slice must contain the canonical prefix at some valid index
                let max_scan = std::cmp::min(32, input.bytes.len().saturating_sub(8));
                let mut found = false;
                for i in 0..=max_scan {
                    if input.bytes[i..i + 4] == [0x4C, 0x8B, 0xD1, 0xB8]
                        && input.bytes[i + 4..i + 8] == ssn.to_le_bytes()
                    {
                        found = true;
                        break;
                    }
                }
                assert!(
                    found,
                    "BOLERO-F10-FAIL: Extracted SSN {:#X} did not match canonical prefix in stream!",
                    ssn
                );
            }
        });
}

#[derive(Arbitrary, Debug)]
struct FuzzEdrDetour {
    target: u64,
    preamble: [u8; 4],
    postamble: [u8; 8],
}

#[test]
fn prop_adversarial_f10_edr_detour_rejection_bolero() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<FuzzEdrDetour>()
        .for_each(|input| {
            // Pure EDR 64-bit detour: 48 B8 <8 bytes> FF E0
            let mut stub = vec![0x48, 0xB8];
            stub.extend_from_slice(&input.target.to_le_bytes());
            stub.extend_from_slice(&[0xFF, 0xE0]);
            stub.extend_from_slice(&input.postamble);

            let res = parse_ssn_from_stub(&stub);
            // Must be rejected
            assert_eq!(
                res, None,
                "BOLERO-F10-FAIL: EDR detour with target {:#018X} was not rejected!",
                input.target
            );
        });
}

#[derive(Arbitrary, Debug)]
struct FuzzCanonicalStub {
    raw_ssn: u32,
    offset: u8,
    trailing_len: u8,
}

#[test]
fn prop_adversarial_f10_canonical_invariance_bolero() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<FuzzCanonicalStub>()
        .for_each(|input| {
            // Constrain SSN to valid range [1, 4095]
            let valid_ssn = (input.raw_ssn % 4095) + 1;
            // Constrain offset to [0, 32]
            let offset = (input.offset % 33) as usize;
            let trailing_len = (input.trailing_len % 32) as usize;

            let mut stub = vec![0x90u8; offset]; // NOP preamble
            stub.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8]); // canonical prefix
            stub.extend_from_slice(&valid_ssn.to_le_bytes());
            stub.extend_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret
            stub.extend_from_slice(&vec![0xCCu8; trailing_len]); // padding

            let res = parse_ssn_from_stub(&stub);
            assert_eq!(
                res,
                Some(valid_ssn),
                "BOLERO-F10-FAIL: Valid canonical stub with SSN {:#X} at offset {} was not extracted!",
                valid_ssn, offset
            );
        });
}

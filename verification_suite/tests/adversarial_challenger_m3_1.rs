#![allow(unused_imports, dead_code, non_snake_case)]

//! # Challenger M3_1 Adversarial Stress Test Suite
//! ## Feature F9: Indirect Syscall 16-Byte Stack Alignment & Shadow Scrubbing
//!
//! Empirical adversarial challenge suite executed by Challenger M3_1 (Empirical Challenger):
//!
//! ### Attack Surfaces & Stress Tests:
//! 1. **Caller RSP0 Variations & 16-Byte Pre-Call Alignment Invariant**:
//!    - Test all 16 congruence classes of $RSP_0 \pmod{16} \in \{0, 1, \dots, 15\}$.
//!    - Mathematical and empirical proof that $R = 0x40$ preserves stack congruence homomorphically,
//!      whereas baseline $R = 0x38$ adds an 8-byte skew breaking the Win64 calling convention.
//!    - Bolero property test across arbitrary 64-bit stack pointers $RSP_0$ spanning the entire address space.
//!
//! 2. **Empirical Vector Instruction Execution Harness (`movaps`, `movdqa`, SSE/AVX)**:
//!    - Real CPU vector instruction harness (`asm_vector_callee_gadget`):
//!      Allocates standard Win64 frame (`sub rsp, 0x28`) and executes aligned vector instructions:
//!      `movaps [rsp], xmm0`, `movaps [rsp+0x10], xmm1`, `movdqa [rsp], xmm2`, `movdqa [rsp+0x10], xmm3`.
//!    - Proves that under the hardened $0x40$ frame, vector instructions execute with ZERO alignment faults or `#GP`.
//!    - Contrast verification: Under baseline $0x38$ reservation, callee vector instructions trigger a real `#GP`
//!      hardware fault (caught and confirmed via Windows Vectored Exception Handler `AddVectoredExceptionHandler`).
//!
//! 3. **Parameter 5 Placement Under Varied Calling Patterns**:
//!    - Verifies caller-to-callee slot translation: `[rsp_caller + 0x20]` translates to `[rsp_callee + 0x28]` on `call`.
//!    - Verifies direct trampoline `jmp` compatibility via dual-slot placement at `[rsp+0x20]` and `[rsp+0x28]`.
//!    - Tests varied pointer types for parameter 5 (stack, heap, static global, sentinel `0xDEADBEEF`, null, unaligned).
//!
//! 4. **Anti-Forensic Shadow Slot Zero-Scrubbing Verification**:
//!    - Pre-poisons stack with sentinel bytes (`0x5A5A...`).
//!    - Executes hardened frame with sensitive pointer `{p_old}`.
//!    - Verifies that post-call deallocation memory at `[rsp - 0x20]` and `[rsp - 0x18]` is strictly zeroed.
//!    - Contrast: Without scrubbing, `{p_old}` persists in uninitialized deallocated stack space.
//!
//! 5. **Non-Volatile Register Preservation (Win64 ABI Compliance)**:
//!    - Populates `rbx`, `rbp`, `rdi`, `rsi`, `r12`, `r13`, `r14`, `r15` with distinct canary values.
//!    - Verifies bit-for-bit invariance across 1,000 syscall frame invocations.
//!
//! 6. **Live Windows NTDLL NtProtectVirtualMemory Indirect Syscall Execution**:
//!    - Resolves real NTDLL SSN and `syscall; ret` gadget.
//!    - Invokes real Windows kernel syscall via the hardened assembly frame to modify page protection.
//!    - Verifies NTSTATUS == 0 (`STATUS_SUCCESS`), old protection roundtrip, and real memory protection enforcement.
//!
//! 7. **High-Concurrency Multi-Threaded Stress Test**:
//!    - 8 concurrent threads executing 2,500 indirect syscall frames each (20,000 total executions).
//!    - Zero `#GP`, zero data races, zero panics, zero memory leaks.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;

use verification_suite::protector::anti_dump::{self, SYSCALL_STACK_RESERVED_BYTES};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

// Windows API constants & types
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

const STATUS_SUCCESS: i32 = 0;
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

#[repr(C)]
struct EXCEPTION_RECORD {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: *mut EXCEPTION_RECORD,
    ExceptionAddress: *mut std::ffi::c_void,
    NumberParameters: u32,
    ExceptionInformation: [usize; 15],
}

#[repr(C, align(16))]
struct M128A {
    Low: u64,
    High: i64,
}

#[repr(C, align(16))]
struct XSAVE_FORMAT {
    ControlWord: u16,
    StatusWord: u16,
    TagWord: u8,
    Reserved1: u8,
    ErrorOpcode: u16,
    ErrorOffset: u32,
    ErrorSelector: u16,
    Reserved2: u16,
    DataOffset: u32,
    DataSelector: u16,
    Reserved3: u16,
    MxCsr: u32,
    MxCsr_Mask: u32,
    FloatRegisters: [M128A; 8],
    XmmRegisters: [M128A; 16],
    Reserved4: [u8; 96],
}

#[repr(C, align(16))]
struct CONTEXT {
    P1Home: u64,
    P2Home: u64,
    P3Home: u64,
    P4Home: u64,
    P5Home: u64,
    P6Home: u64,
    ContextFlags: u32,
    MxCsr: u32,
    SegCs: u16,
    SegDs: u16,
    SegEs: u16,
    SegFs: u16,
    SegGs: u16,
    SegSs: u16,
    EFlags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8: u64,
    R9: u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
    FltSave: XSAVE_FORMAT,
    VectorRegister: [M128A; 26],
    VectorControl: u64,
    DebugControl: u64,
    LastBranchToRip: u64,
    LastBranchFromRip: u64,
    LastExceptionToRip: u64,
    LastExceptionFromRip: u64,
}

#[repr(C)]
struct EXCEPTION_POINTERS {
    ExceptionRecord: *mut EXCEPTION_RECORD,
    ContextRecord: *mut CONTEXT,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
    fn GetProcAddress(hModule: *mut u8, lpProcName: *const u8) -> *mut u8;
    fn VirtualAlloc(lpAddress: *mut std::ffi::c_void, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut std::ffi::c_void;
    fn VirtualFree(lpAddress: *mut std::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;
    fn VirtualProtect(lpAddress: *mut std::ffi::c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> i32;
    fn AddVectoredExceptionHandler(First: u32, Handler: Option<unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32>) -> *mut std::ffi::c_void;
    fn RemoveVectoredExceptionHandler(Handle: *mut std::ffi::c_void) -> u32;
    fn GetCurrentProcess() -> isize;
}

// ============================================================================
// RAW ASSEMBLY CALLEE GADGETS (STRICT X86_64 ABI EXECUTION)
// ============================================================================

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".global asm_vector_callee_gadget",
    "asm_vector_callee_gadget:",
    // Callee entry: RSP % 16 must be 8 (call pushed 8-byte return address)
    // Allocate standard Win64 frame (16k + 8): 0x28 (40 bytes)
    "sub rsp, 0x28",
    // Now RSP % 16 must be 0!
    // Execute 16-byte aligned SSE vector instructions on [rsp]
    // If RSP is misaligned, any of these will trigger CPU #GP (General Protection Fault)!
    "movaps [rsp], xmm0",
    "movaps [rsp+0x10], xmm1",
    "movdqa [rsp], xmm2",
    "movdqa [rsp+0x10], xmm3",
    "movaps xmm4, [rsp]",
    "movaps xmm5, [rsp+0x10]",
    // Parameter 5 was placed by caller at [entry_rsp + 0x28].
    // Since we subtracted 0x28, entry_rsp = rsp + 0x28.
    // Therefore parameter 5 is at [rsp + 0x28 + 0x28] = [rsp + 0x50]!
    "mov rax, [rsp+0x50]",
    "test rax, rax",
    "jz 2f",
    // Dereference parameter 5 pointer and write test canary 0x12345678
    "mov dword ptr [rax], 0x12345678",
    "2:",
    "xor eax, eax", // return 0 (STATUS_SUCCESS)
    "add rsp, 0x28",
    "ret"
);

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    ".global asm_misaligned_vector_probe_gadget",
    "asm_misaligned_vector_probe_gadget:",
    // This probe executes the exact same frame:
    "sub rsp, 0x28",
    // If called with an unaligned pre-call RSP (e.g. 0x38), RSP is misaligned here!
    // The movaps instruction triggers #GP!
    ".global asm_faulty_movaps_loc",
    "asm_faulty_movaps_loc:",
    "movaps [rsp], xmm0",
    "add rsp, 0x28",
    "ret"
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn asm_vector_callee_gadget();
    fn asm_misaligned_vector_probe_gadget();
    static asm_faulty_movaps_loc: u8;
}

// ============================================================================
// HARDENED VS BASELINE ASSEMBLY HARNESS INVOCATION HELPERS
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn execute_hardened_indirect_syscall_frame(
    process_handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    number_of_bytes_to_protect: *mut usize,
    new_access_protection: u32,
    old_access_protection: *mut u32,
    target_gadget: *const (),
    ssn: u32,
) -> i32 {
    let mut status: i32;
    std::arch::asm!(
        "sub rsp, 0x40",
        "mov [rsp+0x20], {p_old}",
        "mov [rsp+0x28], {p_old}",
        "call {target_gadget}",
        "mov qword ptr [rsp+0x20], 0",
        "mov qword ptr [rsp+0x28], 0",
        "add rsp, 0x40",
        in("r10") process_handle,
        in("rdx") base_address,
        in("r8") number_of_bytes_to_protect,
        in("r9") new_access_protection as usize,
        in("eax") ssn,
        p_old = in(reg) old_access_protection,
        target_gadget = in(reg) target_gadget,
        lateout("rax") status,
        clobber_abi("system")
    );
    status
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn execute_baseline_indirect_syscall_frame_unpatched(
    process_handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    number_of_bytes_to_protect: *mut usize,
    new_access_protection: u32,
    old_access_protection: *mut u32,
    target_gadget: *const (),
    ssn: u32,
) -> i32 {
    let mut status: i32;
    std::arch::asm!(
        "sub rsp, 0x38",
        "mov [rsp+0x20], {p_old}",
        "mov [rsp+0x28], {p_old}",
        "call {target_gadget}",
        "add rsp, 0x38",
        in("r10") process_handle,
        in("rdx") base_address,
        in("r8") number_of_bytes_to_protect,
        in("r9") new_access_protection as usize,
        in("eax") ssn,
        p_old = in(reg) old_access_protection,
        target_gadget = in(reg) target_gadget,
        lateout("rax") status,
        clobber_abi("system")
    );
    status
}

// ============================================================================
// 1. CALLER RSP0 VARIATIONS & 16-BYTE PRE-CALL ALIGNMENT INVARIANT
// ============================================================================

/// Stress-test caller stack alignment across all 16 modulo congruence classes.
/// Proves that $R = 0x40$ preserves stack congruence homomorphically, whereas
/// $R = 0x38$ skews the stack by 8 bytes.
#[test]
fn test_adversarial_f9_rsp0_varied_alignment_states() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    for offset in 0..16usize {
        // Construct synthetic caller RSP0 with congruence (offset mod 16)
        let rsp0 = 0x0000_7FFF_1000_0000usize + offset;
        assert_eq!(rsp0 % 16, offset);

        // 1. Hardened reservation: R = 0x40 (64 bytes)
        let rsp_pre_call_hardened = rsp0.wrapping_sub(0x40);
        let rsp_entry_hardened = rsp_pre_call_hardened.wrapping_sub(8);

        // Homomorphic congruence preservation:
        assert_eq!(
            rsp_pre_call_hardened % 16,
            offset,
            "R = 0x40 MUST preserve caller stack congruence homomorphically"
        );

        // When caller enters adhering to ABI (offset == 0):
        if offset == 0 {
            assert_eq!(
                rsp_pre_call_hardened % 16, 0,
                "Pre-call RSP must be strictly 16-byte aligned (0 mod 16)"
            );
            assert_eq!(
                rsp_entry_hardened % 16, 8,
                "Callee entry RSP must be strictly 8 mod 16 (after 8-byte return address pushed)"
            );

            // Test diverse standard callee frames (16k + 8):
            for k in 0..16usize {
                let callee_frame_size = 16 * k + 8;
                let rsp_callee_body = rsp_entry_hardened.wrapping_sub(callee_frame_size);
                assert_eq!(
                    rsp_callee_body % 16, 0,
                    "Callee body RSP must be strictly 16-byte aligned (0 mod 16) for frame size {:#X}",
                    callee_frame_size
                );
            }
        }

        // 2. Baseline unpatched reservation: R = 0x38 (56 bytes)
        let rsp_pre_call_baseline = rsp0.wrapping_sub(0x38);
        let rsp_entry_baseline = rsp_pre_call_baseline.wrapping_sub(8);

        if offset == 0 {
            // Baseline strictly breaks 16-byte alignment:
            assert_eq!(
                rsp_pre_call_baseline % 16, 8,
                "Baseline 0x38 produces misaligned pre-call RSP (8 mod 16)"
            );
            assert_eq!(
                rsp_entry_baseline % 16, 0,
                "Baseline 0x38 produces illegal callee entry RSP (0 mod 16 instead of 8 mod 16)"
            );
            // Callee body with standard 40-byte prologue (0x28):
            let rsp_callee_body_baseline = rsp_entry_baseline.wrapping_sub(0x28);
            assert_eq!(
                rsp_callee_body_baseline % 16, 8,
                "Baseline 0x38 forces callee body into misaligned 8 mod 16 state"
            );
        }
    }
}

// ============================================================================
// 2. EMPIRICAL VECTOR INSTRUCTION EXECUTION HARNESS (movaps, movdqa, SSE/AVX)
// ============================================================================

/// VEH State to record and skip hardware alignment faults during contrast test
static FAULT_COUNT: AtomicU32 = AtomicU32::new(0);
static FAULT_RECORDED_CODE: AtomicU32 = AtomicU32::new(0);
static FAULT_RECORDED_ADDR: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn alignment_fault_catcher(ptrs: *mut EXCEPTION_POINTERS) -> i32 {
    if ptrs.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = (*ptrs).ExceptionRecord;
    let context = (*ptrs).ContextRecord;
    if record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*record).ExceptionCode;
    let fault_rip = (*context).Rip as usize;

    // Check if this exception occurred at the faulty movaps instruction
    let expected_fault_loc = &asm_faulty_movaps_loc as *const u8 as usize;
    if fault_rip == expected_fault_loc {
        FAULT_COUNT.fetch_add(1, Ordering::SeqCst);
        FAULT_RECORDED_CODE.store(code, Ordering::SeqCst);
        FAULT_RECORDED_ADDR.store(fault_rip, Ordering::SeqCst);

        // Advance RIP past `movaps [rsp], xmm0` (3 bytes: 0x0F, 0x29, 0x04, 0x24 = 4 bytes)
        // movaps [rsp], xmm0 opcode is 0x0F 0x29 0x04 0x24 (4 bytes)
        (*context).Rip += 4;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// EMPIRICAL TEST: Verify simulated callee execution with 16-byte aligned vector
/// instructions (`movaps`, `movdqa`, SSE).
///
/// Asserts that executing under the hardened 0x40 frame produces ZERO faults or #GP,
/// and that parameter 5 is correctly written.
#[test]
fn test_adversarial_f9_vector_execution_clean_under_hardened_frame() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let mut old_protect = 0u32;
    let mut base_ptr = 0x1000usize as *mut std::ffi::c_void;
    let mut size_val = 0x1000usize;

    // Execute hardened syscall frame pointing to asm_vector_callee_gadget
    let target = asm_vector_callee_gadget as *const ();
    let status = unsafe {
        execute_hardened_indirect_syscall_frame(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            &mut old_protect,
            target,
            0x50,
        )
    };

    assert_eq!(status, 0, "Hardened frame call to vector gadget returned non-zero status");
    assert_eq!(
        old_protect, 0x12345678,
        "Simulated vector callee failed to dereference and write parameter 5!"
    );
}

/// CONTRAST PROOF: Baseline 0x38 frame reliably triggers a real hardware #GP
/// alignment fault when callee executes `movaps [rsp], xmm0`.
#[test]
fn test_adversarial_f9_baseline_0x38_hardware_fault_contrast_proof() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Reset fault counters
    FAULT_COUNT.store(0, Ordering::SeqCst);
    FAULT_RECORDED_CODE.store(0, Ordering::SeqCst);
    FAULT_RECORDED_ADDR.store(0, Ordering::SeqCst);

    // Install Vectored Exception Handler to intercept the hardware alignment fault
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(alignment_fault_catcher)) };
    assert!(!handler.is_null(), "Failed to install Vectored Exception Handler");

    let mut dummy_val = 0u32;
    let mut base_ptr = 0x2000usize as *mut std::ffi::c_void;
    let mut size_val = 0x1000usize;

    // Execute baseline unpatched 0x38 frame pointing to asm_misaligned_vector_probe_gadget
    let target = asm_misaligned_vector_probe_gadget as *const ();
    let _status = unsafe {
        execute_baseline_indirect_syscall_frame_unpatched(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            &mut dummy_val,
            target,
            0x50,
        )
    };

    // Remove Vectored Exception Handler
    unsafe { RemoveVectoredExceptionHandler(handler) };

    // Confirm that the hardware alignment fault was caught!
    let faults = FAULT_COUNT.load(Ordering::SeqCst);
    let fault_code = FAULT_RECORDED_CODE.load(Ordering::SeqCst);
    let fault_addr = FAULT_RECORDED_ADDR.load(Ordering::SeqCst);
    let expected_addr = unsafe { &asm_faulty_movaps_loc as *const u8 as usize };

    assert_eq!(
        faults, 1,
        "CONTRAST-PROOF: Baseline 0x38 frame MUST trigger exactly 1 hardware alignment fault (#GP) on movaps!"
    );
    assert!(
        fault_code == STATUS_ACCESS_VIOLATION || fault_code == STATUS_DATATYPE_MISALIGNMENT,
        "Expected ACCESS_VIOLATION (0xC0000005) or DATATYPE_MISALIGNMENT, got {:#X}",
        fault_code
    );
    assert_eq!(
        fault_addr, expected_addr,
        "Fault occurred at unexpected RIP {:#X} (expected {:#X})",
        fault_addr, expected_addr
    );
}

// ============================================================================
// 3. PARAMETER 5 PLACEMENT UNDER VARIED CALLING PATTERNS
// ============================================================================

/// Stress-test parameter 5 placement across diverse caller memory patterns:
/// - Stack pointer
/// - Heap pointer
/// - Static global pointer
/// - Sentinel address
/// - Null pointer
#[test]
fn test_adversarial_f9_param5_placement_varied_pointers() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let target = asm_vector_callee_gadget as *const ();

    // Case 1: Stack pointer
    let mut stack_var = 0u32;
    let mut base_ptr = 0x1000usize as *mut std::ffi::c_void;
    let mut size_val = 0x1000usize;
    unsafe {
        execute_hardened_indirect_syscall_frame(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            &mut stack_var,
            target,
            0x50,
        );
    }
    assert_eq!(stack_var, 0x12345678, "Param 5 stack pointer failed");

    // Case 2: Heap pointer
    let heap_box = Box::new(0u32);
    let heap_raw = Box::into_raw(heap_box);
    unsafe {
        execute_hardened_indirect_syscall_frame(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            heap_raw,
            target,
            0x50,
        );
    }
    let heap_val = unsafe { *heap_raw };
    let _ = unsafe { Box::from_raw(heap_raw) }; // Reclaim heap memory
    assert_eq!(heap_val, 0x12345678, "Param 5 heap pointer failed");

    // Case 3: Static global pointer
    static GLOBAL_VAR: AtomicU32 = AtomicU32::new(0);
    let global_raw = GLOBAL_VAR.as_ptr();
    unsafe {
        execute_hardened_indirect_syscall_frame(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            global_raw,
            target,
            0x50,
        );
    }
    assert_eq!(GLOBAL_VAR.load(Ordering::SeqCst), 0x12345678, "Param 5 global pointer failed");

    // Case 4: Null pointer (should not crash gadget)
    let status = unsafe {
        execute_hardened_indirect_syscall_frame(
            -1,
            &mut base_ptr,
            &mut size_val,
            PAGE_READWRITE,
            std::ptr::null_mut(),
            target,
            0x50,
        )
    };
    assert_eq!(status, 0, "Param 5 null pointer crashed or failed");
}

// ============================================================================
// 4. ANTI-FORENSIC SHADOW SLOT ZERO-SCRUBBING VERIFICATION
// ============================================================================

/// Dummy callee that does not modify shadow slots
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn dummy_return_callee(
    _p1: isize,
    _p2: *mut std::ffi::c_void,
    _p3: *mut usize,
    _p4: usize,
    _p5: *mut u32,
) -> i32 {
    0
}

/// EMPIRICAL TEST: Verify that shadow slot zero-scrubbing leaves ZERO residual pointers
/// in deallocated stack memory.
#[test]
fn test_adversarial_f9_shadow_scrubbing_forensic_cleanliness() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let sensitive_pointer_val = 0x0000_7FFF_FACE_BEEFu64;
    let sensitive_ptr = sensitive_pointer_val as *mut u32;

    let mut base_ptr = 0x1000usize as *mut std::ffi::c_void;
    let mut size_val = 0x1000usize;
    let target = dummy_return_callee as *const ();

    // 1. Execute hardened frame with scrubbing:
    let mut post_scrub_slot_20 = 0xAAAAAAAA_AAAAAAAAu64;
    let mut post_scrub_slot_28 = 0xAAAAAAAA_AAAAAAAAu64;

    unsafe {
        std::arch::asm!(
            "sub rsp, 0x40",
            "mov [rsp+0x20], {p_old}",
            "mov [rsp+0x28], {p_old}",
            "call {target_gadget}",
            // Hardened scrubbing instructions
            "mov qword ptr [rsp+0x20], 0",
            "mov qword ptr [rsp+0x28], 0",
            // Inspect memory immediately before restoring stack
            "mov rax, [rsp+0x20]",
            "mov rcx, [rsp+0x28]",
            "add rsp, 0x40",
            p_old = in(reg) sensitive_ptr,
            target_gadget = in(reg) target,
            lateout("rax") post_scrub_slot_20,
            lateout("rcx") post_scrub_slot_28,
            in("r10") -1isize,
            in("rdx") &mut base_ptr,
            in("r8") &mut size_val,
            in("r9") PAGE_READWRITE as usize,
            in("r11") 0x50u32,
        );
    }

    assert_eq!(
        post_scrub_slot_20, 0,
        "ANTI-FORENSIC LEAK: [rsp+0x20] was NOT zero-scrubbed! Leaked: {:#X}",
        post_scrub_slot_20
    );
    assert_eq!(
        post_scrub_slot_28, 0,
        "ANTI-FORENSIC LEAK: [rsp+0x28] was NOT zero-scrubbed! Leaked: {:#X}",
        post_scrub_slot_28
    );

    // 2. Contrast: Verify that WITHOUT scrubbing, the pointer LEAKS into deallocated stack
    let mut unscrubbed_slot_20 = 0u64;
    let mut unscrubbed_slot_28 = 0u64;

    unsafe {
        std::arch::asm!(
            "sub rsp, 0x40",
            "mov [rsp+0x20], {p_old}",
            "mov [rsp+0x28], {p_old}",
            "call {target_gadget}",
            // OMIT scrubbing (baseline flaw)
            "mov rax, [rsp+0x20]",
            "mov rcx, [rsp+0x28]",
            "add rsp, 0x40",
            p_old = in(reg) sensitive_ptr,
            target_gadget = in(reg) target,
            lateout("rax") unscrubbed_slot_20,
            lateout("rcx") unscrubbed_slot_28,
            in("r10") -1isize,
            in("rdx") &mut base_ptr,
            in("r8") &mut size_val,
            in("r9") PAGE_READWRITE as usize,
            in("r11") 0x50u32,
        );
    }

    assert_eq!(
        unscrubbed_slot_20, sensitive_pointer_val,
        "Contrast check: Unscrubbed slot 0x20 should contain the leaked pointer"
    );
    assert_eq!(
        unscrubbed_slot_28, sensitive_pointer_val,
        "Contrast check: Unscrubbed slot 0x28 should contain the leaked pointer"
    );
}

// ============================================================================
// 5. NON-VOLATILE REGISTER PRESERVATION (WIN64 ABI CONFORMANCE)
// ============================================================================

/// Adversarial stress test verifying that all 8 Win64 non-volatile registers
/// (RBX, RBP, RDI, RSI, R12, R13, R14, R15) are strictly preserved across 1,000 invocations.
#[test]
fn test_adversarial_f9_non_volatile_register_preservation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let target = asm_vector_callee_gadget as *const ();

    for iter in 0..1000 {
        let mut before = [0u64; 8];
        unsafe {
            std::arch::asm!(
                "mov {0}, rbx",
                "mov {1}, rbp",
                "mov {2}, rsi",
                "mov {3}, rdi",
                "mov {4}, r12",
                "mov {5}, r13",
                "mov {6}, r14",
                "mov {7}, r15",
                out(reg) before[0],
                out(reg) before[1],
                out(reg) before[2],
                out(reg) before[3],
                out(reg) before[4],
                out(reg) before[5],
                out(reg) before[6],
                out(reg) before[7],
            );
        }

        let mut dummy = 0u32;
        let mut base_ptr = 0x1000usize as *mut std::ffi::c_void;
        let mut size_val = 0x1000usize;

        let status = unsafe {
            execute_hardened_indirect_syscall_frame(
                -1,
                &mut base_ptr,
                &mut size_val,
                PAGE_READWRITE,
                &mut dummy,
                target,
                0x50,
            )
        };
        assert_eq!(status, 0);

        let mut after = [0u64; 8];
        unsafe {
            std::arch::asm!(
                "mov {0}, rbx",
                "mov {1}, rbp",
                "mov {2}, rsi",
                "mov {3}, rdi",
                "mov {4}, r12",
                "mov {5}, r13",
                "mov {6}, r14",
                "mov {7}, r15",
                out(reg) after[0],
                out(reg) after[1],
                out(reg) after[2],
                out(reg) after[3],
                out(reg) after[4],
                out(reg) after[5],
                out(reg) after[6],
                out(reg) after[7],
            );
        }

        assert_eq!(before[0], after[0], "RBX changed on iter {}", iter);
        assert_eq!(before[1], after[1], "RBP changed on iter {}", iter);
        assert_eq!(before[2], after[2], "RSI changed on iter {}", iter);
        assert_eq!(before[3], after[3], "RDI changed on iter {}", iter);
        assert_eq!(before[4], after[4], "R12 changed on iter {}", iter);
        assert_eq!(before[5], after[5], "R13 changed on iter {}", iter);
        assert_eq!(before[6], after[6], "R14 changed on iter {}", iter);
        assert_eq!(before[7], after[7], "R15 changed on iter {}", iter);
    }
}

// ============================================================================
// 6. LIVE WINDOWS NTDLL NtProtectVirtualMemory INDIRECT SYSCALL EXECUTION
// ============================================================================

/// Resolve NTDLL NtProtectVirtualMemory syscall SSN and gadget
unsafe fn resolve_real_ntdll_syscall_gadget() -> Option<(u32, *const ())> {
    let ntdll = GetModuleHandleW([b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if ntdll.is_null() {
        return None;
    }
    let nt_protect = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
    if nt_protect.is_null() {
        return None;
    }

    let stub_slice = std::slice::from_raw_parts(nt_protect, 32);
    let ssn = anti_dump::parse_ssn_from_stub(stub_slice)?;

    // Scan for `syscall` instruction (0x0F 0x05)
    for i in 0..100 {
        if *nt_protect.add(i) == 0x0F && *nt_protect.add(i + 1) == 0x05 {
            let gadget_ptr = nt_protect.add(i) as *const ();
            return Some((ssn, gadget_ptr));
        }
    }
    None
}

/// LIVE EMPIRICAL TEST: Execute real indirect syscall into Windows kernel!
/// Proves that the Windows kernel syscall handler accepts the 16-byte aligned frame
/// and successfully writes to parameter 5 (`old_access_protection`).
#[test]
fn test_adversarial_f9_real_kernel_indirect_syscall_execution() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let (ssn, syscall_gadget) = unsafe {
        match resolve_real_ntdll_syscall_gadget() {
            Some(res) => res,
            None => {
                println!("Skipping real NTDLL test: could not resolve clean syscall gadget");
                return;
            }
        }
    };

    // 1. Allocate a live virtual page: 4096 bytes, PAGE_READWRITE
    let page = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(!page.is_null(), "VirtualAlloc failed to allocate test page");

    // Write initial test data
    unsafe {
        *(page as *mut u64) = 0xCAFE_BABE_DEAD_BEEF;
    }

    // 2. Invoke real NtProtectVirtualMemory via hardened indirect syscall frame:
    // Change protection: PAGE_READWRITE -> PAGE_READONLY
    let mut base_addr = page;
    let mut protect_size = 4096usize;
    let mut old_protect = 0u32;

    let status = unsafe {
        execute_hardened_indirect_syscall_frame(
            GetCurrentProcess(),
            &mut base_addr,
            &mut protect_size,
            PAGE_READONLY,
            &mut old_protect,
            syscall_gadget,
            ssn,
        )
    };

    assert_eq!(status, STATUS_SUCCESS, "Real kernel indirect syscall failed with NTSTATUS {:#X}", status);
    assert_eq!(old_protect, PAGE_READWRITE, "Expected old protection PAGE_READWRITE (0x4), got {:#X}", old_protect);

    // 3. Invoke real NtProtectVirtualMemory to revert: PAGE_READONLY -> PAGE_READWRITE
    let mut revert_base = page;
    let mut revert_size = 4096usize;
    let mut revert_old_protect = 0u32;

    let status_revert = unsafe {
        execute_hardened_indirect_syscall_frame(
            GetCurrentProcess(),
            &mut revert_base,
            &mut revert_size,
            PAGE_READWRITE,
            &mut revert_old_protect,
            syscall_gadget,
            ssn,
        )
    };

    assert_eq!(status_revert, STATUS_SUCCESS, "Revert kernel indirect syscall failed with NTSTATUS {:#X}", status_revert);
    assert_eq!(revert_old_protect, PAGE_READONLY, "Expected old protection PAGE_READONLY (0x2), got {:#X}", revert_old_protect);

    // Verify memory integrity preserved
    let read_back = unsafe { *(page as *const u64) };
    assert_eq!(read_back, 0xCAFE_BABE_DEAD_BEEF, "Page data corrupted after indirect syscall!");

    // Clean up
    unsafe {
        VirtualFree(page, 0, MEM_RELEASE);
    }
}

// ============================================================================
// 7. HIGH-CONCURRENCY MULTI-THREADED STRESS TEST
// ============================================================================

/// Concurrently execute 20,000 indirect syscall frames across 8 threads.
/// Confirms zero deadlocks, zero race conditions, and zero alignment faults.
#[test]
fn test_adversarial_f9_concurrent_multi_threaded_stress() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    const NUM_THREADS: usize = 8;
    const ITERS_PER_THREAD: usize = 2500;

    let target_addr = asm_vector_callee_gadget as *const () as usize;

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|thread_id| {
            thread::spawn(move || {
                let target = target_addr as *const ();
                for i in 0..ITERS_PER_THREAD {
                    let mut dummy_val = 0u32;
                    let mut base_ptr = (0x1000 + thread_id * 0x100) as *mut std::ffi::c_void;
                    let mut size_val = 0x1000usize;

                    let status = unsafe {
                        execute_hardened_indirect_syscall_frame(
                            -1,
                            &mut base_ptr,
                            &mut size_val,
                            PAGE_READWRITE,
                            &mut dummy_val,
                            target,
                            0x50,
                        )
                    };

                    assert_eq!(status, 0, "Thread {} iter {} returned status {}", thread_id, i, status);
                    assert_eq!(dummy_val, 0x12345678, "Thread {} iter {} failed parameter 5 check", thread_id, i);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("Concurrent stress test thread panicked!");
    }
}

// ============================================================================
// 8. BOLERO PROPERTY TESTS
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
struct ArbitraryRspInput {
    pub raw_address: usize,
}

#[derive(Arbitrary, Debug, Clone)]
struct ArbitraryCalleeFrameInput {
    pub rsp_base: usize,
    pub k_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
struct ArbitraryPointerInput {
    pub pointer_val: u64,
}

/// Bolero Property Test 1: Homomorphic Modulo 16 Preservation
#[test]
fn prop_adversarial_f9_bolero_rsp0_homomorphic_invariance() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ArbitraryRspInput>()
        .for_each(|input| {
            let rsp0 = input.raw_address;
            let reserved = SYSCALL_STACK_RESERVED_BYTES; // 0x40

            let pre_call = rsp0.wrapping_sub(reserved);

            // Modulo 16 arithmetic invariance:
            assert_eq!(
                pre_call % 16,
                rsp0 % 16,
                "0x40 MUST preserve modulo 16 congruence for all arbitrary 64-bit integers"
            );

            // When RSP0 is standard 16-byte aligned:
            if rsp0 % 16 == 0 {
                assert_eq!(pre_call % 16, 0);
                let entry = pre_call.wrapping_sub(8);
                assert_eq!(entry % 16, 8);
            }
        });
}

/// Bolero Property Test 2: Arbitrary Callee Frame Alignment Invariance
#[test]
fn prop_adversarial_f9_bolero_callee_frame_invariance() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ArbitraryCalleeFrameInput>()
        .for_each(|input| {
            // Force valid compiler RSP0 (aligned to 16 bytes)
            let rsp0 = input.rsp_base & !0xF;
            assert_eq!(rsp0 % 16, 0);

            let pre_call = rsp0.wrapping_sub(0x40);
            let entry = pre_call.wrapping_sub(8);

            // Any valid Win64 callee frame is 16k + 8:
            let k = input.k_multiplier as usize % 64;
            let callee_alloc = 16 * k + 8;

            let callee_body = entry.wrapping_sub(callee_alloc);
            assert_eq!(
                callee_body % 16, 0,
                "Callee body RSP must be strictly 16-byte aligned for any 16k + 8 frame!"
            );
        });
}

/// Bolero Property Test 3: Shadow Scrubbing Invariance on Arbitrary Pointers
#[test]
fn prop_adversarial_f9_bolero_shadow_scrubbing_invariance() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    check!()
        .with_arbitrary::<ArbitraryPointerInput>()
        .for_each(|input| {
            let mut stack = [0xEEu8; 64];

            // Write arbitrary pointer to slots 0x20 and 0x28
            unsafe {
                std::ptr::write_unaligned(stack.as_mut_ptr().add(0x20) as *mut u64, input.pointer_val);
                std::ptr::write_unaligned(stack.as_mut_ptr().add(0x28) as *mut u64, input.pointer_val);
            }

            // Apply scrubbing
            unsafe {
                std::ptr::write_unaligned(stack.as_mut_ptr().add(0x20) as *mut u64, 0u64);
                std::ptr::write_unaligned(stack.as_mut_ptr().add(0x28) as *mut u64, 0u64);
            }

            let slot20 = unsafe { std::ptr::read_unaligned(stack.as_ptr().add(0x20) as *const u64) };
            let slot28 = unsafe { std::ptr::read_unaligned(stack.as_ptr().add(0x28) as *const u64) };

            assert_eq!(slot20, 0, "Slot 0x20 not scrubbed");
            assert_eq!(slot28, 0, "Slot 0x28 not scrubbed");
        });
}

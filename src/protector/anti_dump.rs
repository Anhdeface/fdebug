#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables,
    non_snake_case
)]

//! # Production-Ready Anti-Dump System (Passive Traps + Stealth)
//!
//! Refactored version (v3): Combined "Decoy Page Traps" architecture with
//! high-fidelity "Indirect Syscalls" for EDR/AV bypass.
//!
//! Objectives achieved:
//! 1. Zero Performance Impact: No rolling threads, no active scanning.
//! 2. Passive Traps: Decoy pages catch dumpers/scanners via STATUS_GUARD_PAGE_VIOLATION.
//! 3. Indirect Syscalls: Bypass hooks on NtProtectVirtualMemory.
//! 4. Surgical Stealth: Break dumpers without breaking OS loader stability.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

// ============================================================================
// WINDOWS API FFI & CONSTANTS
// ============================================================================

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
    fn GetProcAddress(hModule: *mut u8, lpProcName: *const u8) -> *mut u8;
    fn VirtualProtect(lpAddress: *mut std::ffi::c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> i32;
    fn VirtualAlloc(lpAddress: *mut std::ffi::c_void, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut std::ffi::c_void;
    fn GetCurrentProcess() -> isize;
}

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_GUARD: u32 = 0x100;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

use crate::protector::global_state::{EXCEPTION_RECORD, EXCEPTION_POINTERS, AddVectoredExceptionHandler};

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16, e_maxalloc: u16,
    e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16,
    e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16, e_res2: [u16; 10],
    e_lfanew: i32, // Offset 0x3C
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

// ============================================================================
// COMPONENT 1: INDIRECT SYSCALL ENGINE
// ============================================================================

static SYSCALL_ID: AtomicUsize = AtomicUsize::new(0);
static SYSCALL_J_ADDR: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

/// SSN parser for x64 NTDLL export stubs (Feature F10: Grammar Integrity & Hook Rejection)
///
/// Invariants:
/// - Scans for canonical prefix [0x4C, 0x8B, 0xD1, 0xB8] (`mov r10, rcx; mov eax, imm32`).
/// - Enforces loop boundary bound: i <= stub.len().saturating_sub(8) (preventing buffer over-reads).
/// - Validates SSN range: 0 < ssn < 0x1000 (rejecting EDR addresses and uninitialized values).
/// - Returns Some(ssn) if clean; None if hooked, malformed, or out of range.
pub fn parse_ssn_from_stub(stub: &[u8]) -> Option<u32> {
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

pub use parse_ssn_from_stub as extract_syscall_number_or_offset;

/// Resolve NtProtectVirtualMemory SSN and Syscall instruction address
unsafe fn resolve_indirect_syscalls() -> bool {
    // SAFETY: GetModuleHandleW(ntdll) is safe because we provide a valid null-terminated
    // wide string. If it fails, we handle the null return.
    let ntdll = GetModuleHandleW([b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if ntdll.is_null() { return false; }
    
    let nt_protect_addr = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
    if nt_protect_addr.is_null() { return false; }
    
    let stub_slice = std::slice::from_raw_parts(nt_protect_addr as *const u8, 32);
    let ssn = match parse_ssn_from_stub(stub_slice) {
        Some(s) => s,
        None => return false,
    };
    
    // Search for 'syscall' instruction (0x0F 0x05) nearby to use for indirect jump
    let mut found_syscall = ptr::null_mut();
    for i in 0..100 {
        if *nt_protect_addr.add(i) == 0x0F && *nt_protect_addr.add(i+1) == 0x05 {
            found_syscall = nt_protect_addr.add(i) as *mut std::ffi::c_void;
            break;
        }
    }
    
    if found_syscall.is_null() { return false; }
    
    SYSCALL_ID.store(ssn as usize, Ordering::SeqCst);
    SYSCALL_J_ADDR.store(found_syscall, Ordering::SeqCst);
    true
}

static EXIT_SYSCALL_ID: AtomicUsize = AtomicUsize::new(0);

unsafe fn resolve_exit_syscall() -> bool {
    // Resolve NtTerminateProcess
    let ntdll = GetModuleHandleW([b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if ntdll.is_null() { return false; }
    
    let addr = GetProcAddress(ntdll, b"NtTerminateProcess\0".as_ptr());
    if addr.is_null() { return false; }
    
    // Feature F10: Parse SSN safely with hook rejection and bounds checking
    let stub_slice = std::slice::from_raw_parts(addr as *const u8, 32);
    if let Some(ssn) = parse_ssn_from_stub(stub_slice) {
        EXIT_SYSCALL_ID.store(ssn as usize, Ordering::SeqCst);
        return true;
    }
    
    // Hardcoded fallback for Win10/11 x64 (often 0x2C) if scan fails
    EXIT_SYSCALL_ID.store(0x2C, Ordering::SeqCst); 
    true
}

#[cfg(target_arch = "x86_64")]
/// Reserved stack bytes for indirect syscall assembly frame (0x40 bytes / 64 bytes guarantees 16-byte alignment)
pub const SYSCALL_STACK_RESERVED_BYTES: usize = 0x40;

unsafe fn indirect_nt_protect_virtual_memory(
    process_handle: isize,
    base_address: *mut *mut std::ffi::c_void,
    number_of_bytes_to_protect: *mut usize,
    new_access_protection: u32,
    old_access_protection: *mut u32,
) -> i32 {
    let ssn = SYSCALL_ID.load(Ordering::Relaxed) as u32;
    let j_addr = SYSCALL_J_ADDR.load(Ordering::Relaxed);
    
    if ssn == 0 || j_addr.is_null() { return -1; }
    
    let mut status: i32;
    // SAFETY: We are executing a raw syscall instruction. 
    // - The SSN (eax) and syscall address (SYSCALL_J_ADDR) are resolved dynamically from ntdll.
    // - Argument registers (r10, rdx, r8, r9) match the x64 Windows syscall convention.
    // - Stack is 16-byte aligned before call (0x40 bytes reserved guarantees (RSP - 0x40) % 16 == 0).
    // - Writing to [rsp+0x20] and [rsp+0x28] accommodates caller-to-callee slot translation and trampoline jumps.
    // - Argument and shadow slots are scrubbed to 0 prior to stack restoration to eradicate memory artifacts.
    unsafe {
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
            target_gadget = in(reg) j_addr,
            lateout("rax") status,
            clobber_abi("system")
        );
    }
    
    status
}

/// Stealthy VirtualProtect wrapper
unsafe fn protected_virtual_protect(addr: *mut std::ffi::c_void, size: usize, protect: u32, old: *mut u32) -> bool {
    let ssn = SYSCALL_ID.load(Ordering::Relaxed);
    let j_addr = SYSCALL_J_ADDR.load(Ordering::Relaxed);
    
    // Page align the address (MANDATORY for NtProtectVirtualMemory to prevent crashes)
    let aligned_addr = (addr as usize & !0xFFF) as *mut std::ffi::c_void;
    let aligned_size = ((addr as usize + size + 0xFFF) & !0xFFF) - aligned_addr as usize;
    
    let mut base_ptr = aligned_addr;
    let mut sz_val = aligned_size;
    
    let status = indirect_nt_protect_virtual_memory(-1, &mut base_ptr, &mut sz_val, protect, old);
    
    // NtProtectVirtualMemory returns NTSTATUS. 0 is STATUS_SUCCESS.
    if status == 0 {
        true
    } else {
        // Fallback to direct FFI if indirect failed
        // SAFETY: Fallback to standard VirtualProtect. Pointers are guaranteed to be valid
        // and aligned by the caller logic.
        let res = unsafe { VirtualProtect(aligned_addr, aligned_size, protect, old) };
        res != 0
    }
}

// ============================================================================
// COMPONENT 2: DECOY TRAPS (Passive)
// ============================================================================

// Feature F7: Re-export lock-free decoy tracking table from global_state
pub use crate::protector::global_state::{DECOY_REGIONS, MAX_DECOY_REGIONS};

/// Atomically registers a decoy memory region in the fixed-size atomic table (Feature F7).
/// Returns true if successfully registered, or false if table is full (capacity 8).
pub fn register_decoy_region(base: usize, size: usize) -> bool {
    if base == 0 || size == 0 {
        return false;
    }

    // Check if region base is already registered
    for slot in DECOY_REGIONS.iter() {
        if slot.0.load(Ordering::Acquire) == base {
            slot.1.store(size, Ordering::Release);
            return true;
        }
    }

    // Find an empty slot using CAS
    for slot in DECOY_REGIONS.iter() {
        if slot.0.compare_exchange(0, base, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            slot.1.store(size, Ordering::Release);
            return true;
        }
    }

    false // Table full (MAX_DECOY_REGIONS reached)
}

/// Clears all registered decoy regions (primarily for test isolation) (Feature F7).
pub fn clear_decoy_regions() {
    for slot in DECOY_REGIONS.iter() {
        slot.1.store(0, Ordering::Release);
        slot.0.store(0, Ordering::Release);
    }
}

unsafe fn spawn_decoy_traps() {
    let decoy_templates: [&[u8]; 3] = [
        b"XOR_KEY_BUFFER_STATIC_0xAF43\0",
        b"API_HASH_CACHE_V2_PROD\0",
        b"MZ\x90\0\x03\0\0\0\x04\0\0\0\xFF\xFF\0\0",
    ];
    
    for _ in 0..4 {
        // SAFETY: VirtualAlloc is called with valid flags (COMMIT|RESERVE) and permissions.
        // We handle null return check.
        let ptr = VirtualAlloc(ptr::null_mut(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !ptr.is_null() {
            let entropy = get_kuser_shared_entropy();
            let template = decoy_templates[(entropy % decoy_templates.len() as u64) as usize];
            
            // SAFETY: ptr is non-null and allocated 0x1000 bytes. template.len() is small.
            // memcpy is safe within bounds.
            ptr::copy_nonoverlapping(template.as_ptr(), ptr as *mut u8, template.len());
            
            let mut old = 0u32;
            // SAFETY: VirtualProtect is used to set PAGE_GUARD. This triggers the trap mechanism.
            // ptr is valid.
            VirtualProtect(ptr, 0x1000, PAGE_READWRITE | PAGE_GUARD, &mut old);
            register_decoy_region(ptr as usize, 0x1000);
        }
    }
}

// ============================================================================
// COMPONENT 3: SURGICAL PE OBFUSCATION
// ============================================================================

unsafe fn erase_critical_headers(base: *mut u8) {
    // SAFETY: base is derived from GetModuleHandle(NULL). 
    // We check for valid DOS signature (MZ) before proceeding.
    // All pointer arithmetic is based on relative offsets read from valid headers.
    let dos = base as *mut IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { 
        return; 
    }
    
    let nt_offset = (*dos).e_lfanew as usize;
    let nt = (base as usize + nt_offset) as *mut IMAGE_NT_HEADERS64;
    let mut old = 0u32;
    
    let prot_res = protected_virtual_protect(nt as *mut _, 512, PAGE_READWRITE, &mut old);
    if prot_res {
        let entropy = get_kuser_shared_entropy();
        
        // 1. Preserve NT Signature (PE\0\0) to ensure section headers and shard table remain accessible
        // for runtime integrity verification and system unwind stability (FLAW-08).
        // NOTE: We preserve Signature, DOS Header (e_magic) and section headers (.pdata unwind).

        // 2. Corrupt AddressOfEntryPoint -> Bricks execution flow analysis
        ptr::write_volatile(&mut (*nt).OptionalHeader.AddressOfEntryPoint, ((entropy >> 13) & 0xFFFFFFFF) as u32);
        
        // 3. Corrupt SizeOfImage -> Bricks memory dumping tools (incorrect size calc)
        // Set to a random large value to confuse dumpers
        ptr::write_volatile(&mut (*nt).OptionalHeader.SizeOfImage, ((entropy >> 7) & 0xFFFFFF) as u32);
        
        protected_virtual_protect(nt as *mut _, 512, PAGE_READONLY, &mut old);
    }
}

// ============================================================================
// COMPONENT 4: PRODUCTION VEH
// ============================================================================

// Legacy veh_handler removed.

// ============================================================================
// MAIN PRODUCTION INITIALIZATION
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_anti_dump() -> bool {
    // Atomic check allows multiple calls but only one initialization
    if INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return true; 
    }
    
    unsafe {
        let base = GetModuleHandleW(ptr::null());
        if base.is_null() { 
            return false; 
        }
        
        // Ensure shard table in pe_integrity is cached / initialized before erasing PE headers (FLAW-08)
        crate::protector::pe_integrity::init_shard_table();

        if !resolve_indirect_syscalls() {
            crate::protector::global_state::add_suspicion(crate::protector::global_state::DetectionSeverity::Medium);
        }
        
        let _ = resolve_exit_syscall();
        spawn_decoy_traps();
        erase_critical_headers(base);
    }
    
    true // Initialization successful
}

/// Public logic to check for guard page violations in decoy regions.
/// Called by Master VEH (enhanced_veh.rs).
/// Returns true if a Honeytrap was hit.
pub unsafe fn handle_guard_page_violation(ptrs: *mut EXCEPTION_POINTERS) -> bool {
    if ptrs.is_null() {
        return false;
    }
    let record = (*ptrs).ExceptionRecord;
    if !record.is_null() 
        && (*record).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION 
        && (*record).NumberParameters >= 2 
    {
        // In STATUS_GUARD_PAGE_VIOLATION, ExceptionInformation[1] is the accessed virtual address
        let fault_addr = (*record).ExceptionInformation[1] as usize;
        
        // F7: Lock-free, zero-allocation iteration over atomic decoy table
        for slot in DECOY_REGIONS.iter() {
            let base = slot.0.load(Ordering::Acquire);
            let size = slot.1.load(Ordering::Acquire);
            if base != 0 && size > 0 {
                // F5: Saturating interval point-containment
                if fault_addr >= base && fault_addr < base.saturating_add(size) {
                    // HONEYPOT HIT: Dumper or Scanner detected.
                    // F6: Transition triggered decoy page to PAGE_NOACCESS (quarantine)
                    // to prevent concurrent dumping threads from reading decoy memory undetected.
                    let mut old = 0u32;
                    let _ = VirtualProtect(base as *mut _, size, PAGE_NOACCESS, &mut old);
                    return true;
                }
            }
        }
    }
    false
}

// Helper for random data without external crates
fn get_kuser_shared_entropy() -> u64 {
    unsafe {
        // SAFETY: KUSER_SHARED_DATA is a fixed page at 0x7FFE0000 in Windows (user mode).
        // 0x7FFE0014 is InterruptTime (low), 0x7FFE0008 is SystemTime.
        let it_low = (0x7FFE0014 as *const u32).read_volatile();
        let st = (0x7FFE0008 as *const u64).read_volatile();
        (it_low as u64) ^ st
    }
}

/// Canonical Lock-Free KUSER_SHARED_DATA Time Reader (Feature F8)
///
/// In Windows NT, KSYSTEM_TIME structures in KUSER_SHARED_DATA (0x7FFE0000)
/// are updated non-atomically by the timer interrupt:
///   1. High2Time = NewHigh
///   2. LowPart   = NewLow
///   3. High1Time = NewHigh
///
/// Reading LowPart and High1Time without verifying High1Time == High2Time creates torn reads
/// during 32-bit rollovers, causing spurious jumps of ~429.5 seconds and triggering silent poisoning.
/// This lock-free loop ensures that the High1 and High2 words match, proving the 64-bit value is untorn.
#[inline(always)]
pub unsafe fn read_kuser_time_lock_free(base_addr: usize) -> u64 {
    let low_ptr = base_addr as *const u32;
    let high1_ptr = (base_addr + 4) as *const u32;
    let high2_ptr = (base_addr + 8) as *const u32;

    loop {
        let high1 = high1_ptr.read_volatile() as u64;
        let low = low_ptr.read_volatile() as u64;
        let high2 = high2_ptr.read_volatile() as u64;

        if high1 == high2 {
            return (high1 << 32) | low;
        }
        std::hint::spin_loop();
    }
}

/// DIRECT SYSCALL WATCHDOG
/// Checks if the VM loop has updated its heartbeat recently.
/// If not (thread suspended by debugger), it silently poisons execution.
pub unsafe fn check_system_liveness_via_kuser() {
    // 1. Warm-up Period: Skip liveness checks for the first 10 seconds
    if crate::protector::anti_debug::get_load_time().elapsed().as_secs() < 10 {
        return;
    }

    let last_heartbeat = crate::protector::global_state::LAST_VM_HEARTBEAT.load(Ordering::Relaxed);
    
    // If heartbeat is 0, system might be just starting, skip check
    if last_heartbeat == 0 { return; }
    
    // Read current time (100ns units) from KUSER_SHARED_DATA using lock-free rollover verification (Feature F8)
    // 0x7FFE0014 is LowPart, 0x7FFE0018 is High1Time, 0x7FFE001C is High2Time
    let current_time = read_kuser_time_lock_free(0x7FFE0014);
    
    // 2. Adaptive Thresholding
    // Default threshold: 5 seconds (50,000,000 units)
    let mut threshold = 50_000_000;
    
    // If system is under heavy load, double the threshold to avoid false positives
    if crate::protector::global_state::is_system_under_heavy_load() {
        threshold *= 2;
    }
    
    // Delta in 100ns units.
    let delta = current_time.wrapping_sub(last_heartbeat);
    
    if delta > threshold {
        // Heartbeat stopped! Likely debugger suspension or process freeze.
        // SILENT DEFENSE: Instead of killing, we poison the environment.
        crate::protector::global_state::trigger_silent_poisoning();
    }
}

/// Forcefully terminate process via Raw Syscall (Bypassing hooks)
unsafe fn sys_force_exit() {
    let ssn = EXIT_SYSCALL_ID.load(Ordering::Relaxed);
    if ssn == 0 {
        // Fallback if not initialized
        std::process::exit(0xDEAD);
    }
    
    let j_addr = SYSCALL_J_ADDR.load(Ordering::Relaxed);
    if j_addr.is_null() {
        std::process::exit(0xDEAD);
    }
    
    // NtTerminateProcess(ProcessHandle, ExitStatus)
    // ProcessHandle = -1 (Current Process)
    // ExitStatus = 0xC000000D (STATUS_INVALID_PARAMETER) - confusing error code
    
    #[cfg(target_arch = "x86_64")]
    std::arch::asm!(
        "mov r10, -1",      // Param 1: ProcessHandle
        "mov rdx, 0xC000000D", // Param 2: ExitStatus
        "mov eax, {ssn:e}", // SSN
        "syscall",
        ssn = in(reg) ssn,
        options(noreturn)
    );
}

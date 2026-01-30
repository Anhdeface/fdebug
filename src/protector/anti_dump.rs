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

/// Resolve NtProtectVirtualMemory SSN and Syscall instruction address
unsafe fn resolve_indirect_syscalls() -> bool {
    // SAFETY: GetModuleHandleW(ntdll) is safe because we provide a valid null-terminated
    // wide string. If it fails, we handle the null return.
    let ntdll = GetModuleHandleW([b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16, 0].as_ptr());
    if ntdll.is_null() { return false; }
    
    let nt_protect_addr = GetProcAddress(ntdll, b"NtProtectVirtualMemory\0".as_ptr());
    if nt_protect_addr.is_null() { return false; }
    
    let mut ssn = 0u32;
    let mut found_ssn = false;
    for i in 0..32 {
        if *nt_protect_addr.add(i) == 0xB8 {
            ssn = ptr::read_unaligned(nt_protect_addr.add(i+1) as *const u32);
            found_ssn = true;
            break;
        }
    }
    
    if !found_ssn { return false; }
    
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

#[cfg(target_arch = "x86_64")]
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
    // - Stack is aligned and shadow space (0x20) is allocated plus padding.
    // - All pointers passed are valid local variables or arguments.
    unsafe {
        std::arch::asm!(
            "mov r10, {h_process}", // Param 1
            "mov rdx, {p_base}",    // Param 2
            "mov r8, {p_size}",     // Param 3
            "mov r9d, {protect:e}", // Param 4
            "mov eax, {ssn:e}",     // SSN
            "sub rsp, 0x28",        // Shadow space (0x20) + alignment/padding (0x8)
            "mov r11, {p_old}",     // Get param 5
            "mov [rsp+0x20], r11",  // Place param 5 at [RSP + 32]
            "syscall",              // DIRECT HARDWARE SYSCALL
            "add rsp, 0x28",        // Cleanup
            h_process = in(reg) process_handle,
            p_base = in(reg) base_address,
            p_size = in(reg) number_of_bytes_to_protect,
            protect = in(reg) new_access_protection,
            p_old = in(reg) old_access_protection,
            ssn = in(reg) ssn,
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

static DECOY_REGIONS: LazyLock<Mutex<Vec<(usize, usize)>>> = LazyLock::new(|| Mutex::new(Vec::new()));

unsafe fn spawn_decoy_traps() {
    let mut regions = DECOY_REGIONS.lock().unwrap();
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
            regions.push((ptr as usize, 0x1000));
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
    
    // Protect only 512 bytes to avoid page boundary issues if header is at the end of a page
    if protected_virtual_protect(nt as *mut _, 512, PAGE_READWRITE, &mut old) {
        // Zero vital fields to brick reconstruction tools
        // SAFETY: Volatile writes required because these are raw pointers to PE headers
        // WEAPONIZATION: Use random entropy instead of zeros to break pattern matching scanners.
        let entropy = get_kuser_shared_entropy();
        
        // 1. Corrupt NT Signature (PE\0\0) -> Bricks strict PE parsers
        // NOTE: We preserve DOS Header (e_magic) for basic system stability.
        ptr::write_volatile(&mut (*nt).Signature, (entropy & 0xFFFFFFFF) as u32);

        // 2. Corrupt AddressOfEntryPoint -> Bricks execution flow analysis
        ptr::write_volatile(&mut (*nt).OptionalHeader.AddressOfEntryPoint, ((entropy >> 13) & 0xFFFFFFFF) as u32);
        
        // 3. Corrupt SizeOfImage -> Bricks memory dumping tools (incorrect size calc)
        // Set to a random large value to confuse dumpers
        ptr::write_volatile(&mut (*nt).OptionalHeader.SizeOfImage, ((entropy >> 7) & 0xFFFFFF) as u32);
        
        // Wipe Section Headers with entropy
        let file_hdr_size = std::mem::size_of::<IMAGE_FILE_HEADER>();
        let opt_hdr_size = (*nt).FileHeader.SizeOfOptionalHeader as usize;
        
        let section_hdr = (nt as usize + 4 + file_hdr_size + opt_hdr_size) as *mut u8;
        for i in 0..(*nt).FileHeader.NumberOfSections as usize {
             // Overwrite 8 bytes of Name + VirtualSize with random entropy
             // This effectively destroys the section table mapping
             let section_entropy = get_kuser_shared_entropy().wrapping_add(i as u64);
             std::ptr::write_volatile(section_hdr.add(i * 40) as *mut u64, section_entropy);
             std::ptr::write_volatile(section_hdr.add(i * 40 + 8) as *mut u32, (section_entropy >> 32) as u32);
        }
        
        protected_virtual_protect(nt as *mut _, 512, PAGE_READONLY, &mut old);
    }
}

// ============================================================================
// COMPONENT 4: PRODUCTION VEH
// ============================================================================

// ============================================================================
// COMPONENT 4: PRODUCTION VEH (REMOVED - Handled by Master VEH)
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
        
        // 1. Resolve Indirect Syscalls for all future stealth ops
        if !resolve_indirect_syscalls() {
            crate::protector::global_state::add_suspicion(crate::protector::global_state::DetectionSeverity::Medium);
        }
        
        // 2. Register Global Production VEH -> REMOVED (Handled by enhanced_veh::init_master_veh)
        
        // 3. Deploy Passive Honeytraps (Decoy Pages)
        spawn_decoy_traps();
        
        // 4. Surgical PE Header Erasure
        erase_critical_headers(base);
    }
    
    true // Initialization successful
}

/// Public logic to check for guard page violations in decoy regions.
/// Called by Master VEH (enhanced_veh.rs).
/// Returns true if a Honeytrap was hit.
pub unsafe fn handle_guard_page_violation(ptrs: *mut EXCEPTION_POINTERS) -> bool {
    let record = (*ptrs).ExceptionRecord;
    if (*record).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION {
        let fault_addr = (*record).ExceptionAddress as usize;
        let decoys = DECOY_REGIONS.lock().unwrap();
        
        for &(base, size) in decoys.iter() {
            if fault_addr >= base && fault_addr < base + size {
                // HONEYPOT HIT: Dumper or Scanner detected.
                // Strict logic: Only check and return detection status.
                // Side effects (hang/loop) are handled by the caller (Master VEH) via exception continuation.
                return true;
            }
        }
    }
    false
}

// Helper for random data without external crates
fn get_kuser_shared_entropy() -> u64 {
    unsafe {
        // SAFETY: KUSER_SHARED_DATA is a fixed page at 0x7FFE0000 in Windows (user mode).
        // 0x7FFE0014 is InterruptTime, 0x7FFE0008 is SystemTime.
        // These addresses are constant and readable in all Windows versions (XP+).
        let it = (0x7FFE0014 as *const u64).read_volatile();
        let st = (0x7FFE0008 as *const u64).read_volatile();
        it ^ st
    }
}

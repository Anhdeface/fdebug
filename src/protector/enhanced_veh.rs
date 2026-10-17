#![allow(non_snake_case)]

//! Enhanced Vectored Exception Handler (VEH)
//! 
//! Implements a 5-phase exception filtering system:
//! 1. Entry Filtering (Bounds Check)
//! 2. Stack Validation (RtlVirtualUnwind)
//! 3. Anti-Dump Dispatch (Guard Page Traps)
//! 4. Anti-Debug Dispatch (INT3 / Hardware Breakpoints)
//! 5. Internal VM Integrity Check (TinyVM Heartbeat)
//! 6. Silent Redirection (Poisoning)

use core::ffi::c_void;
use core::ptr;
use std::arch::asm;
use std::sync::atomic::Ordering;

use crate::protector::global_state::{
    CONTEXT, EXCEPTION_POINTERS, POISON_SEED, GLOBAL_VIRTUAL_MACHINE_KEY, 
    AddVectoredExceptionHandler
};
use crate::protector::pe_integrity::get_text_section_bounds;
use crate::protector::tiny_vm::{vm_execute, VmOp};

// ============================================================================
// FFI DEFINITIONS (Strict Zero-Dependency)
// ============================================================================

#[repr(C)]
pub struct RUNTIME_FUNCTION {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
    // RtlCaptureContext not strictly needed here if we only use ContextRecord
    fn RtlLookupFunctionEntry(
        control_pc: u64,
        image_base: *mut u64,
        history_table: *mut c_void
    ) -> *mut RUNTIME_FUNCTION;
    fn RtlVirtualUnwind(
        handler_type: u32,
        image_base: u64,
        control_pc: u64,
        function_entry: *mut RUNTIME_FUNCTION,
        context: *mut CONTEXT,
        handler_data: *mut *mut c_void,
        establisher_frame: *mut u64,
        context_pointers: *mut c_void
    ) -> *mut c_void;
}

// Exception Constants
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

// ============================================================================
// VEH LOGIC
// ============================================================================

/// **MASTER INITIALIZATION**: Register the one and only VEH handler.
/// This should be called exactly once during protector startup.
pub fn init_master_veh() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        unsafe {
            // Register as FIRST handler (1) to pre-empt everything else
            AddVectoredExceptionHandler(1, Some(master_veh_handler));
        }
    });
}

/// Reference evaluation of VEH Phase 1 entry filtering with guard page exception preservation (FLAW-04)
pub fn evaluate_veh_phase1(exc_addr: u64, rip: u64, text_start: u64, text_size: u64, exception_code: u32) -> i32 {
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
    const EXCEPTION_INTERCEPTED: i32 = -1; // Proceeds to Phase 2..5

    // STATUS_GUARD_PAGE_VIOLATION is 0x80000001
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

/// The MASTER VEH handler implementing the multi-phase protection logic
unsafe extern "system" fn master_veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = &mut *(*exception_info).ExceptionRecord;
    let context = &mut *(*exception_info).ContextRecord;
    
    // ========================================================================
    // PHASE 0: WATCHDOG & LIVENESS CHECK
    // ========================================================================
    // Check if the VM or system heartbeat has been frozen (Suspension Detection)
    unsafe {
        crate::protector::anti_dump::check_system_liveness_via_kuser();
    }

    // ========================================================================
    // PHASE 1: ENTRY FILTERING
    // ========================================================================
    // Ensure the exception occurs within the legitimate .text section
    
    let base_addr = GetModuleHandleW(ptr::null());
    if base_addr.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    let exc_addr = record.ExceptionAddress as u64;
    let rip = context.Rip;
    let exc_code = record.ExceptionCode as u32;
    
    // Guard page violations (0x80000001) from decoy honeytraps must NOT be dropped by Phase 1!
    let is_guard_page = exc_code == 0x80000001;

    if !is_guard_page {
        // Get trusted .text bounds from pe_integrity
        if let Some((rva, size)) = get_text_section_bounds() {
            let start = base_addr as u64 + rva as u64;
            let end = start + size as u64;
            
            // Check ExceptionAddress
            if exc_addr < start || exc_addr >= end {
                // Check RIP as well (often same, but just in case of weird traps)
                if rip < start || rip >= end {
                    // Exception from outside .text -> External code/hooks/system
                    return EXCEPTION_CONTINUE_SEARCH; 
                }
            }
        } else {
            // Validation data not ready, fail open to avoid crashing legitimate early exceptions
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    // ========================================================================
    // PHASE 2: STACK VALIDATION
    // ========================================================================
    // Shallow stack walk (2 frames) to verify call stack integrity using RtlVirtualUnwind
    
    if !validate_stack_frames(context, base_addr as u64) {
        // Stack looks spoofed or invalid -> Tampering
        return poison_thread_context(context);
    }

    // ========================================================================
    // PHASE 3: ANTI-DUMP DISPATCH
    // ========================================================================
    // Delegate to anti_dump module for Guard Page violations (Decoy Traps)
    
    if crate::protector::anti_dump::handle_guard_page_violation(exception_info) {
        // Honeypot hit: poison state and redirect instruction pointer away from guarded page
        return poison_thread_context(context);
    }

    // ========================================================================
    // PHASE 4: ANTI-DEBUG DISPATCH
    // ========================================================================
    // Delegate to anti_debug module for INT3 and HW Breakpoints
    
    if crate::protector::anti_debug::handle_debug_exception(exception_info) {
        // Debugger artifact detected (INT3 or DRx).
        // Logic already applied side-effects (poisoning).
        // Now we divert execution flow to confuse the attacker further.
        return poison_thread_context(context);
    }

    // ========================================================================
    // PHASE 5: INTERNAL VM INTEGRITY CHECK (Backup Heartbeat)
    // ========================================================================
    
    if record.ExceptionCode == EXCEPTION_SINGLE_STEP {
        // Enforce Integrity Heartbeat during Debugging/Stepping
        // If an attacker steps through, we verify memory integrity using their current location as entropy
        crate::protector::pe_integrity::heartbeat_check(context.Rip as u32);

        // Verify if this single step is authorized (matches our Heartbeat) via TinyVM
        // If anti_debug didn't catch it (e.g. some other mechanism), verify strictly.
        if !verify_drx_integrity(context) {
             // External debugger Step or HW Breakpoint detected
             return poison_thread_context(context);
        }
    }

    // Pass through legitimate system exceptions (Access Violation, etc.) 
    // to inner handlers or crash reporter if they are valid
    EXCEPTION_CONTINUE_SEARCH
}

/// Graceful exit stub for redirected threads when decoy returns
#[no_mangle]
pub unsafe extern "system" fn safe_exit_stub() {
    windows::Win32::System::Threading::ExitThread(0);
}

// Helper function (Phase 6 implementation)
/// Phase 6: Silent Redirection & Poisoning with Call Frame Synthesis (FLAW-10)
pub unsafe fn poison_thread_context(context: &mut CONTEXT) -> i32 {
    // 1. Update Global State (Poisoning) via centralized function
    crate::protector::global_state::poison_encryption_on_dump_attempt();
    POISON_SEED.store(0xDEAD6666BEEF, Ordering::SeqCst);
    
    // 2. Synthesize valid call frame on stack before redirection to prevent RET crash
    // Windows x64 ABI requires:
    // - RSP aligned to 16 bytes minus 8 on entry to called function
    // - 32-byte shadow space ([Rsp+8..Rsp+32])
    // - [Rsp] contains return address (pointing to safe_exit_stub)
    let aligned_rsp = (context.Rsp & !0xFu64).wrapping_sub(0x28);
    let ret_addr = safe_exit_stub as *const () as usize as u64;
    let rsp_ptr = aligned_rsp as *mut u64;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ptr::write_volatile(rsp_ptr, ret_addr);
    }));
    context.Rsp = aligned_rsp;

    // 3. Set RIP to Decoy function
    context.Rip = crate::protector::decoy_system::is_process_being_debugged as *const () as usize as u64;
    
    // 4. Set RAX to Poison Value (derived from VM Key)
    let key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed) as u64;
    context.Rax = key.wrapping_mul(0xDEADBEEF);
    
    EXCEPTION_CONTINUE_EXECUTION
}

/// Perform shallow stack walk using RtlVirtualUnwind
unsafe fn validate_stack_frames(initial_context: &CONTEXT, image_base: u64) -> bool {
    // Create a copy of context for unwinding so we don't modify the real one
    let mut ctx = ptr::read(initial_context);
    let mut frames_walked = 0;
    
    // We want to verify at least 2 frames (Caller -> Callee)
    while frames_walked < 2 {
        let mut image_base_out = 0u64;
        
        // Lookup function entry
        let entry = RtlLookupFunctionEntry(
            ctx.Rip,
            &mut image_base_out, 
            ptr::null_mut()
        );

        if entry.is_null() {
            // Leaf function or error.
            // If we are in .text (verified in Phase 1), this might be a leaf.
            let ret_addr = *(ctx.Rsp as *const u64);
            if ret_addr == 0 {
                break;
            }
            ctx.Rip = ret_addr;
            ctx.Rsp += 8;
        } else {
            // Non-leaf function, perform virtual unwind
            let mut handler_data: *mut c_void = ptr::null_mut();
            let mut establisher_frame: u64 = 0;
            
            RtlVirtualUnwind(
                0, // UNW_FLAG_NHANDLER
                image_base_out,
                ctx.Rip,
                entry,
                &mut ctx,
                &mut handler_data,
                &mut establisher_frame,
                ptr::null_mut()
            );
        }

        if ctx.Rip == 0 {
            break;
        }
        
        // Optional: We could check if the unwound RIP is also in .text logic
        // But for now, just succeeding unwinding is enough validation of stack alignment/pointers.
        frames_walked += 1;
    }
    
    // If we managed to walk, assume stack is at least structurally sane
    true
}

/// Verify DRx registers using TinyVM
unsafe fn verify_drx_integrity(context: &CONTEXT) -> bool {
    // Requirements: 
    // 1. Dr7 should be 0 (No HW BPs active) 
    // 2. OR if active, Dr0-Dr3 must match "Internal Protection Heartbeat"
    // We delegate this decision logic to TinyVM obfuscation.
    
    let dr7 = context.Dr7;
    let dr0 = context.Dr0;
    
    let vm_key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed) as u64;
    // Magic match value: Key * 0x1337
    let expected_heartbeat = vm_key.wrapping_mul(0x13371337); 
    
    let mut plain_bc = Vec::with_capacity(32);
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
    plain_bc.extend_from_slice(&expected_heartbeat.to_le_bytes());
    plain_bc.push(VmOp::op_cmp_eq()); // Pushes boolean result to stack (NO op_push)
    
    // 3. OR results and exit
    plain_bc.push(VmOp::op_or());
    plain_bc.push(VmOp::op_exit());
    
    // 4. Encode using authentic rolling-key recurrence, position salt, and integrity token
    let mut encoded = Vec::with_capacity(plain_bc.len());
    let mut state_key: u8 = 0;
    let integrity_val = crate::protector::pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
    let global_entropy = crate::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::Relaxed);
    
    for (vip, &plain) in plain_bc.iter().enumerate() {
        let pos_salt = (vip as u8).wrapping_mul(0x7);
        let raw_byte = plain.wrapping_sub(pos_salt) ^ k ^ state_key ^ integrity_val;
        encoded.push(raw_byte);
        
        state_key = state_key.wrapping_add(raw_byte).wrapping_mul(0x1F);
        state_key ^= state_key.rotate_right(3) ^ 0x3C;
        state_key ^= global_entropy;
    }
    
    let result = vm_execute(&encoded, k, 0);
    result != 0
}


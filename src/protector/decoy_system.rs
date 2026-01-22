#![allow(dead_code)]

//! Decoy System - Honey Pot Pattern for Anti-Reverse Engineering
//! Contains decoy functions that look important but are designed to catch hackers who try to patch them

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::arch::asm;

// Global atomic flag to track if decoy functions have been tampered with
static DECOY_TAMPERED: AtomicBool = AtomicBool::new(false);

// Counter for how many times tampering has been detected
static TAMPER_DETECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

// Store expected hashes for the decoy functions
static EXPECTED_KERNEL_DEBUGGER_HASH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static EXPECTED_PROCESS_DEBUGGED_HASH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static EXPECTED_ANTI_TAMPER_HASH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Fake kernel debugger check - looks important but does minimal checking
pub fn check_kernel_debugger() -> bool {
    // This function looks important but only does a basic check
    // If a hacker patches this to always return false, they'll trigger tamper detection

    // Basic check that's easy to bypass but looks important
    let result = unsafe {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    };

    // Perform tamper detection after the check
    detect_decoy_tampering("check_kernel_debugger");

    result // Return the result directly
}

/// Fake process debugging check - another decoy that looks critical
pub fn is_process_being_debugged() -> bool {
    // Another function that looks important but does basic checking
    // Designed to be patched by hackers, which triggers our detection

    // Simple check that's easy to fool but looks important
    let result = unsafe {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    };

    // Perform tamper detection after the check
    detect_decoy_tampering("is_process_being_debugged");

    !result // Return true if no debugger detected (opposite to confuse)
}

/// Fake anti-tamper validation - sounds important but is just a trap
pub fn anti_tamper_validation() -> bool {
    // This function sounds like it does important validation
    // but it's just another trap for hackers to fall into

    // Simple check that looks complex
    let entropy = get_cpu_entropy();
    let fake_threshold = 0x12345678u32;

    // This check is meaningless but looks important
    let result = (entropy ^ fake_threshold) != 0;

    // Perform tamper detection after the check
    detect_decoy_tampering("anti_tamper_validation");

    result
}

/// Function to detect if decoy functions have been tampered with
/// Uses checksums and pattern detection to detect if the function code has been modified
fn detect_decoy_tampering(function_name: &str) {
    // Get function pointers for the decoy functions
    let func_ptr = match function_name {
        "check_kernel_debugger" => check_kernel_debugger as *const fn() -> bool as *const u8,
        "is_process_being_debugged" => is_process_being_debugged as *const fn() -> bool as *const u8,
        "anti_tamper_validation" => anti_tamper_validation as *const fn() -> bool as *const u8,
        _ => return, // Unknown function
    };

    // Check for common patch patterns first (this catches RET patches immediately)
    let is_patched = is_function_patched(func_ptr);

    // Calculate a simple checksum of the first few bytes of the function
    let checksum = calculate_checksum(func_ptr, 10); // Check first 10 bytes for faster detection

    // Compare with expected checksums
    let is_checksum_modified = match function_name {
        "check_kernel_debugger" => {
            let expected = EXPECTED_KERNEL_DEBUGGER_HASH.load(Ordering::Relaxed);
            if expected == 0 {
                // First time: store the calculated hash as expected
                EXPECTED_KERNEL_DEBUGGER_HASH.store(checksum, Ordering::Relaxed);
                false
            } else {
                checksum != expected
            }
        },
        "is_process_being_debugged" => {
            let expected = EXPECTED_PROCESS_DEBUGGED_HASH.load(Ordering::Relaxed);
            if expected == 0 {
                // First time: store the calculated hash as expected
                EXPECTED_PROCESS_DEBUGGED_HASH.store(checksum, Ordering::Relaxed);
                false
            } else {
                checksum != expected
            }
        },
        "anti_tamper_validation" => {
            let expected = EXPECTED_ANTI_TAMPER_HASH.load(Ordering::Relaxed);
            if expected == 0 {
                // First time: store the calculated hash as expected
                EXPECTED_ANTI_TAMPER_HASH.store(checksum, Ordering::Relaxed);
                false
            } else {
                checksum != expected
            }
        },
        _ => false,
    };

    // If either patch pattern is detected OR checksum is modified, trigger tamper detection
    if is_patched || is_checksum_modified {
        // Set the tamper flag if modification is detected
        DECOY_TAMPERED.store(true, Ordering::SeqCst);

        // Increment tamper detection counter
        TAMPER_DETECTION_COUNT.fetch_add(1, Ordering::SeqCst);

        // Add suspicion score through the global state with high penalty
        add_tamper_suspicion();
    }
}

/// Calculate a simple checksum of memory region
fn calculate_checksum(ptr: *const u8, len: usize) -> u32 {
    let mut checksum = 0u32;

    unsafe {
        for i in 0..len {
            // Use volatile read to prevent optimization
            let byte = std::ptr::read_volatile(ptr.add(i));
            checksum = checksum.wrapping_add(byte as u32).wrapping_mul(31).wrapping_add(1);
        }
    }

    checksum
}

/// Check if the function has been patched with common patch patterns
fn is_function_patched(ptr: *const u8) -> bool {
    unsafe {
        // Check for common patch patterns in the first few bytes
        for i in 0..5 {
            let byte = std::ptr::read_volatile(ptr.add(i));

            // Check for RET instruction (0xC3) at the beginning
            if i == 0 && byte == 0xC3 {
                return true;
            }

            // Check for NOP sleds (0x90) which are common patches
            if byte != 0x90 {
                // If not all NOPs, continue checking other patterns
            }

            // Check for JMP instructions that redirect execution
            if byte == 0xEB || byte == 0xE9 {  // Short and near jumps
                return true;
            }

            // Check for INT3 breakpoints (0xCC)
            if byte == 0xCC {
                return true;
            }
        }

        // Additional check: if the first few bytes are all NOPs, it's likely patched
        let first_byte = std::ptr::read_volatile(ptr);
        let second_byte = std::ptr::read_volatile(ptr.add(1));
        let third_byte = std::ptr::read_volatile(ptr.add(2));

        // If it starts with multiple NOPs followed by RET, it's definitely patched
        if first_byte == 0x90 && second_byte == 0x90 && third_byte == 0x90 {
            return true;
        }
    }

    false
}

/// Get CPU entropy for additional checks
fn get_cpu_entropy() -> u32 {
    let mut result: u32 = 0;
    let success: u8;

    unsafe {
        asm!(
            "xor {result}, {result}",      // Clear result
            "rdrand {result}",             // Try to get random value from CPU
            "setc {success}",              // Set success flag based on carry flag
            result = out(reg) result,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }

    // If RDRAND failed, fall back to a combination of RDTSC and other sources
    if success == 0 {
        let (low, high): (u32, u32);
        unsafe {
            asm!(
                "lfence",
                "rdtsc",
                "lfence",
                out("eax") low,
                out("edx") high,
                options(nomem, nostack)
            );
        }
        result = low ^ high;
    }

    result
}

/// Add suspicion when tampering is detected
fn add_tamper_suspicion() {
    // Call the global state function to add suspicion
    // Use a random value to make it less predictable
    use crate::protector::global_state;
    let random_suspicion = (get_cpu_entropy() % 100) + 200; // Random value between 200-299
    global_state::add_suspicion(random_suspicion, 0); // Random suspicion score for tampering (category 0 for tampering)
}

/// Check if any decoy function has been tampered with
pub fn is_decoy_tampered() -> bool {
    DECOY_TAMPERED.load(Ordering::SeqCst)
}

/// Get the number of times tampering has been detected
pub fn get_tamper_count() -> usize {
    TAMPER_DETECTION_COUNT.load(Ordering::SeqCst)
}

/// Reset the tamper detection state (for testing purposes)
#[cfg(test)]
pub fn reset_tamper_detection() {
    DECOY_TAMPERED.store(false, Ordering::SeqCst);
    TAMPER_DETECTION_COUNT.store(0, Ordering::SeqCst);
    EXPECTED_KERNEL_DEBUGGER_HASH.store(0, Ordering::Relaxed);
    EXPECTED_PROCESS_DEBUGGED_HASH.store(0, Ordering::Relaxed);
    EXPECTED_ANTI_TAMPER_HASH.store(0, Ordering::Relaxed);
}

/// Function to perform anti-hooking checks in real system functions
/// This should be called from actual protection functions to detect tampering
pub fn perform_anti_hooking_check() {
    // Perform integrity checks on all decoy functions
    detect_decoy_tampering("check_kernel_debugger");
    detect_decoy_tampering("is_process_being_debugged");
    detect_decoy_tampering("anti_tamper_validation");
}

/// Watchdog function that performs random checks on decoy functions
/// This is called externally to monitor the decoy functions without them knowing
pub fn watchdog_check_decoys() -> bool {
    // Perform checks on all decoy functions and return if any tampering was detected
    let original_tampered = is_decoy_tampered();

    // Perform integrity checks on all decoy functions
    detect_decoy_tampering("check_kernel_debugger");
    detect_decoy_tampering("is_process_being_debugged");
    detect_decoy_tampering("anti_tamper_validation");

    // Return true if tampering was detected during this check
    is_decoy_tampered() && !original_tampered  // Only return true if newly detected
}
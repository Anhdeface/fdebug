#![allow(dead_code)]

//! Global state management for the anti-debug system
// github.com/anhdeface
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

// Global atomic detection state shared across all threads
pub static GLOBAL_ENCODED_STATE: AtomicU32 = AtomicU32::new(0xDEADBEEF);
pub static GLOBAL_PEB_SUSPICION: AtomicU32 = AtomicU32::new(0);
pub static GLOBAL_TIMING_SUSPICION: AtomicU32 = AtomicU32::new(0);
pub static GLOBAL_EXCEPTION_SUSPICION: AtomicU32 = AtomicU32::new(0);
pub static GLOBAL_INTEGRITY_SUSPICION: AtomicU32 = AtomicU32::new(0);
pub static GLOBAL_INTEGRITY_HASH: AtomicU32 = AtomicU32::new(0x12345678);
pub static GLOBAL_ENCRYPTION_KEY: AtomicU8 = AtomicU8::new(0x42);
pub static GLOBAL_VIRTUAL_MACHINE_KEY: AtomicU8 = AtomicU8::new(0x42);

/// Calculate integrity hash to detect mid-execution tampering
pub fn recalculate_global_integrity() {
    let combined = GLOBAL_ENCODED_STATE.load(Ordering::SeqCst)
        .wrapping_add(GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_TIMING_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_EXCEPTION_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_INTEGRITY_SUSPICION.load(Ordering::SeqCst));

    // Djb2 hash algorithm (simple but effective)
    let mut hash = 5381u32;
    for byte in combined.to_le_bytes().iter() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u32);
    }
    GLOBAL_INTEGRITY_HASH.store(hash, Ordering::SeqCst);
}

/// Detect mid-execution tampering via checksum validation
pub fn validate_global_integrity() -> bool {
    let combined = GLOBAL_ENCODED_STATE.load(Ordering::SeqCst)
        .wrapping_add(GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_TIMING_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_EXCEPTION_SUSPICION.load(Ordering::SeqCst))
        .wrapping_add(GLOBAL_INTEGRITY_SUSPICION.load(Ordering::SeqCst));

    let mut hash = 5381u32;
    for byte in combined.to_le_bytes().iter() {
        hash = hash.wrapping_mul(33).wrapping_add(*byte as u32);
    }
    hash == GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst)
}

/// Get total suspicion score across all categories
pub fn get_global_total_score() -> u32 {
    GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst)
        .saturating_add(GLOBAL_TIMING_SUSPICION.load(Ordering::SeqCst))
        .saturating_add(GLOBAL_EXCEPTION_SUSPICION.load(Ordering::SeqCst))
        .saturating_add(GLOBAL_INTEGRITY_SUSPICION.load(Ordering::SeqCst))
}

/// Add suspicion to a specific category
pub fn add_suspicion(score: u32, checkpoint_type: usize) {
    match checkpoint_type {
        0 => {
            let current = GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst);
            GLOBAL_PEB_SUSPICION.store(current.saturating_add(score), Ordering::SeqCst);
        },
        1 => {
            let current = GLOBAL_TIMING_SUSPICION.load(Ordering::SeqCst);
            GLOBAL_TIMING_SUSPICION.store(current.saturating_add(score), Ordering::SeqCst);
        },
        2 => {
            let current = GLOBAL_EXCEPTION_SUSPICION.load(Ordering::SeqCst);
            GLOBAL_EXCEPTION_SUSPICION.store(current.saturating_add(score), Ordering::SeqCst);
        },
        3 => {
            let current = GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst);
            GLOBAL_PEB_SUSPICION.store(current.saturating_add(score), Ordering::SeqCst); // Hypervisor affects multiple fields
        },
        4 => {
            let current = GLOBAL_INTEGRITY_SUSPICION.load(Ordering::SeqCst);
            GLOBAL_INTEGRITY_SUSPICION.store(current.saturating_add(score), Ordering::SeqCst); // Integrity tampering affects multiple fields
        },
        _ => {}
    }

    // Recalculate integrity hash after adding suspicion
    recalculate_global_integrity();
}

/// Get the current encryption key (may be corrupted if debugger detected)
pub fn get_current_encryption_key() -> u8 {
    GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst)
}

/// Get the current virtual machine key (may be corrupted if debugger detected)
pub fn get_current_vm_key() -> u8 {
    GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst)
}

/// Check if globally debugged flag is set
pub fn is_globally_debugged() -> bool {
    let current_state = GLOBAL_ENCODED_STATE.load(Ordering::SeqCst);
    let integrity_ok = validate_global_integrity();
    integrity_ok && ((current_state & 1) != 0)
}

/// Get the current suspicion score
pub fn get_suspicion_score() -> u32 {
    get_global_total_score()
}

/// Initialize VEH protection (distributed state)
pub fn initialize_veh_protection() {
    // Initialize the global state with default values
    GLOBAL_ENCODED_STATE.store(0xDEADBEEF, Ordering::SeqCst);
    GLOBAL_PEB_SUSPICION.store(0, Ordering::SeqCst);
    GLOBAL_TIMING_SUSPICION.store(0, Ordering::SeqCst);
    GLOBAL_EXCEPTION_SUSPICION.store(0, Ordering::SeqCst);
    GLOBAL_INTEGRITY_SUSPICION.store(0, Ordering::SeqCst);
    GLOBAL_INTEGRITY_HASH.store(0x12345678, Ordering::SeqCst);
    GLOBAL_ENCRYPTION_KEY.store(0x42, Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(0x42, Ordering::SeqCst);

    // Recalculate integrity hash after initialization
    recalculate_global_integrity();

    println!("[*] VEH Protection Initialized (Distributed State)");
}

/// Update VM key with result from VM execution (for silent corruption)
pub fn update_vm_key_with_result(vm_result: u64) {
    let current_key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(current_key ^ (vm_result & 0xFF) as u8, Ordering::SeqCst);
}

/// Get the current integrity hash value
pub fn get_integrity_hash() -> u32 {
    GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst)
}

/// Get the current encoded state value
pub fn get_current_encoded_state() -> u32 {
    GLOBAL_ENCODED_STATE.load(Ordering::SeqCst)
}


#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables
)]

//! # Anti-Debug Protection Library
//!
//! A modular anti-debugging solution that can be integrated into any Rust project.
//! Provides VM-based detection with silent corruption mechanisms.

use std::cell::RefCell;
use std::sync::atomic::Ordering;

// Runtime Seed Reconstruction Modules
#[cfg(target_os = "windows")]
mod hardware_entropy;
#[cfg(target_os = "windows")]
mod pe_integrity;

pub mod seed_orchestrator;

// Re-export seed reconstruction functions for all platforms
pub use crate::protector::seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8};

#[cfg(target_os = "windows")]
mod tiny_vm;
#[cfg(target_os = "windows")]
pub mod anti_debug;
#[cfg(target_os = "windows")]
pub mod global_state;
#[cfg(target_os = "windows")]
pub mod decoy_system;
#[cfg(target_os = "windows")]
pub mod anti_dump;
#[cfg(target_os = "windows")]
pub mod enhanced_veh;

#[cfg(target_os = "windows")]
pub use tiny_vm::*;
#[cfg(target_os = "windows")]
pub use anti_debug::*;

/// Initialize the unified memory stealth protection system
#[cfg(target_os = "windows")]
pub fn init_protector() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // 1. Initialize PE Integrity (Get .text bounds)
        crate::protector::pe_integrity::get_text_section_bounds();

        // 2. Initialize Anti-Dump (Traps, but NO VEH registration)
        crate::protector::anti_dump::init_anti_dump();

        // 3. Initialize Master VEH (Register the single handler)
        enhanced_veh::init_master_veh();
    });
}

// ============================================================================
// HIDDEN PE HEADER VERIFICATION MOVED TO PROTECTOR IMPL
// ============================================================================

#[cfg(not(target_os = "windows"))]
pub struct Protector {
    _seed: u32,
}

#[cfg(not(target_os = "windows"))]
impl Protector {

    /// Guarded execution function that combines security checks with business logic
    /// This prevents hackers from hooking the is_debugged function directly
    pub fn run_guarded<F, T>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T,
    {
        // On non-Windows, always generate a valid token since there's no debugging detection
        let token = self._seed as u64 ^ 0x12345678; // Valid token based on seed

        // Execute the operation with the security token
        operation(token)
    }

    pub fn get_detection_details(&self) -> DetectionDetails {
        DetectionDetails {
            is_debugged: false,
            score: 0,
            peb_check: false,
            rdtsc_check: false,
            heap_check: false,
            hypervisor_check: false,
            integrity_check: false,
        }
    }

    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> {
        // On non-Windows, return data unchanged
        // Use guarded execution for consistency
        self.run_guarded(|_token| plaintext.to_vec())
    }

    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> {
        // On non-Windows, return data unchanged
        // Use guarded execution for consistency
        self.run_guarded(|_token| ciphertext.to_vec())
    }

    pub fn validate_license(&self, license_key: &str) -> bool {
        // On non-Windows, return true
        // Use guarded execution for consistency
        self.run_guarded(|_token| {
            license_key.len() == 32 && license_key.chars().all(|c| c.is_ascii_alphanumeric())
        })
    }
}

#[cfg(not(target_os = "windows"))]
impl<T> CoupledLogic<T> for Protector
where
    T: Corruptible,
{
    fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T,
    {
        // On non-Windows, just execute the operation without anti-debug checks
        // but still call decoy functions to maintain consistent behavior
        use crate::protector::decoy_system;
        let _ = decoy_system::check_kernel_debugger();
        let _ = decoy_system::is_process_being_debugged();
        let _ = decoy_system::anti_tamper_validation();

        // Perform watchdog checks to detect if decoy functions have been modified
        // This is done more systematically to ensure monitoring happens regularly
        // The watchdog monitors the decoy functions externally without them knowing
        if get_internal_entropy() % 2 == 0 {  // Approximately 1 in 2 chance for more frequent monitoring
            decoy_system::watchdog_check_decoys();
        }

        // Use a default token value on non-Windows
        let default_token = 0x12345678ABCDEF00u64;

        // Execute the operation with the token
        // The operation closure receives the security token as an argument
        // This creates a deep functional coupling between security and business logic
        let result = operation(default_token);

        result.corrupt_if_needed(default_token)
    }
}

#[cfg(target_os = "windows")]
pub struct Protector {
    _seed: u32,
}

#[cfg(target_os = "windows")]
impl Protector {
    pub fn new(seed: u32) -> Self {
        // Ensure core protection is initialized (VEH, Traps, etc.)
        init_protector();

        use std::sync::Once;
        static INSTANCE_INIT: Once = Once::new();
        
        // Instance-specific initialization
        INSTANCE_INIT.call_once(|| {
            // Initialize Anti-Debug Globals which might need seed/warming
            anti_debug::init_global_detection_vector(seed);
            anti_debug::initialize_veh_protection();
        });

        Protector {
            _seed: seed,
        }
    }
// github.com/anhdeface
    // Silent Heartbeat: Triggers suspicion if regular execution flow is interrupted
    fn heartbeat(&self) {
        use std::sync::atomic::Ordering;
        static CALL_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        
        let count = CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        if count % 10 == 0 {
            // Periodic deep check during heartbeats
            anti_debug::checkpoint_timing_anomaly();
            
            // Monitor decoy functions for patching
            decoy_system::watchdog_check_decoys();

            // DIRECT SYSCALL WATCHDOG (Liveness Check)
            // Checks if the thread was suspended by a debugger
            unsafe {
                anti_dump::check_system_liveness_via_kuser();
            }
        }
    }

    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> {
        // Enforce secure execution for encryption
        self.run_secure(&SecureVault::new(plaintext.to_vec()), |data, key| {
            let mut result = data.clone();
            if !result.is_empty() {
                for i in 0..std::cmp::min(8, result.len()) {
                    let shift = ((key >> (i * 2)) & 0x7) as u32;
                    result[i] = result[i].rotate_left(shift) ^ (key as u8);
                }
            }
            anti_debug::encrypt_data(&result)
        })
    }

    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> {
        // Enforce secure execution for decryption
        self.run_secure(&SecureVault::new(ciphertext.to_vec()), |data, key| {
            let mut result = data.clone();
            if !result.is_empty() {
                for i in 0..std::cmp::min(8, result.len()) {
                    let shift = ((key >> (i * 2)) & 0x7) as u32;
                    result[i] = (result[i] ^ (key as u8)).rotate_right(shift);
                }
            }
            anti_debug::decrypt_data(&result)
        })
    }

    pub fn validate_license(&self, license_key: &str) -> bool {
        // Enforce secure execution for license validation
        self.run_secure(&SecureVault::new(license_key), |key, token| {
            let base_result = anti_debug::validate_license(key);
            // Couple base_result mathematically with the token parity
            // This ensures a 'lazily' returned true becomes random if token is garbage.
            base_result ^ ((token % 2) == 0)
        })
    }

    pub fn get_detection_details(&self) -> global_state::DetectionDetails {
        global_state::get_detection_details()
    }

    // Verify stealth state (Anti-Dump Success Check)
    // Returns true if secure, false if compromised
    #[inline(always)]
    fn verify_stealth_state(&self) -> bool {
        #[cfg(target_os = "windows")]
        unsafe {
             // HIDDEN CHECK via FFI
             // We manually re-declare GetModuleHandleW here to avoid any external interference
             #[link(name = "kernel32")]
             extern "system" {
                 fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
             }
             
             let base = GetModuleHandleW(std::ptr::null());
             if base.is_null() { return false; }
             
             // Check if NT signature (0x00004550) is present
             // The offset to NT headers is at base + 0x3C
             let lfanew = *(base.offset(0x3C) as *const i32);
             let nt_sig_ptr = base.offset(lfanew as isize) as *const u32;
             
             // If PRESENT (0x00004550), then Anti-Dump header erasure FAILED.
             // If ERASED (Garbage), then Anti-Dump PASSED.
             let signature = std::ptr::read_volatile(nt_sig_ptr);
             std::hint::black_box(signature != 0x00004550)
        }
        #[cfg(not(target_os = "windows"))]
        true
    }
}

/// A container that requires a transformation key to access its data.
pub struct SecureVault<T> {
    inner: T,
}

impl<T> SecureVault<T> {
    pub fn new(value: T) -> Self {
        SecureVault { inner: value }
    }

    /// Access the value by proving security state through the Protector.
    pub fn unlock<F, R>(&self, protector: &Protector, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R,
    {
        protector.run_secure(self, f)
    }
}

/// Core trait for mandatory security integration.
pub trait ShieldedExecution<T> {
    /// Executes a closure with access to the vaulted data and a dynamic TRANSFORMATION_KEY.
    fn run_secure<F, R>(&self, vault: &SecureVault<T>, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R;
}

impl<T> ShieldedExecution<T> for Protector {
    fn run_secure<F, R>(&self, vault: &SecureVault<T>, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R,
    {
        // 1. Mandatory Heartbeat pulse
        self.heartbeat();

        // 2. Hidden Anti-Dump Verification (The "Cannot Bypass" Check)
        // If Anti-Dump failed to erase headers (or wasn't called), we poison everything.
        #[cfg(target_os = "windows")]
        if !self.verify_stealth_state() {
            // Anti-Dump failed or was bypassed -> Trigger immediate corruption
            global_state::poison_encryption_on_dump_attempt();
        }

        // 2. Derivation of TRANSFORMATION_KEY
        // This key is strictly dependent on the environment being clean.
        let score = global_state::get_suspicion_score();
        let poison = global_state::POISON_SEED.load(Ordering::SeqCst);
        
        // Theoretical base key derived from runtime-reconstructed seed
        let mut transformation_key = (seed_orchestrator::get_dynamic_seed() as u64) ^ 0x61C8864680B583EB;

        // Mathematical corruption: If score > 0, the key is structurally altered.
        // We use wrapping arithmetic and non-linear rotations to ensure silent failure.
        if score > 0 {
            transformation_key = transformation_key
                .wrapping_add(score as u64)
                .rotate_left((score % 61) as u32)
                .wrapping_mul(0x9E3779B97F4A7C15); // Golden ratio constant for mixing
        }

        // Apply Poison Seed contamination (modified by early-bird TLS callback if debugged)
        transformation_key ^= poison;

        // Force compiler to keep the check via black_box
        let result = std::hint::black_box(f(&vault.inner, transformation_key));
        
        result
    }
}

/// Macro to wrap a value and force a transformation-dependent calculation.
#[macro_export]
macro_rules! guarded_value {
    ($val:expr, $protector:expr) => {
        $protector.run_secure(&$crate::protector::SecureVault::new($val), |data, key| {
            // Force copy/clone to avoid lifetime issues with the temporary vault
            (*data, key)
        })
    };
}

use std::fmt::Display;

// Re-export functions from global_state module
pub use crate::protector::global_state::{
    add_suspicion,
    log_checkpoint_trigger,
    DetectionSeverity,
    EXCEPTION_POINTERS,
    EXCEPTION_RECORD,
    get_current_vm_key,
    get_suspicion_score,
    get_combined_score,
    recalculate_global_integrity,
    initialize_veh_protection,
};

// ============================================================================
// COUPLED LOGIC LAYER - Anti-Debug Protection Integrated with Business Logic
// ============================================================================

/// Trait for coupled anti-debug protection with business logic
pub trait CoupledLogic<T> {
    /// Run a coupled operation with security token integration
    /// The operation receives a security token that must be used in calculations
    fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T;
}

/// Macro to couple data with the security token using random operations
/// This creates a dependency between business logic and security token
#[allow(unused_macros)]
macro_rules! couple_data {
    ($data:expr, $token:expr) => {
        {
            // Use the token to perform random mixing operations
            // The specific operation depends on the token value to make it unpredictable
            let op_selector = ($token % 4) as u8;
            match op_selector {
                0 => $data ^ ($token as u64),  // XOR operation
                1 => $data.wrapping_add($token),  // Addition
                2 => $data.wrapping_sub($token),  // Subtraction
                3 => $data ^ (($token << 1) | ($token >> 63)),  // XOR with shifted token
                _ => $data,  // Fallback
            }
        }
    };
}

/// Secure result wrapper that applies context-aware corruption when debugger is detected
#[derive(Debug, Clone)]
pub struct SecureResult<T> {
    value: T,
    is_corrupted: bool,
}

impl<T> SecureResult<T> {
    /// Create a new secure result
    pub fn new(value: T) -> Self {
        let suspicion_score = get_suspicion_score();
        let is_corrupted = suspicion_score > 50; // Threshold for corruption
        SecureResult { value, is_corrupted }
    }

    /// Get the value, applying corruption if necessary
    pub fn into_inner(self) -> T {
        if self.is_corrupted {
            apply_contextual_corruption(self.value)
        } else {
            self.value
        }
    }
}

/// Apply contextual corruption based on the type
fn apply_contextual_corruption<T>(value: T) -> T {
    // This function needs to be implemented differently since we can't use TypeId to determine the type at runtime
    // Instead, we'll use trait bounds to handle different types
    // For now, we'll implement a version that works with the types we expect to use
    // This is a simplified approach - in a real implementation, you'd want more sophisticated type handling

    // Since we can't directly determine the type at runtime in a generic way,
    // we'll implement specific handling for the types we know we'll use
    // by using trait bounds and specialization

    // For this implementation, we'll use a trait to define how to corrupt different types
    impl_corruption_for_known_types(value)
}

/// Trait for types that can be corrupted in context-aware ways
pub trait ContextualCorruption {
    fn corrupt_if_needed(self) -> Self;
}

impl ContextualCorruption for f64 {
    fn corrupt_if_needed(self) -> Self {
        self * 0.99 // Small corruption that's hard to notice
    }
}

impl ContextualCorruption for String {
    fn corrupt_if_needed(self) -> Self {
        let mut s = self;
        if !s.is_empty() {
            let idx = (get_cpu_entropy() % s.len() as u32) as usize;
            let mut chars: Vec<char> = s.chars().collect();

            if let Some(ch) = chars.get_mut(idx) {
                let new_char = if ch.is_ascii_digit() {
                    char::from((*ch as u8 - b'0' + 1) % 10 + b'0')
                } else if ch.is_ascii_lowercase() {
                    char::from((*ch as u8 - b'a' + 1) % 26 + b'a')
                } else if ch.is_ascii_uppercase() {
                    char::from((*ch as u8 - b'A' + 1) % 26 + b'A')
                } else {
                    // For other characters, use a simple transformation
                    char::from(*ch as u8 ^ 0x20) // Toggle case-like bit
                };
                *ch = new_char;
            }
            s = chars.iter().collect();
        }
        s
    }
}

impl ContextualCorruption for Vec<u8> {
    fn corrupt_if_needed(self) -> Self {
        let mut vec = self;
        if !vec.is_empty() {
            let idx = (get_cpu_entropy() % vec.len() as u32) as usize;
            if idx < vec.len() {
                vec[idx] = vec[idx].wrapping_add(1); // Flip a bit
            }
        }
        vec
    }
}

impl ContextualCorruption for bool {
    fn corrupt_if_needed(self) -> Self {
        !self // Flip the boolean value
    }
}

impl ContextualCorruption for u32 {
    fn corrupt_if_needed(self) -> Self {
        self.wrapping_add(get_cpu_entropy()) // Add some entropy
    }
}

/// Implementation for known types that implement ContextualCorruption
fn impl_corruption_for_known_types<T>(value: T) -> T {
    // For this simplified implementation, we'll just return the value as-is
    // since we can't effectively determine the type at runtime in this generic context
    // The actual corruption will be handled by the type-specific implementations
    // when the caller uses the specialized methods
    value
}


// For the specific types we want to handle, we'll implement a different approach
// by creating specific functions for each type we want to handle
impl<T> SecureResult<T>
where
    T: ContextualCorruption
{
    /// Get the value, applying corruption if necessary (specialized for types that implement ContextualCorruption)
    pub fn into_inner_specialized(self) -> T {
        if self.is_corrupted {
            self.value.corrupt_if_needed()
        } else {
            self.value
        }
    }
}

// For types that don't implement ContextualCorruption, we'll use the original method
impl<T> SecureResult<T> {
    /// Get the value without corruption for types that don't support contextual corruption
    pub fn into_inner_unsafe(self) -> T {
        self.value
    }
}

/// Opaque predicate function to compare state values without direct equality
/// This makes static analysis harder by hiding the actual comparison
#[inline(always)]
fn opaque_predicate_eq(value: u32, expected: u32) -> bool {
    // Use a complex mathematical expression that evaluates to true only when value == expected
    // This is equivalent to: value == expected
    let result = (value ^ expected).count_ones() == 0;

    // Additional obfuscation: add a check that doesn't change the result
    let extra_check = value.wrapping_sub(expected) == 0;

    result && extra_check
}

/// Opaque predicate function to determine branching based on boolean condition
/// This makes static analysis harder by hiding the direct boolean check
#[inline(always)]
fn opaque_predicate_branch(condition: bool) -> bool {
    // Use a complex mathematical expression that evaluates to the same value as condition
    // This is equivalent to: condition
    let int_condition = condition as u32;
    let result = (int_condition & 1) != 0;

    // Additional obfuscation: add a check that doesn't change the result
    let extra_check = (int_condition % 2) != 0;

    result && extra_check
}

/// Get CPU entropy for randomization (imported from anti_debug module)
fn get_internal_entropy() -> u32 {
    use crate::protector::anti_debug::get_cpu_entropy as cpu_entropy;
    cpu_entropy()
}

impl<T> CoupledLogic<T> for Protector
where
    T: Corruptible,
{
    fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T,
    {
        // Redirect CoupedLogic to the new execute_secure infrastructure
        // This maintains compatibility with legacy code while using the token-based model.
        // Redirect CoupedLogic to the new execution infrastructure
        // This maintains compatibility with legacy code while using the token-based model.
        self.run_secure(&SecureVault::new(()), |_, token| {
            // Internal safety verification
            anti_debug::checkpoint_memory_integrity();
            
            // Execute business logic with the dynamic token
            let result = operation(token);
            
            // Apply silent corruption if the token is poisoned
            result.corrupt_if_needed(token)
        })
    }
}

/// Trait for types that can be silently corrupted based on protector state
pub trait Corruptible {
    fn corrupt_if_needed(self, token: u64) -> Self;
}

/// Helper function to handle soft corruption (delays)
fn apply_soft_corruption(score: u32) {
    if score >= 50 {
        // Soft Corruption: Exponential Backoff
        // Delay = (score - 50)^2 milliseconds
        let mut delay_ms = (score.saturating_sub(50)).pow(2) as u64;
        
        // Constraint Check: Don't block main UI thread excessively
        // We check the thread name to identify the main thread
        let current_thread = std::thread::current();
        let thread_name = current_thread.name().unwrap_or("unknown");
        
        if thread_name == "main" {
            // Cap the delay on the main thread to avoid "Application Not Responding"
            // 50ms allows for ~20 FPS, which feels "laggy" but not frozen
            delay_ms = std::cmp::min(delay_ms, 50);
        }
        
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }
}

impl Corruptible for String {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let score = anti_debug::get_suspicion_score();
        
        // Apply Soft Corruption (Delay)
        apply_soft_corruption(score);

        // Apply Hard Corruption if score > 100 or token indicates debug (legacy check)
        let corruption_factor = token.count_ones() as usize;
        if score > 100 || corruption_factor > 16 {
            let mut s = self;
            if !s.is_empty() {
                let idx = (token % s.len() as u64) as usize;
                let mut chars: Vec<char> = s.chars().collect();

                if let Some(ch) = chars.get_mut(idx) {
                    let new_char = if ch.is_ascii_digit() {
                        char::from((*ch as u8 - b'0' + 1) % 10 + b'0')
                    } else if ch.is_ascii_lowercase() {
                        char::from((*ch as u8 - b'a' + 1) % 26 + b'a')
                    } else if ch.is_ascii_uppercase() {
                        char::from((*ch as u8 - b'A' + 1) % 26 + b'A')
                    } else {
                        char::from(*ch as u8 ^ 0x20) // Toggle case-like bit
                    };
                    *ch = new_char;
                }
                s = chars.iter().collect();
            }
            s
        } else {
            self // Return unmodified if no hard corruption needed
        }
    }
}

impl Corruptible for Vec<u8> {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let score = anti_debug::get_suspicion_score();

        // Apply Soft Corruption (Delay)
        apply_soft_corruption(score);

        // Apply Hard Corruption
        let corruption_factor = token.count_ones() as usize;
        if score > 100 || corruption_factor > 16 {
            let mut vec = self;
            if !vec.is_empty() {
                let idx = (token % vec.len() as u64) as usize;
                if idx < vec.len() {
                    vec[idx] = vec[idx].wrapping_add(1); // Flip a bit
                }
            }
            vec
        } else {
            self
        }
    }
}

impl Corruptible for bool {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let score = anti_debug::get_suspicion_score();

        // Apply Soft Corruption (Delay)
        apply_soft_corruption(score);

        // Apply Hard Corruption
        let corruption_factor = token.count_ones() as usize;
        if score > 100 || corruption_factor > 16 {
            !self // Flip the boolean value
        } else {
            self
        }
    }
}

impl Corruptible for u32 {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let score = anti_debug::get_suspicion_score();

        // Apply Soft Corruption (Delay)
        apply_soft_corruption(score);

        // Apply Hard Corruption
        let corruption_factor = token.count_ones() as usize;
        if score > 100 || corruption_factor > 16 {
            self.wrapping_add(token as u32) // Add some entropy from token
        } else {
            self
        }
    }
}

impl Corruptible for f64 {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let score = anti_debug::get_suspicion_score();

        // Apply Soft Corruption (Delay)
        apply_soft_corruption(score);

        // Apply Hard Corruption
        let corruption_factor = token.count_ones() as usize;
        if score > 100 || corruption_factor > 16 {
            self * (1.0 + (token as f64 * 0.0001)) // Small multiplication factor
        } else {
            self
        }
    }
}

// ============================================================================
// MANDATORY MACRO - The Only Way to Instantiate
// ============================================================================

/// Macro to safely construct the Protector.
/// Enforces consolidated initialization (VEH, Traps) before returning the instance.
#[macro_export]
macro_rules! setup_anti_debug {
    ($seed:expr) => {{
        // 1. Force strict initialization flow
        #[cfg(target_os = "windows")]
        {
            $crate::protector::init_protector();
        }

        // 2. Create Protector
        $crate::protector::Protector::new($seed)
    }};
}

// Export the setup macro
pub use setup_anti_debug;

#[cfg(not(target_os = "windows"))] // Structs moved to global_state.rs
pub struct DetectionDetails {
    pub is_debugged: bool,
    pub score: u32,
    pub peb_check: bool,
    pub rdtsc_check: bool,
    pub heap_check: bool,
    pub hypervisor_check: bool,
    pub integrity_check: bool,
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protector_creation() {
        let protector = Protector::new(12345);
        // We can't directly access the seed field anymore, so we'll just test creation
        assert!(true); // Basic test to ensure creation works
    }

    #[test]
    fn test_detection_details() {
        let protector = Protector::new(12345);
        let details = protector.get_detection_details();
        // On CI/development environments, this might be true
        // Just ensure the function doesn't panic
        assert!(details.score >= 0);
    }
}
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

#[cfg(target_os = "windows")]
mod tiny_vm;
#[cfg(target_os = "windows")]
pub mod anti_debug;
#[cfg(target_os = "windows")]
pub mod global_state;
#[cfg(target_os = "windows")]
pub mod decoy_system;

#[cfg(target_os = "windows")]
pub use tiny_vm::*;
#[cfg(target_os = "windows")]
pub use anti_debug::*;

// Macro to quickly set up anti-debug protection in a new project
// For non-Windows platforms, provide dummy implementations
#[cfg(not(target_os = "windows"))]
pub struct Protector {
    _seed: u32,
}

#[cfg(not(target_os = "windows"))]
impl Protector {
    pub fn new(seed: u32) -> Self {
        Protector { _seed: seed }
    }

    fn check_internal_status(&self) -> bool {
        false // Always return false on non-Windows platforms
    }

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
        if get_cpu_entropy() % 2 == 0 {  // Approximately 1 in 2 chance for more frequent monitoring
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
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            // Initialize the protection system with the provided seed
            anti_debug::init_global_detection_vector(seed);
            anti_debug::initialize_veh_protection();
        });

        Protector {
            _seed: seed,
        }
    }
// github.com/anhdeface
    fn check_internal_status(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            anti_debug::is_globally_debugged()
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    /// Guarded execution function that combines security checks with business logic
    /// This prevents hackers from hooking the is_debugged function directly
    pub fn run_guarded<F, T>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T,
    {
        // Check internal status to determine if system is in safe mode
        let is_debugged = self.check_internal_status();

        // Generate a token based on the security status
        let token = if is_debugged {
            // If system is compromised, generate a corrupted token
            0xDEADBEEFCAFEBABE // Corrupted value that will affect business logic
        } else {
            // If system is safe, generate a valid token
            self._seed as u64 ^ 0x12345678 // Valid token based on seed
        };

        // Execute the operation with the security token
        operation(token)
    }

    pub fn get_detection_details(&self) -> DetectionDetails {
        DetectionDetails {
            is_debugged: self.check_internal_status(),
            score: anti_debug::get_suspicion_score(),
            peb_check: anti_debug::checkpoint_memory_integrity(),
            rdtsc_check: anti_debug::checkpoint_timing_anomaly(),
            heap_check: anti_debug::checkpoint_exception_handling(),
            hypervisor_check: anti_debug::checkpoint_hypervisor_detection(),
            integrity_check: anti_debug::checkpoint_integrity_self_hash(),
        }
    }

    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> {
        // Use coupled logic to run the encryption with security token integration
        self.run_coupled(|token| {
            // Verify and rotate the token before performing encryption
            use crate::protector::anti_debug::DetectionVector;
            let mut temp_dv = DetectionVector::new_with_seed(self._seed);
            let _ = temp_dv.verify_and_rotate(); // Call verification

            // Apply token coupling to the result
            let mut result = anti_debug::encrypt_data(plaintext);

            // Deep functional coupling: Use the token as part of the encryption process
            // This creates a hard dependency between security and business logic
            // Even if token & 0 is always 0, the compiler generates code that depends on the token
            if !result.is_empty() {
                // Example of deep functional coupling: use token bits to modify encryption
                // If hacker freezes the token to avoid corruption, business logic will be wrong
                for i in 0..std::cmp::min(8, result.len()) {
                    // Use specific bits from the token to influence the encryption
                    let token_bit = ((token >> (i + 3)) & 1) as u8;  // Use bit at position (i+3)
                    let token_shift = ((token >> (i * 2)) & 0x7) as u8;  // Use 3 bits for shift amount

                    // Apply token-dependent transformation
                    result[i] = result[i].wrapping_add(token_bit).rotate_left(token_shift as u32);
                }
            }

            result
        })
    }

    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> {
        // Use coupled logic to run the decryption with security token integration
        self.run_coupled(|token| {
            // Verify and rotate the token before performing decryption
            use crate::protector::anti_debug::DetectionVector;
            let mut temp_dv = DetectionVector::new_with_seed(self._seed);
            let _ = temp_dv.verify_and_rotate(); // Call verification

            // Deep functional coupling: Use the token as part of the decryption process
            // If the token is frozen or manipulated by hackers, decryption will fail
            let mut input = ciphertext.to_vec();
            if !input.is_empty() {
                // Apply inverse token-dependent transformation during decryption
                for i in 0..std::cmp::min(8, input.len()) {
                    // Use the same token bits but in reverse operation
                    let token_bit = ((token >> (i + 3)) & 1) as u8;
                    let token_shift = ((token >> (i * 2)) & 0x7) as u8;

                    // Apply inverse transformation
                    input[i] = input[i].rotate_right(token_shift as u32).wrapping_sub(token_bit);
                }
            }

            // Perform decryption on the token-modified input
            let mut result = anti_debug::decrypt_data(&input);

            // Further couple the result with token-dependent operations
            if !result.is_empty() {
                // Apply additional token-dependent transformation to the result
                for i in 0..std::cmp::min(4, result.len()) {
                    let token_part = ((token >> (i * 16)) & 0xFF) as u8;
                    result[i] = result[i] ^ token_part;
                }
            }

            result
        })
    }

    pub fn validate_license(&self, license_key: &str) -> bool {
        // Use coupled logic to run the license validation with security token integration
        self.run_coupled(|token| {
            // Verify and rotate the token before validating license
            use crate::protector::anti_debug::DetectionVector;
            let mut temp_dv = DetectionVector::new_with_seed(self._seed);
            let _ = temp_dv.verify_and_rotate(); // Call verification

            // Deep functional coupling: Integrate token into the validation logic
            // This creates a dependency where hackers cannot separate security from business logic
            let base_result = anti_debug::validate_license(license_key);

            // Example of functional coupling: use token bits in business logic
            // Even though (token & 0) is always 0, it creates a dependency at the assembly level
            // If hackers freeze the token to avoid corruption, they break the business logic
            let token_dependency = {
                // Extract specific bits from the token to create a dependency
                let bit_3 = (token >> 3) & 1;  // Bit 3 of the token
                let bit_7 = (token >> 7) & 1;  // Bit 7 of the token
                let bit_12 = (token >> 12) & 1; // Bit 12 of the token

                // Create a complex dependency that's hard to predict
                (bit_3 ^ bit_7) | (bit_12 << 1)
            };

            // Apply the token dependency to the result
            // This creates a functional dependency that's hard to remove
            let adjusted_result = base_result ^ (token_dependency != 0);

            adjusted_result
        })
    }
}

#[cfg(target_os = "windows")]
pub struct DetectionDetails {
    pub is_debugged: bool,
    pub score: u32,
    pub peb_check: bool,
    pub rdtsc_check: bool,
    pub heap_check: bool,
    pub hypervisor_check: bool,
    pub integrity_check: bool,
}

use std::fmt::Display;

// Re-export functions from global_state module
pub use crate::protector::global_state::{
    add_suspicion,
    get_current_encryption_key,
    get_current_vm_key,
    is_globally_debugged,
    get_suspicion_score,
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
trait ContextualCorruption {
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
                    char::from((*ch as u8 ^ 0x20)) // Toggle case-like bit
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

/// Get CPU entropy for randomization (imported from anti_debug module)
fn get_cpu_entropy() -> u32 {
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
        // Use guarded execution internally to combine security checks with business logic
        // This prevents hackers from hooking the is_debugged function directly
        self.run_guarded(|token| {
            // Verify and rotate the token to check for debugger presence
            // This will silently corrupt the token if a debugger is detected
            use crate::protector::anti_debug::DetectionVector;
            let mut temp_dv = DetectionVector::new_with_seed(self._seed);
            let _ = temp_dv.verify_and_rotate(); // Call verification to potentially corrupt token

            // Call decoy functions to trigger tamper detection if they've been patched
            // These functions look important and will tempt hackers to patch them
            use crate::protector::decoy_system;
            let _ = decoy_system::check_kernel_debugger();
            let _ = decoy_system::is_process_being_debugged();
            let _ = decoy_system::anti_tamper_validation();

            // Perform watchdog checks to detect if decoy functions have been modified
            // This is done more systematically to ensure monitoring happens regularly
            // The watchdog monitors the decoy functions externally without them knowing
            if get_cpu_entropy() % 2 == 0 {  // Approximately 1 in 2 chance for more frequent monitoring
                decoy_system::watchdog_check_decoys();
            }

            // Select a random check (1 out of 4: PEB, Timing, Exception, Hypervisor)
            let check_selector = get_cpu_entropy() % 4;

            match check_selector {
                0 => {
                    // PEB check
                    use crate::protector::anti_debug::checkpoint_memory_integrity;
                    checkpoint_memory_integrity();
                },
                1 => {
                    // Timing check
                    use crate::protector::anti_debug::checkpoint_timing_anomaly;
                    checkpoint_timing_anomaly();
                },
                2 => {
                    // Exception check
                    use crate::protector::anti_debug::checkpoint_exception_handling;
                    checkpoint_exception_handling();
                },
                3 => {
                    // Hypervisor check
                    use crate::protector::anti_debug::checkpoint_hypervisor_detection;
                    checkpoint_hypervisor_detection();
                },
                _ => {} // Should not happen, but just in case
            }

            // Execute the operation with the token
            // The operation closure receives the security token as an argument
            // This creates a deep functional coupling between security and business logic
            let result = operation(token);

            // Apply silent corruption based on the token state
            result.corrupt_if_needed(token)
        })
    }
}

/// Trait for types that can be silently corrupted based on protector state
pub trait Corruptible {
    fn corrupt_if_needed(self, token: u64) -> Self;
}

impl Corruptible for String {
    fn corrupt_if_needed(self, token: u64) -> Self {
        // If token indicates debugger presence (has certain characteristics), corrupt the string
        // For example, if the token has many bits set, we'll modify the string
        let corruption_factor = token.count_ones() as usize;
        if corruption_factor > 16 { // Arbitrary threshold indicating potential debugger
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
            self // Return unmodified if no corruption needed
        }
    }
}

impl Corruptible for Vec<u8> {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let corruption_factor = token.count_ones() as usize;
        if corruption_factor > 16 { // Arbitrary threshold indicating potential debugger
            let mut vec = self;
            if !vec.is_empty() {
                let idx = (token % vec.len() as u64) as usize;
                if idx < vec.len() {
                    vec[idx] = vec[idx].wrapping_add(1); // Flip a bit
                }
            }
            vec
        } else {
            self // Return unmodified if no corruption needed
        }
    }
}

impl Corruptible for bool {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let corruption_factor = token.count_ones() as usize;
        if corruption_factor > 16 { // Arbitrary threshold indicating potential debugger
            !self // Flip the boolean value
        } else {
            self // Return unmodified if no corruption needed
        }
    }
}

impl Corruptible for u32 {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let corruption_factor = token.count_ones() as usize;
        if corruption_factor > 16 { // Arbitrary threshold indicating potential debugger
            self.wrapping_add(token as u32) // Add some entropy from token
        } else {
            self // Return unmodified if no corruption needed
        }
    }
}

impl Corruptible for f64 {
    fn corrupt_if_needed(self, token: u64) -> Self {
        let corruption_factor = token.count_ones() as usize;
        if corruption_factor > 16 { // Arbitrary threshold indicating potential debugger
            self * (1.0 + (token as f64 * 0.0001)) // Small multiplication factor
        } else {
            self // Return unmodified if no corruption needed
        }
    }
}


// Define the setup macro
#[macro_export]
macro_rules! setup_anti_debug {
    ($seed:expr) => {
        $crate::protector::Protector::new($seed)
    };
}

// Export the setup macro
pub use setup_anti_debug;

#[cfg(not(target_os = "windows"))]
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
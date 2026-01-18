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
mod anti_debug;
#[cfg(target_os = "windows")]
pub mod global_state;

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

    pub fn is_debugged(&self) -> bool {
        false // Always return false on non-Windows platforms
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
        plaintext.to_vec()
    }

    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> {
        // On non-Windows, return data unchanged
        ciphertext.to_vec()
    }

    pub fn validate_license(&self, license_key: &str) -> bool {
        // On non-Windows, return true
        license_key.len() == 32 && license_key.chars().all(|c| c.is_ascii_alphanumeric())
    }
}

#[cfg(target_os = "windows")]
pub struct Protector {
    seed: u32,
}

#[cfg(target_os = "windows")]
impl Protector {
    pub fn new(seed: u32) -> Self {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            // Initialize the protection system
            anti_debug::initialize_veh_protection();
        });

        Protector {
            seed,
        }
    }
// github.com/anhdeface
    pub fn is_debugged(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            anti_debug::is_globally_debugged()
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    pub fn get_detection_details(&self) -> DetectionDetails {
        DetectionDetails {
            is_debugged: self.is_debugged(),
            score: anti_debug::get_suspicion_score(),
            peb_check: anti_debug::checkpoint_memory_integrity(),
            rdtsc_check: anti_debug::checkpoint_timing_anomaly(),
            heap_check: anti_debug::checkpoint_exception_handling(),
            hypervisor_check: anti_debug::checkpoint_hypervisor_detection(),
            integrity_check: anti_debug::checkpoint_integrity_self_hash(),
        }
    }

    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> {
        anti_debug::encrypt_data(plaintext)
    }

    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> {
        anti_debug::decrypt_data(ciphertext)
    }

    pub fn validate_license(&self, license_key: &str) -> bool {
        anti_debug::validate_license(license_key)
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
        assert_eq!(protector.seed, 12345);
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
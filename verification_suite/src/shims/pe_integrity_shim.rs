//! PE Integrity Shim
//!
//! Provides zero-modification access to the private module
//! `src/protector/pe_integrity.rs` in `fuckDebug`.
//!
//! Internal references to `crate::protector::global_state::POISON_SEED` and
//! `crate::protector::global_state::LAST_VM_HEARTBEAT` resolve via `pub use fuckDebug::protector;`
//! declared in `verification_suite/src/lib.rs`.

#[path = "../../../src/protector/pe_integrity.rs"]
pub mod pe_integrity;

pub use pe_integrity::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_pe_integrity_callable() {
        let token = heartbeat_check(0);
        assert_ne!(token, 0, "PE integrity heartbeat via shim must be non-zero");
    }
}

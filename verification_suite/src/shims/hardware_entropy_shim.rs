//! Hardware Entropy Shim
//!
//! Provides zero-modification access to the private module
//! `src/protector/hardware_entropy.rs` in `fuckDebug`.

#[path = "../../../src/protector/hardware_entropy.rs"]
pub mod hardware_entropy;

pub use hardware_entropy::*;

/// Reference implementation of FNV-1a hash matching hardware_entropy.rs
/// for black-box property and differential testing.
#[inline(always)]
pub fn fnv1a_hash_ref(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
    const FNV_PRIME: u32 = 0x01000193;
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim_hardware_entropy_callable() {
        let entropy = get_hardware_entropy();
        assert_ne!(entropy, 0, "Hardware entropy via shim must be non-zero");
    }

    #[test]
    fn test_shim_fnv1a_reference_matches() {
        assert_eq!(fnv1a_hash_ref(b"test"), 2949673445);
    }
}

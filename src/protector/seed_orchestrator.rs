#![allow(dead_code)]

//! Seed Orchestrator - Runtime Seed Reconstruction
//! 
//! This module combines multiple entropy sources to reconstruct the DYNAMIC_SEED
//! at runtime, making static analysis and memory patching ineffective.
//! 
//! **Entropy Sources**:
//! 1. **Build-Time Seed**: Original const value generated at compile time
//! 2. **Hardware Entropy**: CPU-specific fingerprint from CPUID
//! 3. **PE Integrity Hash**: Code section checksum for anti-tampering
//! 
//! **Shard Recomposition**:
//! ```
//! FINAL_SEED = Avalanche(BUILD_SEED ^ HW_ENTROPY ^ PE_HASH)
//! ```
//! 
//! **Caching Strategy**:
//! - Uses `OnceLock` for thread-safe lazy initialization
//! - Computed only once on first access
//! - Subsequent calls return cached value (~1-10ns overhead)

use std::sync::OnceLock;

// Import the two entropy modules (Windows only)
#[cfg(target_os = "windows")]
use crate::protector::hardware_entropy;
#[cfg(target_os = "windows")]
use crate::protector::pe_integrity;

/// Cache for the reconstructed seed
/// 
/// **Thread Safety**: OnceLock provides thread-safe initialization
/// - First thread to call get_or_init() computes the seed
/// - Other threads wait and receive the computed value
/// - After initialization, all threads read without synchronization overhead
static RECONSTRUCTED_SEED: OnceLock<u32> = OnceLock::new();

/// Seed Orchestrator - Combines multiple entropy sources
/// 
/// **Design Pattern**: Zero-sized type (ZST) with static methods
/// No runtime overhead, just a namespace for organization
pub struct SeedOrchestrator;

impl SeedOrchestrator {
    /// Reconstruct the dynamic seed from multiple entropy shards
    /// 
    /// **Process**:
    /// 1. Check cache (OnceLock) - if present, return immediately
    /// 2. Otherwise, compute seed by XORing all entropy sources
    /// 3. Apply avalanche mixing for bit distribution
    /// 4. Cache result for future calls
    /// 
    /// **Performance**:
    /// - First call: ~50-100 microseconds (CPUID + PE parsing)
    /// - Cached calls: ~1-10 nanoseconds (atomic read)
    /// 
    /// **Inlining Strategy**:
    /// - #[inline(always)] ensures this wrapper is inlined
    /// - Actual computation is #[inline(never)] to prevent optimization
    /// 
    /// **Return**: 32-bit reconstructed seed
    #[inline(always)]
    pub fn reconstruct() -> u32 {
        *RECONSTRUCTED_SEED.get_or_init(|| Self::compute_seed())
    }
    
    /// Compute the seed by combining all entropy shards
    /// 
    /// **Shard Composition**:
    /// ```
    /// Shard 1: BUILD_TIME_SEED  (compile-time constant)
    /// Shard 2: HW_ENTROPY       (CPUID-based fingerprint)
    /// Shard 3: PE_INTEGRITY     (.text section checksum)
    /// 
    /// COMBINED = Shard1 ^ Shard2 ^ Shard3
    /// FINAL = avalanche_mix(COMBINED)
    /// ```
    /// 
    /// **XOR Properties**:
    /// - Reversible: A ^ B ^ B = A
    /// - Commutative: A ^ B = B ^ A
    /// - Any shard modification completely changes the result
    /// 
    /// **Avalanche Mixing**:
    /// - Ensures bit changes propagate throughout the entire value
    /// - Even single bit flip → ~50% of output bits flip
    /// 
    /// **Inlining**: #[inline(never)] prevents optimization to hide logic
    #[inline(never)]
    fn compute_seed() -> u32 {
        // ====================================================================
        // SHARD 1: Build-Time Seed (Original Constant)
        // ====================================================================
        // This is the original 32-bit value generated at build time
        const BUILD_TIME_SEED: u32 = include!(concat!(env!("OUT_DIR"), "/dynamic_seed.rs"));
        
        #[cfg(target_os = "windows")]
        {
            // ====================================================================
            // SHARD 2: Hardware Entropy (CPUID Fingerprint)
            // ====================================================================
            let hw_entropy = hardware_entropy::get_hardware_entropy();
            
            // ====================================================================
            // SHARD 3: PE Integrity Hash (.text Section Checksum)
            // ====================================================================
            let integrity_hash = pe_integrity::get_text_section_hash();
            
            // Shard Recomposition: XOR All Entropy Sources
            let combined = BUILD_TIME_SEED ^ hw_entropy ^ integrity_hash;
            
            // Avalanche Mixing: Distribute Bit Changes
            Self::avalanche_mix(combined)
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Simplified construction for non-Windows platforms
            // Still uses build-time seed but adds dummy entropy
            let dummy_entropy = 0xA5A5A5A5u32;
            Self::avalanche_mix(BUILD_TIME_SEED ^ dummy_entropy)
        }
    }
    
    /// Avalanche mixing function for bit distribution
    /// 
    /// **Purpose**: Ensure that changes to any input bit affect all output bits
    /// 
    /// **Algorithm** (MurmurHash3 finalizer):
    /// ```
    /// x ^= x >> 16
    /// x *= 0x85ebca6b
    /// x ^= x >> 13
    /// x *= 0xc2b2ae35
    /// x ^= x >> 16
    /// ```
    /// 
    /// **Properties**:
    /// - Single bit flip in input → ~50% of output bits flip (avalanche)
    /// - Non-linear mixing prevents simple algebraic attacks
    /// - Fast computation (~5-10 CPU cycles)
    /// 
    /// **Magic Constants**:
    /// - 0x85ebca6b and 0xc2b2ae35 are carefully chosen primes
    /// - These values maximize avalanche effect and minimize collisions
    /// 
    /// **Time Complexity**: O(1) - Fixed number of operations
    #[inline(always)]
    fn avalanche_mix(mut x: u32) -> u32 {
        // First layer: XOR with right-shifted self
        x ^= x >> 16;
        
        // Multiply by magic constant (prime number)
        x = x.wrapping_mul(0x85ebca6b);
        
        // Second layer: XOR with right-shifted self
        x ^= x >> 13;
        
        // Multiply by another magic constant
        x = x.wrapping_mul(0xc2b2ae35);
        
        // Final layer: XOR with right-shifted self
        x ^= x >> 16;
        
        x
    }
}

/// Public API to get the reconstructed seed
/// 
/// **Usage**: This function replaces all uses of the old `DYNAMIC_SEED` constant
/// 
/// **Example**:
/// ```rust
/// // Old code:
/// let key = DYNAMIC_SEED ^ some_value;
/// 
/// // New code:
/// let key = get_dynamic_seed() ^ some_value;
/// ```
/// 
/// **Performance**: After first call, this is essentially a cached read
#[inline(always)]
pub fn get_dynamic_seed() -> u32 {
    SeedOrchestrator::reconstruct()
}

/// Convert u32 seed to u8 for backward compatibility
/// 
/// **Usage**: Some parts of the codebase expect a u8 seed
/// We take the XOR of all 4 bytes to compress to u8
/// 
/// **Compression**:
/// ```
/// byte0 ^ byte1 ^ byte2 ^ byte3
/// ```
#[inline(always)]
pub fn get_dynamic_seed_u8() -> u8 {
    let seed = get_dynamic_seed();
    
    // XOR all 4 bytes together
    let byte0 = (seed & 0xFF) as u8;
    let byte1 = ((seed >> 8) & 0xFF) as u8;
    let byte2 = ((seed >> 16) & 0xFF) as u8;
    let byte3 = ((seed >> 24) & 0xFF) as u8;
    
    byte0 ^ byte1 ^ byte2 ^ byte3
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_seed_reconstruction_caching() {
        // Seed should be cached and stable across multiple calls
        let seed1 = SeedOrchestrator::reconstruct();
        let seed2 = SeedOrchestrator::reconstruct();
        assert_eq!(seed1, seed2, "Seed should be cached and deterministic");
    }
    
    #[test]
    fn test_seed_non_zero() {
        // Seed should not be zero (would indicate complete failure)
        let seed = get_dynamic_seed();
        assert_ne!(seed, 0, "Reconstructed seed should not be zero");
    }
    
    #[test]
    fn test_seed_u8_conversion() {
        // u8 version should be derived from u32 version
        let seed_u32 = get_dynamic_seed();
        let seed_u8 = get_dynamic_seed_u8();
        
        // Manually compute what u8 should be
        let expected = ((seed_u32 & 0xFF) ^ ((seed_u32 >> 8) & 0xFF) ^ 
                       ((seed_u32 >> 16) & 0xFF) ^ ((seed_u32 >> 24) & 0xFF)) as u8;
        
        assert_eq!(seed_u8, expected, "u8 seed should be XOR of all bytes");
    }
    
    #[test]
    fn test_avalanche_effect() {
        // Test that avalanche mixing creates significant bit changes
        let input1 = 0x12345678u32;
        let input2 = 0x12345679u32; // Single bit different
        
        let output1 = SeedOrchestrator::avalanche_mix(input1);
        let output2 = SeedOrchestrator::avalanche_mix(input2);
        
        // Count different bits
        let diff = output1 ^ output2;
        let bit_changes = diff.count_ones();
        
        // Avalanche effect should flip approximately 50% of bits (16 out of 32)
        // We check for at least 8 bits changed (25% threshold)
        assert!(bit_changes >= 8, 
            "Avalanche effect should change at least 25% of bits, got {} bits changed", 
            bit_changes);
    }
}

#![allow(dead_code)]

//! Hardware Entanglement Module - Runtime Hardware ID Generation
//! 
//! This module extracts hardware-specific entropy using CPUID instruction to create
//! a unique fingerprint that binds the application to specific hardware.
//! 
//! **Security Features**:
//! - No external crates dependency (pure std + inline asm)
//! - FNV-1a hash for hardware data mixing
//! - Fallback mechanisms for edge cases
//! - Anti-tampering detection (all-zero checks)

use std::arch::asm;

/// FNV-1a Hash Constants (32-bit version)
/// FNV (Fowler-Noll-Vo) is a fast non-cryptographic hash function
/// Used here for hardware entropy mixing without external dependencies
const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
const FNV_PRIME: u32 = 0x01000193;

/// FNV-1a hash implementation for arbitrary byte slices
/// 
/// **Algorithm**:
/// ```text
/// hash = FNV_offset_basis
/// for each byte in data:
///     hash = hash XOR byte
///     hash = hash * FNV_prime
/// ```
/// 
/// **Time Complexity**: O(n) where n is data length
/// **Space Complexity**: O(1)
#[inline(always)]
fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Execute CPUID instruction with proper register preservation
/// 
/// **CPUID Basics**:
/// - Input: EAX = leaf (function number), ECX = subleaf (for some functions)
/// - Output: EAX, EBX, ECX, EDX contain requested information
/// 
/// **Register Preservation**:
/// - RBX must be preserved in x86_64 ABI (it's a callee-saved register)
/// - We push/pop RBX around the CPUID instruction
/// 
/// **Safety**: This function is marked unsafe because it uses inline assembly
/// and directly manipulates CPU state.
#[inline(always)]
unsafe fn cpuid_helper(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    
    asm!(
        "push rbx",          // Save RBX (callee-saved register)
        "cpuid",             // Execute CPUID instruction
        "mov {0:e}, ebx",    // Move EBX result to output (before restoring)
        "pop rbx",           // Restore RBX
        out(reg) ebx,        // Output for EBX
        inout("eax") leaf => eax,  // Input leaf, output EAX
        out("ecx") ecx,      // Output ECX
        out("edx") edx,      // Output EDX
        options(nomem, nostack)  // No memory access, no stack manipulation
    );
    
    (eax, ebx, ecx, edx)
}

/// Fallback entropy source when CPUID is not available or returns invalid data
/// 
/// Uses RDTSC (Read Time-Stamp Counter) XORed with stack pointer for entropy.
/// This ensures we always have some entropy even on very old CPUs or in edge cases.
/// 
/// **Instruction**: RDTSC returns a 64-bit counter in EDX:EAX
/// **Anti-Tampering**: XOR with stack address to prevent simple manipulation
#[inline(always)]
fn fallback_entropy() -> u32 {
    let low: u32;
    let high: u32;
    
    unsafe {
        asm!(
            "rdtsc",             // Read Time-Stamp Counter
            out("eax") low,      // Low 32 bits
            out("edx") high,     // High 32 bits
            options(nomem, nostack)
        );
    }
    
    // XOR the two halves for mixing
    let rdtsc_entropy = low ^ high;
    
    // Mix with stack pointer for additional entropy
    let stack_var = 0u8;
    let stack_ptr = &stack_var as *const u8 as u32;
    
    rdtsc_entropy ^ stack_ptr
}

/// Extract hardware entropy from CPU using CPUID instruction
/// 
/// **Data Sources**:
/// 1. **CPUID Leaf 0x00000000**: Vendor ID String (12 bytes)
///    - Returns: "GenuineIntel", "AuthenticAMD", "VIA VIA VIA", etc.
///    - Stored in EBX, EDX, ECX registers
/// 
/// 2. **CPUID Leaf 0x00000001**: Processor Info and Feature Bits
///    - EAX bits 0-3: Stepping ID
///    - EAX bits 4-7: Model
///    - EAX bits 8-11: Family
///    - EAX bits 12-13: Processor Type
///    - EAX bits 16-19: Extended Model ID
///    - EAX bits 20-27: Extended Family ID
/// 
/// 3. **CPUID Leaf 0x80000002-0x80000004**: Processor Brand String (48 bytes)
///    - Returns: "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz" or similar
///    - Spread across 3 leaves, each returning 16 bytes (4 registers × 4 bytes)
/// 
/// **Anti-Tampering**:
/// - Checks for all-zero buffer (VM/debugger zeroing attack)
/// - Falls back to RDTSC+stack mixing if CPUID returns invalid data
/// 
/// **Time Complexity**: O(1) - Fixed number of CPUID calls (5-6 instructions)
/// **Estimated Cycles**: ~2000-3000 (CPUID is expensive, ~200-500 cycles each)
/// 
/// **Return**: 32-bit hardware fingerprint unique to this CPU
#[inline(always)]
pub fn get_hardware_entropy() -> u32 {
    // Buffer to accumulate hardware-specific bytes
    // Layout: [Vendor ID: 12 bytes][Processor Info: 4 bytes][Brand String: 48 bytes]
    // Total: 64 bytes maximum
    let mut entropy_buffer = [0u8; 64];
    let mut offset;
    
    unsafe {
        // ========================================================================
        // STEP 1: Get Maximum Basic CPUID Leaf and Vendor ID (Leaf 0x00000000)
        // ========================================================================
        let (max_leaf, ebx, ecx, edx) = cpuid_helper(0);
        
        // If max_leaf is 0, CPUID is not fully supported
        // This is extremely rare on modern x86_64 systems
        if max_leaf == 0 {
            return fallback_entropy();
        }
        
        // Pack Vendor ID string into buffer
        // Vendor string format: EBX=first 4 chars, EDX=middle 4, ECX=last 4
        // Example: "Genu" "ineI" "ntel" = "GenuineIntel"
        entropy_buffer[0..4].copy_from_slice(&ebx.to_le_bytes());
        entropy_buffer[4..8].copy_from_slice(&edx.to_le_bytes());
        entropy_buffer[8..12].copy_from_slice(&ecx.to_le_bytes());
        offset = 12;
        
        // ========================================================================
        // STEP 2: Get Processor Info and Feature Bits (Leaf 0x00000001)
        // ========================================================================
        if max_leaf >= 1 {
            let (eax, _ebx, _ecx, _edx) = cpuid_helper(1);
            
            // EAX contains:
            // - Stepping ID, Model, Family, Processor Type
            // - Extended Model ID, Extended Family ID
            // This uniquely identifies the CPU microarchitecture
            entropy_buffer[offset..offset+4].copy_from_slice(&eax.to_le_bytes());
            offset += 4;
        }
        
        // ========================================================================
        // STEP 3: Get Processor Brand String (Leaf 0x80000002-0x80000004)
        // ========================================================================
        // First check if extended CPUID functions are available
        let (max_ext_leaf, _, _, _) = cpuid_helper(0x80000000);
        
        // Extended CPUID functions start at 0x80000000
        // Brand string is available if max_ext_leaf >= 0x80000004
        if max_ext_leaf >= 0x80000004 {
            // Brand string is spread across 3 CPUID leaves
            // Each leaf returns 16 bytes (4 registers × 4 bytes)
            for leaf in 0x80000002..=0x80000004 {
                let (eax, ebx, ecx, edx) = cpuid_helper(leaf);
                
                // Pack all 4 registers into buffer (16 bytes total per leaf)
                entropy_buffer[offset..offset+4].copy_from_slice(&eax.to_le_bytes());
                offset += 4;
                entropy_buffer[offset..offset+4].copy_from_slice(&ebx.to_le_bytes());
                offset += 4;
                entropy_buffer[offset..offset+4].copy_from_slice(&ecx.to_le_bytes());
                offset += 4;
                entropy_buffer[offset..offset+4].copy_from_slice(&edx.to_le_bytes());
                offset += 4;
            }
        }
    }
    
    // ========================================================================
    // ANTI-TAMPERING: Detect if buffer was zeroed by VM/debugger
    // ========================================================================
    let is_zeroed = entropy_buffer[..offset].iter().all(|&b| b == 0);
    
    if is_zeroed {
        // Attacker may have zeroed CPUID output or we're in a heavily sandboxed VM
        // Mix with stack address as anti-tampering countermeasure
        let stack_var = 0u8;
        let stack_ptr = &stack_var as *const u8 as usize;
        
        return fnv1a_hash(&entropy_buffer[..offset]) ^ (stack_ptr as u32);
    }
    
    // ========================================================================
    // FINAL STEP: Hash all collected hardware data with FNV-1a
    // ========================================================================
    fnv1a_hash(&entropy_buffer[..offset])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hardware_entropy_deterministic() {
        // Hardware entropy should be stable across multiple calls
        let entropy1 = get_hardware_entropy();
        let entropy2 = get_hardware_entropy();
        assert_eq!(entropy1, entropy2, "Hardware entropy should be deterministic on same hardware");
    }
    
    #[test]
    fn test_hardware_entropy_non_zero() {
        // Entropy should not be zero (would indicate total failure)
        let entropy = get_hardware_entropy();
        assert_ne!(entropy, 0, "Hardware entropy should not be zero");
    }
    
    #[test]
    fn test_fnv1a_hash_basic() {
        // Test FNV-1a hash with known values
        let data1 = b"test";
        let data2 = b"test";
        let data3 = b"test2";
        
        assert_eq!(fnv1a_hash(data1), fnv1a_hash(data2), "Same input should produce same hash");
        assert_ne!(fnv1a_hash(data1), fnv1a_hash(data3), "Different input should produce different hash");
    }
    
    #[test]
    fn test_fallback_entropy_non_zero() {
        // Fallback entropy should also be non-zero
        let entropy = fallback_entropy();
        assert_ne!(entropy, 0, "Fallback entropy should not be zero");
    }
}

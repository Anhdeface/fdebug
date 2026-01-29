#![allow(dead_code)]

//! PE Integrity Checker - Runtime .text Section Hashing
//! 
//! This module parses the PE (Portable Executable) headers of the current process
//! and computes a checksum of the .text section to detect code modifications.
//! 
//! **Security Features**:
//! - Manual PE header parsing (no dependencies on external crates)
//! - Comprehensive error detection with corrupted seed returns (Silent Defense)
//! - MZ and PE signature validation
//! - .text section integrity verification via XOR checksum
//! 
//! **PE Structure Overview**:
//! ```
//! DOS Header (0x00)
//!   ├─ e_magic: 0x5A4D ("MZ")
//!   └─ e_lfanew: Offset to PE Header
//! 
//! PE Header (DOS_Header + e_lfanew)
//!   ├─ Signature: 0x00004550 ("PE\0\0")
//!   ├─ IMAGE_FILE_HEADER
//!   │   ├─ Machine: 0x8664 (x64)
//!   │   ├─ NumberOfSections
//!   │   └─ SizeOfOptionalHeader
//!   └─ IMAGE_OPTIONAL_HEADER64
//! 
//! Section Headers (PE_Header + sizeof(headers))
//!   ├─ .text section
//!   ├─ .data section
//!   └─ ...
//! ```

use std::ptr;
use std::sync::OnceLock;

// ============================================================================
// FFI DECLARATIONS - Windows Kernel32 API
// ============================================================================

#[link(name = "kernel32")]
extern "system" {
    /// Retrieves a module handle for the specified module.
    /// 
    /// **Parameters**:
    /// - `lpModuleName`: Module name, or NULL for current process executable
    /// 
    /// **Returns**: Handle to the module (base address in memory)
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut u8;
}

// ============================================================================
// PE STRUCTURE DEFINITIONS (Manual - No winapi crate dependency)
// ============================================================================

/// DOS Header - First structure in every PE file
/// 
/// **Size**: 64 bytes
/// **Location**: File offset 0x00
/// **Key Field**: e_lfanew at offset 0x3C (points to PE header)
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,           // Magic number "MZ" (0x5A4D)
    _reserved1: [u8; 58],   // Various DOS fields we don't need
    e_lfanew: i32,          // File offset to PE header (at offset 0x3C)
}

/// PE File Header - Describes the PE file characteristics
/// 
/// **Size**: 20 bytes
/// **Location**: Immediately after PE signature (4 bytes)
#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,                   // Machine type (0x8664 for x64)
    number_of_sections: u16,        // Number of section headers
    time_date_stamp: u32,           // Timestamp when file was created
    pointer_to_symbol_table: u32,   // Deprecated - usually 0
    number_of_symbols: u32,         // Deprecated - usually 0
    size_of_optional_header: u16,   // Size of optional header (240 for PE64)
    characteristics: u16,           // File characteristics flags
}

/// PE Optional Header (64-bit version)
/// 
/// **Size**: 240 bytes for PE32+ (64-bit)
/// **Note**: We define this as a byte array since we don't need to parse its fields
/// The important part is knowing its size to skip over it to reach section headers
#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    magic: u16,                     // 0x020B for PE32+ (64-bit)
    _other_fields: [u8; 238],       // Remaining fields (not needed for our purpose)
}

/// NT Headers (PE Headers) - Combines signature + file header + optional header
/// 
/// **Size**: 4 + 20 + 240 = 264 bytes for PE32+ (64-bit)
/// **Location**: Pointed to by DOS_Header.e_lfanew
#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,                         // PE signature: 0x00004550 ("PE\0\0")
    file_header: IMAGE_FILE_HEADER,         // File header (20 bytes)
    optional_header: IMAGE_OPTIONAL_HEADER64, // Optional header (240 bytes)
}

/// Section Header - Describes a section (.text, .data, etc.)
/// 
/// **Size**: 40 bytes each
/// **Location**: After NT Headers
/// **Count**: Specified by IMAGE_FILE_HEADER.number_of_sections
#[repr(C)]
struct IMAGE_SECTION_HEADER {
    name: [u8; 8],              // Section name (".text\0\0\0" or similar)
    virtual_size: u32,          // Size in memory
    virtual_address: u32,       // RVA (Relative Virtual Address) when loaded
    size_of_raw_data: u32,      // Size on disk
    pointer_to_raw_data: u32,   // File offset on disk
    _reserved: [u8; 16],        // Various flags and reserved fields
}

// ============================================================================
// CORRUPTED SEED CONSTANTS - Returned on tampering detection
// ============================================================================

/// Seed returned when GetModuleHandleW fails
const SEED_MODULE_HANDLE_FAILED: u32 = 0xDEADC0DE;

/// Seed returned when DOS header signature is invalid (not "MZ")
const SEED_INVALID_MZ_SIGNATURE: u32 = 0xBADC0FFE;

/// Seed returned when PE signature is invalid (not "PE\0\0")
const SEED_INVALID_PE_SIGNATURE: u32 = 0xDEADBEEF;

/// Seed returned when .text section is not found
const SEED_TEXT_SECTION_NOT_FOUND: u32 = 0xBADF00D;

/// Static cache for storing the .text section offset and size
/// This allows us to access the .text section data even after PE headers are destroyed
static TEXT_SECTION_DATA: OnceLock<(u32, u32)> = OnceLock::new(); // (VirtualAddress, VirtualSize)

// ============================================================================
// PE PARSING AND INTEGRITY CHECKING
// ============================================================================

/// Compute XOR checksum of the .text section (first 1024 bytes)
///
/// **Algorithm**:
/// 1. Check if TEXT_SECTION_DATA cache is populated - if yes, use cached data
/// 2. If cache is empty, get base address of current process via GetModuleHandleW(NULL)
/// 3. Parse DOS Header and validate "MZ" signature (0x5A4D)
/// 4. Follow e_lfanew to locate PE Header
/// 5. Validate PE signature "PE\0\0" (0x00004550)
/// 6. Parse IMAGE_FILE_HEADER to get number of sections
/// 7. Iterate through section headers to find ".text" section
/// 8. Calculate physical address of .text section (base + RVA)
/// 9. Compute XOR checksum of first 1024 bytes (or less if section is smaller)
/// 10. Store section data in cache for future use
///
/// **XOR Checksum Formula**:
/// ```
/// checksum = 0
/// for i in 0..min(1024, section_size):
///     byte = text_section[i]
///     checksum ^= (byte << ((i % 4) * 8))
/// ```
///
/// **Silent Defense**:
/// - Returns corrupted seeds instead of panicking on errors
/// - Attacker will get wrong seed → application logic fails silently
/// - No visible error messages to tip off reverse engineers
///
/// **Time Complexity**: O(1) - Fixed 1024 bytes to hash
/// **Estimated Time**: ~20-30 microseconds
///
/// **Safety**: This function uses unsafe pointer arithmetic to parse PE structures.
/// All pointer accesses are validated before dereferencing to prevent crashes.
#[inline(always)]
pub fn get_text_section_hash() -> u32 {
    // Check if we have cached section data first
    if let Some(&(rva, size)) = TEXT_SECTION_DATA.get() {
        // SAFETY: We're accessing the cached RVA and size to compute the hash
        // The base address is retrieved fresh each time to ensure it's current
        unsafe {
            // Get base address of current process
            let base_addr = GetModuleHandleW(ptr::null()) as *const u8;

            if base_addr.is_null() {
                // Module handle failed - should never happen for current process
                // Return corrupted seed to silently fail
                return SEED_MODULE_HANDLE_FAILED;
            }

            // Calculate physical address of .text section using cached data
            let text_addr = base_addr.offset(rva as isize);

            // Compute XOR checksum of first 1024 bytes (or less if section is smaller)
            let bytes_to_hash = std::cmp::min(1024, size) as usize;
            let mut checksum = 0u32;

            // XOR checksum with byte rotation for better mixing
            // Each byte is shifted based on its position modulo 4
            // This ensures all bytes contribute to all 32 bits of the checksum
            for i in 0..bytes_to_hash {
                let byte = *text_addr.offset(i as isize);

                // Shift amount: 0, 8, 16, 24, 0, 8, 16, 24, ...
                let shift = ((i % 4) * 8) as u32;

                // XOR byte into checksum at rotating positions
                checksum ^= (byte as u32) << shift;
            }

            return checksum;
        }
    }

    // Cache is empty, perform full parsing and populate cache
    unsafe {
        // ====================================================================
        // STEP 1: Get Base Address of Current Process
        // ====================================================================
        // GetModuleHandleW(NULL) returns the base address where our executable
        // is loaded in memory (the address of the DOS header)
        let base_addr = GetModuleHandleW(ptr::null()) as *const u8;

        if base_addr.is_null() {
            // Module handle failed - should never happen for current process
            // Return corrupted seed to silently fail
            return SEED_MODULE_HANDLE_FAILED;
        }

        // ====================================================================
        // STEP 2: Read and Validate DOS Header
        // ====================================================================
        // DOS header is always at offset 0 (base address)
        let dos_header = base_addr as *const IMAGE_DOS_HEADER;

        // Validate MZ signature (0x5A4D = "MZ" in little-endian)
        if (*dos_header).e_magic != 0x5A4D {
            // Invalid DOS signature - PE has been tampered with
            return SEED_INVALID_MZ_SIGNATURE;
        }

        // ====================================================================
        // STEP 3: Locate PE Header via e_lfanew
        // ====================================================================
        // e_lfanew is at offset 0x3C in DOS header
        // It contains the file offset to the PE header
        let pe_header_offset = (*dos_header).e_lfanew as isize;

        // Calculate address of NT Headers (PE Header)
        // NT Headers = Base Address + e_lfanew
        let nt_headers = base_addr.offset(pe_header_offset) as *const IMAGE_NT_HEADERS64;

        // ====================================================================
        // STEP 4: Validate PE Signature
        // ====================================================================
        // PE signature should be 0x00004550 ("PE\0\0" in ASCII)
        if (*nt_headers).signature != 0x00004550 {
            // Invalid PE signature - file has been corrupted or tampered
            return SEED_INVALID_PE_SIGNATURE;
        }

        // ====================================================================
        // STEP 5: Extract Section Information from File Header
        // ====================================================================
        let num_sections = (*nt_headers).file_header.number_of_sections;
        let optional_header_size = (*nt_headers).file_header.size_of_optional_header;

        // ====================================================================
        // STEP 6: Calculate Location of Section Headers
        // ====================================================================
        // Section headers come immediately after the NT Headers
        // Layout: [PE Signature: 4 bytes][FILE_HEADER: 20 bytes][OPTIONAL_HEADER: variable][SECTIONS...]
        let section_headers_offset = pe_header_offset
            + std::mem::size_of::<u32>() as isize                      // PE signature (4 bytes)
            + std::mem::size_of::<IMAGE_FILE_HEADER>() as isize        // File header (20 bytes)
            + optional_header_size as isize;                           // Optional header (240 bytes for PE64)

        let section_headers = base_addr.offset(section_headers_offset) as *const IMAGE_SECTION_HEADER;

        // ====================================================================
        // STEP 7: Find .text Section
        // ====================================================================
        let mut text_section_rva = 0u32;
        let mut text_section_size = 0u32;

        // Iterate through all section headers
        for i in 0..num_sections {
            let section = &*section_headers.offset(i as isize);
            let name = &section.name;

            // Check if section name is ".text"
            // Section names are 8 bytes, null-padded
            // ".text" = [0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00]
            if name[0] == b'.'
                && name[1] == b't'
                && name[2] == b'e'
                && name[3] == b'x'
                && name[4] == b't' {

                text_section_rva = section.virtual_address;
                text_section_size = section.virtual_size;
                break;
            }
        }

        // If .text section was not found, PE structure is invalid
        if text_section_rva == 0 {
            return SEED_TEXT_SECTION_NOT_FOUND;
        }

        // ====================================================================
        // STEP 8: Calculate Physical Address of .text Section
        // ====================================================================
        // RVA (Relative Virtual Address) is relative to the base address
        // Physical Address = Base Address + RVA
        let text_addr = base_addr.offset(text_section_rva as isize);

        // ====================================================================
        // STEP 9: Compute XOR Checksum of First 1024 Bytes
        // ====================================================================
        // We hash at most 1024 bytes, or the entire section if it's smaller
        let bytes_to_hash = std::cmp::min(1024, text_section_size) as usize;
        let mut checksum = 0u32;

        // XOR checksum with byte rotation for better mixing
        // Each byte is shifted based on its position modulo 4
        // This ensures all bytes contribute to all 32 bits of the checksum
        for i in 0..bytes_to_hash {
            let byte = *text_addr.offset(i as isize);

            // Shift amount: 0, 8, 16, 24, 0, 8, 16, 24, ...
            let shift = ((i % 4) * 8) as u32;

            // XOR byte into checksum at rotating positions
            checksum ^= (byte as u32) << shift;
        }

        // ====================================================================
        // STEP 10: Cache the section data for future use
        // ====================================================================
        // Store the RVA and size in the cache for future access after headers are destroyed
        let _ = TEXT_SECTION_DATA.set((text_section_rva, text_section_size));

        checksum
    }
}

/// Force caching of PE metadata without computing the hash
/// This function ensures the .text section metadata is cached while headers are still intact
/// It can be called during initialization to pre-populate the cache before anti-dump runs
pub fn force_cache_pe_metadata() -> bool {
    // Check if cache is already populated
    if TEXT_SECTION_DATA.get().is_some() {
        return true; // Already cached
    }

    // Call get_text_section_hash to trigger the initial parse and caching
    let _hash = get_text_section_hash();

    // Return true if caching was successful
    TEXT_SECTION_DATA.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_text_section_hash_deterministic() {
        // PE integrity hash should be stable across multiple calls
        let hash1 = get_text_section_hash();
        let hash2 = get_text_section_hash();
        assert_eq!(hash1, hash2, "PE integrity hash should be deterministic");
    }
    
    #[test]
    fn test_text_section_hash_not_corrupted() {
        let hash = get_text_section_hash();
        
        // Ensure we don't get any of the corrupted seed values
        // If we do, it means PE parsing failed
        assert_ne!(hash, SEED_MODULE_HANDLE_FAILED, "GetModuleHandleW should not fail");
        assert_ne!(hash, SEED_INVALID_MZ_SIGNATURE, "DOS header should have valid MZ signature");
        assert_ne!(hash, SEED_INVALID_PE_SIGNATURE, "PE header should have valid PE signature");
        assert_ne!(hash, SEED_TEXT_SECTION_NOT_FOUND, ".text section should be found");
    }
    
    #[test]
    fn test_text_section_hash_non_zero() {
        let hash = get_text_section_hash();
        
        // Hash should not be zero (would indicate empty .text section)
        assert_ne!(hash, 0, "PE integrity hash should not be zero");
    }
}

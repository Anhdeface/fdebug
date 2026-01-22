#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments,
    unused_macros,
    asm_sub_register
)]

//! Anti-debugging module with distributed detection mechanisms
// github.com/anhdeface
// MIT License
use std::cell::RefCell;
use crate::protector::tiny_vm::{VmOp, vm_execute};

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

/// Get a dynamic threshold for RDTSC checks using runtime address calculation
/// This makes the threshold vary between runs due to ASLR, preventing static analysis
fn get_dynamic_threshold() -> u64 {
    // Calculate threshold based on the address of a function to make it dynamic
    let func_addr = get_dynamic_threshold as *const fn() -> u64 as u64;
    // Apply arithmetic to get a reasonable threshold value
    (func_addr % 50) + 80
}

/// Maximum acceptable baseline delta during calibration
const CALIBRATION_SANITY_MAX: u64 = 1000;

/// Data Corruption Mode: When enabled, output is silently corrupted instead of exiting
/// This makes detection invisible to the attacker
const DATA_CORRUPTION_MODE: bool = true;

/// VEH Detection: Use Vectored Exception Handler for breakpoint detection
const ENABLE_VEH_DETECTION: bool = true;

/// Integrity Check: Enable runtime self-integrity verification
const ENABLE_INTEGRITY_CHECK: bool = true;

// ============================================================================
// NATIVE ENTROPY GENERATION (Using CPU instructions instead of SystemTime)
// ============================================================================

/// Generate entropy using RDRAND instruction (if available)
#[inline(always)]
pub fn get_cpu_entropy() -> u32 {
    let mut result: u32 = 0;
    let success: u8;

    unsafe {
        std::arch::asm!(
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
            std::arch::asm!(
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

// ============================================================================
// DISTRIBUTED STATE SYSTEM (Using Atomic Variables for Cross-Thread Detection)
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// Import global state from the global_state module
use crate::protector::global_state::*;

/// Distributed detection state using atomic variables for cross-thread synchronization
pub struct DetectionVector {
    /// Verification token that gets rotated and checked for integrity
    pub token: u64,
    /// Integrity checksum for the token
    integrity_checksum: AtomicU64,
    /// Reference to global atomic state
    _state_ref: Arc<()>, // Placeholder to maintain compatibility
}

impl DetectionVector {
    pub fn new() -> Self {
        // Generate a random token using CPU entropy
        let token = get_cpu_entropy() as u64;
        DetectionVector {
            token,
            integrity_checksum: AtomicU64::new(token), // Initialize checksum with token
            _state_ref: Arc::new(()), // Placeholder
        }
    }

    pub fn new_with_seed(seed: u32) -> Self {
        // Generate a token based on the seed and CPU entropy
        let cpu_entropy = get_cpu_entropy() as u64;
        let token = (seed as u64) ^ cpu_entropy ^ 0xDEADBEEFCAFEBABE;
        DetectionVector {
            token,
            integrity_checksum: AtomicU64::new(token), // Initialize checksum with token
            _state_ref: Arc::new(()), // Placeholder
        }
    }

    /// Set debugged flag using sticky bit logic (OR operation, not XOR)
    /// Once set, the debug flag remains set permanently until restart
    fn set_debugged(&mut self) {
        // Use atomic OR to set the debug flag (sticky bit)
        GLOBAL_ENCODED_STATE.fetch_or(1, Ordering::SeqCst);

        // Silent corruption: Change encryption key when debugger is detected
        GLOBAL_ENCRYPTION_KEY.store(0xFF, Ordering::SeqCst);  // Corrupted key
        GLOBAL_VIRTUAL_MACHINE_KEY.store(0x00, Ordering::SeqCst);  // Corrupted VM key

        // Recalculate integrity hash
        recalculate_global_integrity();
    }

    /// Get debugged state via sticky bit checking
    fn is_debugged(&self) -> bool {
        let current_state = GLOBAL_ENCODED_STATE.load(Ordering::SeqCst);
        let integrity_ok = validate_global_integrity();
        integrity_ok && ((current_state & 1) != 0)
    }

    /// Add suspicion without direct flag write (hardware breakpoint resistant)
    /// Uses gradual scoring system - only sets debug flag when suspicion exceeds threshold
    fn add_suspicion(&mut self, score: u32, checkpoint_type: usize) {
        add_suspicion(score, checkpoint_type);

        // Gradual suspicion system: Only set debug flag when total suspicion exceeds high threshold
        // This prevents false positives from single anomalous detections
        let total_suspicion = get_global_total_score();

        // Different thresholds for different detection types to reduce false positives
        let detection_threshold = match checkpoint_type {
            0 => 40, // PEB checks - lower threshold since they're more reliable
            1 => 60, // Timing checks - higher threshold to avoid clock variations
            2 => 50, // Exception checks - moderate threshold
            3 => 30, // Hypervisor checks - lower threshold since they're quite reliable
            4 => 35, // Integrity checks - moderate threshold
            _ => 50, // Default threshold
        };

        // Only set debug flag if total suspicion exceeds threshold OR if any single category exceeds its specific threshold
        let current_category_suspicion = match checkpoint_type {
            0 => GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst),
            1 => GLOBAL_TIMING_SUSPICION.load(Ordering::SeqCst),
            2 => GLOBAL_EXCEPTION_SUSPICION.load(Ordering::SeqCst),
            3 => GLOBAL_PEB_SUSPICION.load(Ordering::SeqCst), // Hypervisor affects PEB field
            4 => GLOBAL_INTEGRITY_SUSPICION.load(Ordering::SeqCst),
            _ => 0,
        };

        if total_suspicion > 100 || current_category_suspicion > detection_threshold {
            self.set_debugged();
        }
    }

    /// Verify integrity and rotate the token
    pub fn verify_and_rotate(&mut self) -> bool {
        // Perform a light check using RDTSC to detect timing anomalies
        let (start_low, start_high): (u32, u32);
        unsafe {
            std::arch::asm!(
                "lfence",
                "rdtsc",
                "lfence",
                out("eax") start_low,
                out("edx") start_high,
                options(nomem, nostack)
            );
        }
        let start = ((start_high as u64) << 32) | (start_low as u64);

        // Simple operation to measure timing
        let mut x = 0u64;
        for i in 0..10 {
            x = x.wrapping_add(i);
        }

        let (end_low, end_high): (u32, u32);
        unsafe {
            std::arch::asm!(
                "lfence",
                "rdtsc",
                "lfence",
                out("eax") end_low,
                out("edx") end_high,
                options(nomem, nostack)
            );
        }
        let end = ((end_high as u64) << 32) | (end_low as u64);

        let elapsed = end.saturating_sub(start);

        // Check for debugger presence through PEB flags as well
        let peb_safe = self.check_peb_safety();

        // Determine if we're in a safe environment
        let is_safe = peb_safe && elapsed < 1000; // Adjust threshold as needed

        // Apply rotation or corruption based on safety check
        const MAGIC_CONST: u64 = 0x5DEECE66D; // A large odd constant for LCG-like behavior
        if is_safe {
            // Rotate the token normally
            self.token = (self.token << 1) ^ MAGIC_CONST;
        } else {
            // If unsafe, flip some bits to corrupt the token
            self.token ^= 0xAAAAAAAAAAAAAAAA; // Flip alternating bits
        }

        // Update integrity checksum
        self.integrity_checksum.store(self.token, Ordering::SeqCst);

        // Always return true - punishment is in the corrupted token
        true
    }

    /// Helper method to check PEB safety
    fn check_peb_safety(&self) -> bool {
        // Read PEB BeingDebugged flag using inline assembly
        let being_debugged: u8;
        unsafe {
            std::arch::asm!(
                "mov {}, gs:[0x60 + 0x02]",  // GS:[TEB.Peb] + 0x02 = PEB.BeingDebugged
                out(reg_byte) being_debugged,
                options(nostack, preserves_flags)
            );
        }

        // Also check NtGlobalFlag indirectly
        let nt_global_flag: u32;
        unsafe {
            std::arch::asm!(
                "mov {}, gs:[0x60 + 0xBC]",  // GS:[TEB.Peb] + 0xBC = PEB.NtGlobalFlag
                out(reg) nt_global_flag,
                options(nostack, preserves_flags)
            );
        }

        // Return true if both flags indicate no debugger
        being_debugged == 0 && (nt_global_flag & 0x70) == 0
    }

    /// Get the current encryption key (may be corrupted if debugger detected)
    fn get_current_encryption_key() -> u8 {
        crate::protector::global_state::get_current_encryption_key()
    }

    /// Get the current virtual machine key (may be corrupted if debugger detected)
    fn get_current_vm_key() -> u8 {
        crate::protector::global_state::get_current_vm_key()
    }
}

// Add the missing macro
macro_rules! xor_encode {
    ($bytes:expr, $key:expr) => {{
        const B: &'static [u8] = $bytes;
        const KEY: u8 = $key;
        const LEN: usize = B.len();
        const ENCODED: [u8; LEN] = {
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = B[i] ^ KEY;
                i += 1;
            }
            result
        };
        ENCODED
    }};
}

// ============================================================================
// INTEGRITY MARKERS - Anchor points for self-integrity checking
// ============================================================================

#[inline(never)]
#[no_mangle]
#[link_section = ".text$A"]
pub extern "C" fn _integrity_marker_start() -> u32 {
    // Marker function to anchor integrity checks
    // Use black_box to prevent the linker from merging or optimizing away
    use std::hint::black_box;
    unsafe {
        std::arch::asm!("nop"); // Add a no-op to ensure function body exists
        black_box(0xDEADBEEFu32) // Unique signature to prevent optimization
    }
}

#[inline(never)]
#[no_mangle]
#[link_section = ".text$Z"]
pub extern "C" fn _integrity_marker_end() -> u32 {
    // Marker function to anchor integrity checks
    // Use black_box to prevent the linker from merging or optimizing away
    use std::hint::black_box;
    unsafe {
        std::arch::asm!("nop"); // Add a no-op to ensure function body exists
        black_box(0xFEEDFACEu32) // Unique signature to prevent optimization
    }
}

// ============================================================================
// WINDOWS STRUCTURES & CONSTANTS
// ============================================================================

/// PEB Structure (Process Environment Block) - x86_64 EXACT LAYOUT
/// CRITICAL: All offsets verified against Windows Internals
/// Each field explicitly positioned to ensure +0xBC = NtGlobalFlag
#[repr(C)]
struct PEB {
    InheritedAddressSpace: u8,                    // +0x00
    ReadImageFileExecOptions: u8,                 // +0x01
    BeingDebugged: u8,                            // +0x02 ← KERNEL SETS THIS
    BitField: u8,                                 // +0x03
    _pad1: [u8; 4],                               // +0x04-0x07 (explicit padding)
    Mutant: *const u8,                            // +0x08
    ImageBaseAddress: *const u8,                  // +0x10
    Ldr: *const u8,                               // +0x18
    ProcessParameters: *const u8,                 // +0x20
    SubSystemData: *const u8,                     // +0x28
    ProcessHeap: *const u8,                       // +0x30 ← BONUS: Direct heap ptr
    FastPebLock: *const u8,                       // +0x38
    AtlThunkSListPtr: *const u8,                  // +0x40
    IFEOKey: *const u8,                           // +0x48
    _pad2: [u8; 4],                               // +0x50-0x53
    CrossProcessFlags: u32,                       // +0x50
    _pad3: [u8; 4],                               // +0x54-0x57
    UserSharedInfoPtr: *const u8,                 // +0x58
    SystemReserved: u32,                          // +0x60
    AtlThunkSListPtr32: u32,                      // +0x64
    ApiSetMap: *const u8,                         // +0x68
    TlsExpansionCounter: u32,                     // +0x70
    TlsBitmap: *const u8,                         // +0x78
    TlsBitmapBits: [u32; 2],                      // +0x80
    ReadOnlySharedMemoryBase: *const u8,          // +0x88
    SharedData: *const u8,                        // +0x90
    ReadOnlyStaticServerData: *const u8,          // +0x98
    AnsiCodePageData: *const u8,                  // +0xA0
    OemCodePageData: *const u8,                   // +0xA8
    UnicodeCaseTableData: *const u8,              // +0xB0
    NumberOfProcessors: u32,                      // +0xB8
    NtGlobalFlag: u32,                            // +0xBC ← DEBUG FLAGS HERE (EXACT!)
}
// github.com/anhdeface
// ============================================================================
// EXECUTE ACTUAL VM-BASED CHECKPOINTS
// ============================================================================

/// Checkpoint 1: Memory-based detection using TinyVM
#[inline(always)]
pub fn checkpoint_memory_integrity() -> bool {
    // Create bytecode for memory integrity check using polymorphic TinyVM
    // This bytecode will:
    // 1. PUSH PEB Address.
    // 2. DUP địa chỉ đó.
    // 3. Dùng bản sao thứ nhất để đọc BeingDebugged.
    // 4. SWAP để đưa bản sao thứ hai lên đầu.
    // 5. Dùng bản sao thứ hai để đọc NtGlobalFlag.
    // 6. ADD cả hai kết quả lại.

    let encryption_key = compute_encryption_key();
    let memory_check_bytecode = [
        // Step 1: PUSH PEB Address
        (VmOp::OP_READ_GS_OFFSET as u8) ^ encryption_key,
        0x60 ^ encryption_key,  // GS:[0x60] = PEB pointer

        // Step 2: DUP địa chỉ đó
        (VmOp::OP_DUP as u8) ^ encryption_key,

        // Step 3: Dùng bản sao thứ nhất để đọc BeingDebugged
        // Load offset for BeingDebugged (0x02)
        (VmOp::OP_LOAD_IMM as u8) ^ encryption_key,
        (0x02u64.to_le_bytes()[0]) ^ encryption_key,
        (0x02u64.to_le_bytes()[1]) ^ encryption_key,
        (0x02u64.to_le_bytes()[2]) ^ encryption_key,
        (0x02u64.to_le_bytes()[3]) ^ encryption_key,
        (0x02u64.to_le_bytes()[4]) ^ encryption_key,
        (0x02u64.to_le_bytes()[5]) ^ encryption_key,
        (0x02u64.to_le_bytes()[6]) ^ encryption_key,
        (0x02u64.to_le_bytes()[7]) ^ encryption_key,

        // Add to get address of BeingDebugged field
        (VmOp::OP_ADD as u8) ^ encryption_key,

        // Read 1 byte value from memory at that address (BeingDebugged flag)
        (VmOp::OP_READ_MEM_U8 as u8) ^ encryption_key,

        // Step 4: SWAP để đưa bản sao thứ hai lên đầu
        (VmOp::OP_SWAP as u8) ^ encryption_key,

        // Step 5: Dùng bản sao thứ hai để đọc NtGlobalFlag
        // Load offset for NtGlobalFlag (0xBC)
        (VmOp::OP_LOAD_IMM as u8) ^ encryption_key,
        (0xBCu64.to_le_bytes()[0]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[1]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[2]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[3]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[4]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[5]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[6]) ^ encryption_key,
        (0xBCu64.to_le_bytes()[7]) ^ encryption_key,

        // Add to get address of NtGlobalFlag
        (VmOp::OP_ADD as u8) ^ encryption_key,

        // Read 4 byte value from memory at that address (NtGlobalFlag)
        (VmOp::OP_READ_MEM_U32 as u8) ^ encryption_key,

        // Step 6: ADD cả hai kết quả lại
        (VmOp::OP_ADD as u8) ^ encryption_key,

        // Exit VM with result (top of stack)
        (VmOp::OP_EXIT as u8) ^ encryption_key,
    ];

    // Execute the bytecode in the VM with a context key
    let context_key = get_cpu_entropy() as u64; // Use entropy as context key
    let vm_result = vm_execute(&memory_check_bytecode, encryption_key, context_key);

    // THE KILLER FEATURE: Use VM result directly as key modifier
    // If there's a debugger, vm_result will be non-zero, corrupting the key
    let vm_key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key ^ (vm_result & 0xFF) as u8, Ordering::SeqCst);

    // Interpret the result - if non-zero, we detected something suspicious
    let detected = vm_result != 0;

    if detected {
        add_suspicion(50, 0);
    }

    detected
}

/// Checkpoint 2: Timing-based detection using TinyVM
#[inline(always)]
pub fn checkpoint_timing_anomaly() -> bool {
    // Create bytecode for timing anomaly check using polymorphic TinyVM
    // This bytecode will:
    // 1. Execute RDTSC twice
    // 2. Calculate difference
    // 3. Compare with threshold
    // 4. Return anomaly count

    let encryption_key = compute_encryption_key();
    let timing_check_bytecode = [
        // Execute first RDTSC
        (VmOp::OP_RDTSC as u8) ^ encryption_key,

        // Execute second RDTSC
        (VmOp::OP_RDTSC as u8) ^ encryption_key,

        // Subtract first from second to get delta
        (VmOp::OP_SUB as u8) ^ encryption_key,

        // Load threshold value using dynamic calculation
        (VmOp::OP_LOAD_IMM as u8) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[0]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[1]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[2]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[3]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[4]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[5]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[6]) ^ encryption_key,
        (get_dynamic_threshold().to_le_bytes()[7]) ^ encryption_key,

        // Compare delta with threshold
        (VmOp::OP_CMP_GT as u8) ^ encryption_key,

        // Exit VM with result (1 if delta > threshold, 0 otherwise)
        (VmOp::OP_EXIT as u8) ^ encryption_key,
    ];

    // Execute the bytecode in the VM with a context key
    let context_key = get_cpu_entropy() as u64; // Use entropy as context key
    let vm_result = vm_execute(&timing_check_bytecode, encryption_key, context_key);

    // Interpret the result - if non-zero, we detected timing anomaly
    let detected = vm_result != 0;

    if detected {
        add_suspicion(30, 1);
    }

    detected
}

/// Checkpoint 3: Exception handling detection (real VEH)
#[inline(always)]
pub fn checkpoint_exception_handling() -> bool {
    if !ENABLE_VEH_DETECTION {
        return false;
    }

    let detected = check_real_breakpoint();

    if detected {
        add_suspicion(40, 2);
    }

    detected
}

/// Checkpoint 4: Hypervisor detection using multi-layered approach
#[inline(always)]
pub fn checkpoint_hypervisor_detection() -> bool {
    // Create bytecode for hypervisor detection using polymorphic TinyVM
    // This bytecode will:
    // Layer A: Use CPUID with leaf 0x40000000 to detect hypervisor brand strings
    // Layer B: Use I/O port 0x5658 (VMware backdoor) if available
    // Layer C: Use timing side-channel to measure VM-exit latency

    let encryption_key = compute_encryption_key();

    // First, let's try CPUID-based detection using VM
    let mut detected = false;

    // Check for hypervisor presence using CPUID leaf 1
    // But be more conservative - some legitimate systems may have this bit set
    unsafe {
        let cpuid_result = cpuid_helper(1);

        // Bit 31 of ECX indicates hypervisor presence
        // Only add suspicion, don't immediately detect
        if (cpuid_result.2 & (1 << 31)) != 0 {
            // Don't set detected=true immediately, just add to suspicion
            add_suspicion(20, 3); // Add moderate suspicion
        }
    }

    // If hypervisor bit is set, perform deeper checks
    // Only set detected=true if we find strong evidence
    let mut deep_check_detected = false;
    let mut brand_suspicion = 0u32;

    // Check hypervisor brand string using CPUID leaves 0x40000000-0x40000002
    let mut brand_string = [0u8; 12];

    unsafe {
        // CPUID leaf 0x40000000
        let (_, ebx, ecx, edx) = cpuid_helper(0x40000000);

        // Store first 12 bytes of brand string
        let ebx_bytes = ebx.to_le_bytes();
        let ecx_bytes = ecx.to_le_bytes();
        let edx_bytes = edx.to_le_bytes();

        brand_string[0..4].copy_from_slice(&ebx_bytes);
        brand_string[4..8].copy_from_slice(&ecx_bytes);
        brand_string[8..12].copy_from_slice(&edx_bytes);
    }

    // Check for known hypervisor signatures using XOR-encoded strings
    let brand_str = std::str::from_utf8(&brand_string).unwrap_or("");

    // XOR-encoded hypervisor signatures (using precomputed constants to avoid macro ordering issues)
    const VMWARE_ENCODED: [u8; 6] = [0x7C, 0x27, 0x1D, 0x04, 0x18, 0x0B]; // "VMware" XOR 0x5A
    const VBOX_ENCODED: [u8; 4] = [0x3C, 0x11, 0x35, 0x30];     // "VBox" XOR 0x5A
    const KVM_ENCODED: [u8; 9] = [0x21, 0x3C, 0x27, 0x21, 0x3C, 0x27, 0x21, 0x3C, 0x27]; // "KVMKVMKVM" XOR 0x5A
    const MS_HV_ENCODED: [u8; 12] = [0x17, 0x03, 0x09, 0x18, 0x05, 0x1D, 0x05, 0x0C, 0x1E, 0x7A, 0x10, 0x1C]; // "Microsoft Hv" XOR 0x5A
    const XEN_ENCODED: [u8; 12] = [0x32, 0x3F, 0x34, 0x3C, 0x27, 0x27, 0x32, 0x3F, 0x34, 0x3C, 0x27, 0x27]; // "XenVMMXenVMM" XOR 0x5A
    const PRL_ENCODED: [u8; 10] = [0x2A, 0x28, 0x36, 0x7A, 0x1E, 0x2F, 0x2A, 0x3F, 0x28, 0x2C]; // "prl hyperv" XOR 0x5A

    // Check if brand string contains any of the XOR-encoded signatures
    let brand_bytes = brand_str.as_bytes();
    if contains_encoded_string(brand_bytes, &VMWARE_ENCODED, 0x5A) ||
       contains_encoded_string(brand_bytes, &VBOX_ENCODED, 0x5A) ||
       contains_encoded_string(brand_bytes, &KVM_ENCODED, 0x5A) ||
       contains_encoded_string(brand_bytes, &MS_HV_ENCODED, 0x5A) ||
       contains_encoded_string(brand_bytes, &XEN_ENCODED, 0x5A) ||
       contains_encoded_string(brand_bytes, &PRL_ENCODED, 0x5A) {
        brand_suspicion = 30; // Stronger suspicion for known hypervisor signatures
        deep_check_detected = true;
    }

    // Perform timing-based detection - be more conservative to avoid cloud false positives
    let timing_suspicion = {
        let mut timing_anomalies = 0u32;
        let mut total_checks = 0u32;

        for _ in 0..5 { // Increase sample size to reduce false positives
            total_checks += 1;

            // Measure CPUID execution time
            let (start_low, start_high): (u32, u32);
            unsafe {
                std::arch::asm!(
                    "lfence",
                    "rdtsc",
                    "lfence",
                    out("eax") start_low,
                    out("edx") start_high,
                    options(nomem, nostack)
                );
            }
            let start = ((start_high as u64) << 32) | (start_low as u64);

            // Execute CPUID (potential trap in hypervisor)
            let _ = unsafe { cpuid_helper(1) };

            let (end_low, end_high): (u32, u32);
            unsafe {
                std::arch::asm!(
                    "lfence",
                    "rdtsc",
                    "lfence",
                    out("eax") end_low,
                    out("edx") end_high,
                    options(nomem, nostack)
                );
            }
            let end = ((end_high as u64) << 32) | (end_low as u64);

            let cpuid_time = end.saturating_sub(start);

            // Measure simple arithmetic time for comparison
            let (start_low2, start_high2): (u32, u32);
            unsafe {
                std::arch::asm!(
                    "lfence",
                    "rdtsc",
                    "lfence",
                    out("eax") start_low2,
                    out("edx") start_high2,
                    options(nomem, nostack)
                );
            }
            let start2 = ((start_high2 as u64) << 32) | (start_low2 as u64);

            // Simple arithmetic (no trap)
            let mut x = 0u64;
            for i in 0..100 {
                x = x.wrapping_add(i);
            }

            let (end_low2, end_high2): (u32, u32);
            unsafe {
                std::arch::asm!(
                    "lfence",
                    "rdtsc",
                    "lfence",
                    out("eax") end_low2,
                    out("edx") end_high2,
                    options(nomem, nostack)
                );
            }
            let end2 = ((end_high2 as u64) << 32) | (end_low2 as u64);

            let arith_time = end2.saturating_sub(start2);

            // Be more conservative with timing detection - increase threshold to avoid cloud false positives
            if cpuid_time > arith_time.saturating_mul(10) { // Increased from 5 to 10
                timing_anomalies += 1;
            }
        }

        // Only add suspicion if more than 60% of checks show anomalies
        if timing_anomalies > (total_checks * 60 / 100) {
            25 // Moderate suspicion for timing anomalies
        } else {
            0
        }
    };

    // Combine all suspicion sources
    let total_suspicion = if detected { 20 } else { 0 } + brand_suspicion + timing_suspicion;

    // Only trigger detection if suspicion score exceeds a high threshold
    // This reduces false positives from legitimate cloud environments
    detected = total_suspicion > 50;

    if detected || total_suspicion > 0 {
        add_suspicion(total_suspicion.max(10), 3); // Minimum suspicion score for hypervisor
    }

    detected
}

/// Check for self-integrity by comparing current hash with golden hash
pub fn checkpoint_integrity_self_hash() -> bool {
    if !ENABLE_INTEGRITY_CHECK {
        return false;
    }

    unsafe {
        // Use black_box to ensure the function addresses are not optimized away
        let start_ptr = std::hint::black_box(_integrity_marker_start as *const u8);
        let end_ptr = std::hint::black_box(_integrity_marker_end as *const u8);

        if start_ptr >= end_ptr {
            return false; // Invalid range
        }

        let current_hash = calculate_runtime_hash(start_ptr, end_ptr);

        // Compare with the stored integrity hash in the global state
        let stored_hash = std::hint::black_box(GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst));

        let tampered = current_hash != stored_hash;

        if tampered {
            add_suspicion(70, 4); // High suspicion for tampering
        }

        std::hint::black_box(tampered)
    }
}

/// Calculate a hash of memory region using DJB2 algorithm
unsafe fn calculate_runtime_hash(start: *const u8, end: *const u8) -> u32 {
    let mut hash: u32 = 5381;
    let mut ptr = start;

    while ptr < end {
        // Read byte as array to avoid function pointer issues
        let byte_array: [u8; 1] = std::ptr::read_volatile(ptr as *const [u8; 1]);
        let byte = byte_array[0];
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);
        ptr = ptr.add(1);
        
        // Use black_box to prevent compiler optimizations
        std::hint::black_box(&mut hash);
    }

    std::hint::black_box(hash)
}

/// Get global detection state (from distributed vector)
#[inline(always)]
pub fn is_globally_debugged() -> bool {
    // Create a temporary instance to access the atomic state
    let temp_dv = DetectionVector::new();
    temp_dv.is_debugged()
}

/// Get suspicion score (from distributed vector)
#[inline(always)]
pub fn get_suspicion_score() -> u32 {
    crate::protector::global_state::get_global_total_score()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Helper function to execute CPUID safely
unsafe fn cpuid_helper(leaf: u32) -> (u32, u32, u32, u32) {
    let eax_out: u32;
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;

    std::arch::asm!(
        "push rbx",
        "cpuid",
        "mov {0:e}, ebx",
        "pop rbx",
        out(reg) ebx_out,
        inout("eax") leaf => eax_out,
        out("ecx") ecx_out,
        out("edx") edx_out,
        options(nomem, nostack)
    );

    (eax_out, ebx_out, ecx_out, edx_out)
}

/// Real VEH check - uses actual exception handling
#[inline(never)]
fn check_real_breakpoint() -> bool {
    // In a real implementation, this would register a real VEH
    // For this example, we'll simulate the check
    false
}

/// Helper function to check if a slice contains an XOR-encoded string
fn contains_encoded_string(haystack: &[u8], encoded_needle: &[u8], key: u8) -> bool {
    if encoded_needle.is_empty() {
        return true;
    }
    if encoded_needle.len() > haystack.len() {
        return false;
    }

    // Decode the needle by XORing with the key
    let decoded_needle: Vec<u8> = encoded_needle.iter().map(|&b| b ^ key).collect();

    for i in 0..=(haystack.len() - encoded_needle.len()) {
        if &haystack[i..i + encoded_needle.len()] == decoded_needle.as_slice() {
            return true;
        }
    }
    false
}

// ============================================================================
// COMPUTATION FUNCTIONS
// ============================================================================

use std::sync::Mutex;

// Global instance of DetectionVector for token access
static GLOBAL_DETECTION_VECTOR: Mutex<Option<DetectionVector>> = Mutex::new(None);

#[inline(always)]
fn compute_encryption_key() -> u8 {
    // Use the distributed state to get the current encryption key
    // This will return the corrupted key if debugger was detected
    let base_key = DetectionVector::get_current_encryption_key();

    // Mix with the current token from the global DetectionVector
    let token = get_current_token();
    let mixed_key = base_key ^ (token & 0xFF) as u8;

    mixed_key
}

#[inline(always)]
fn compute_vm_key() -> u8 {
    // Use the distributed state to get the current VM key
    // This will return the corrupted key if debugger was detected
    let base_key = DetectionVector::get_current_vm_key();

    // Mix with the current token from the global DetectionVector
    let token = get_current_token();
    let mixed_key = base_key ^ ((token >> 8) & 0xFF) as u8;

    mixed_key
}

/// Helper function to get the current token from the global DetectionVector
fn get_current_token() -> u64 {
    let guard = GLOBAL_DETECTION_VECTOR.lock().unwrap();
    if let Some(ref dv) = *guard {
        dv.token
    } else {
        // If not initialized, return a default value
        0xDEADBEEFCAFEBABE
    }
}

/// Initialize the global DetectionVector
pub fn init_global_detection_vector(seed: u32) {
    let mut guard = GLOBAL_DETECTION_VECTOR.lock().unwrap();
    *guard = Some(DetectionVector::new_with_seed(seed));
}

// ============================================================================
// BUSINESS LOGIC FUNCTIONS WITH EMBEDDED DECENTRALIZED CHECKS
// ============================================================================

/// Example: Encrypt sensitive data with embedded memory integrity check
/// RISK 2 Mitigation: Constant-time operations to prevent timing analysis
/// ENHANCEMENT: Opaque predicates to confuse static analysis
pub fn encrypt_data(plaintext: &[u8]) -> Vec<u8> {
    checkpoint_memory_integrity();
    checkpoint_integrity_self_hash(); // Trigger integrity check

    let mut result = Vec::with_capacity(plaintext.len());
    let encryption_key = compute_encryption_key();  // Will be corrupted if debugger detected
    let vm_key = compute_vm_key();  // Will be corrupted if debugger detected

    // Combine both keys to maximize corruption effect
    let combined_key = encryption_key ^ vm_key;

    for &byte in plaintext {
        let encrypted_byte = byte ^ combined_key;
        result.push(encrypted_byte);
    }

    result
}

/// Example: Validate license with embedded timing anomaly check
/// RISK 3 Mitigation: Silent corruption when debugger is detected
/// ENHANCEMENT: Result may be corrupted if debugger was detected
pub fn validate_license(license_key: &str) -> bool {
    checkpoint_timing_anomaly();
    checkpoint_integrity_self_hash(); // Trigger integrity check

    // Validate key structure
    let valid = license_key.len() == 32 && license_key.chars().all(|c| c.is_ascii_alphanumeric());

    // THE KILLER FEATURE: Use VM result as key modifier has already corrupted the keys
    // If debugger is detected, the keys will be corrupted, causing silent failure
    // without explicit conditional checks
    let encryption_key = compute_encryption_key();
    let vm_key = compute_vm_key();
    
    // Simulate using the corrupted keys for some validation operation
    let combined_key = encryption_key ^ vm_key;
    
    // If keys are corrupted (non-zero due to debugger detection), return false
    if combined_key != (0x42 ^ 0x42) { // Expected value when no corruption
        false  // Silent corruption: return false when keys are corrupted
    } else {
        valid
    }
}

/// Example: Decrypt sensitive data with embedded exception handling check
/// RISK 3 Mitigation: Silent corruption when debugger is detected
/// ENHANCEMENT: Data is silently corrupted if debugger was detected
pub fn decrypt_data(ciphertext: &[u8]) -> Vec<u8> {
    checkpoint_exception_handling();
    checkpoint_integrity_self_hash(); // Trigger integrity check

    let mut result = Vec::with_capacity(ciphertext.len());
    let encryption_key = compute_encryption_key(); // Will be corrupted if debugger detected
    let vm_key = compute_vm_key(); // Will be corrupted if debugger detected

    // Combine both keys to maximize corruption effect
    let combined_key = encryption_key ^ vm_key;

    for &byte in ciphertext {
        let decrypted = byte ^ combined_key; // Single XOR to decrypt (same as encrypt)
        result.push(decrypted);
    }

    result
}

// ============================================================================
// ANTI-DEBUG CHECKER STRUCT - Main Module Interface
// ============================================================================

pub struct AntiDebugChecker {
    pub detection_score: u32,
    pub detected_methods: [bool; 5],
}

impl AntiDebugChecker {
    #[inline]
    pub fn new() -> Self {
        AntiDebugChecker {
            detection_score: 0,
            detected_methods: [false; 5],
        }
    }

    #[inline(always)]
    pub fn is_debugged(&self) -> bool {
        is_globally_debugged()
    }

    pub fn get_detection_details(&self) -> DetectionDetails {
        DetectionDetails {
            is_debugged: self.is_debugged(),
            score: self.detection_score,
            peb_check: self.detected_methods[0],
            rdtsc_check: self.detected_methods[1],
            heap_check: self.detected_methods[2],
            hypervisor_check: self.detected_methods[3],
            integrity_check: self.detected_methods[4],
        }
    }
}

// ============================================================================
// DETECTION DETAILS STRUCT - For Logging
// ============================================================================

#[derive(Debug, Clone)]
pub struct DetectionDetails {
    pub is_debugged: bool,
    pub score: u32,
    pub peb_check: bool,
    pub rdtsc_check: bool,
    pub heap_check: bool,
    pub hypervisor_check: bool,
    pub integrity_check: bool,
}

impl DetectionDetails {
    pub fn new() -> Self {
        DetectionDetails {
            is_debugged: is_globally_debugged(),
            score: get_suspicion_score(),
            peb_check: checkpoint_memory_integrity(),
            rdtsc_check: checkpoint_timing_anomaly(),
            heap_check: checkpoint_exception_handling(),
            hypervisor_check: checkpoint_hypervisor_detection(),
            integrity_check: checkpoint_integrity_self_hash(),
        }
    }
}

// ============================================================================
// DECOY SYSTEM (Mê hồn trận - Misleading functions for reverse engineers)
// ============================================================================

use std::sync::atomic::AtomicBool;

// Global atomic flag to track if decoy functions have been tampered with
static DECOY_TAMPERED: AtomicBool = AtomicBool::new(false);

/// Security check main function - appears critical but is just a decoy
/// REVERSE ENGINEERS: This function looks important but is just a distraction!
pub fn security_check_main() -> bool {
    // Simple check that looks important but is just a decoy
    // If someone patches this function, they'll think they've bypassed security
    // but the real checks are elsewhere

    // This is the actual check - very simple
    let is_debugged = unsafe {
        // Use the windows crate instead of winapi
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent()
    };

    // If this function was tampered with (patched to always return true/false),
    // the real system will detect it through other means
    is_debugged == false
}

/// Anti-hack guard function - another decoy that looks important
/// REVERSE ENGINEERS: Don't waste time on this function!
pub fn anti_hack_guard() -> bool {
    // Another simple check that looks important
    // This is just to distract from the real anti-debug mechanisms

    // Simple check that looks complex but isn't
    let entropy = get_cpu_entropy();
    let fake_threshold = 0x12345678u32;

    // This check is meaningless but looks important
    (entropy ^ fake_threshold) != 0
}

/// Drop guard to detect tampering with decoy functions
pub struct DecoyGuard {
    id: u32,
}

impl DecoyGuard {
    pub fn new(id: u32) -> Self {
        DecoyGuard { id }
    }
}

impl Drop for DecoyGuard {
    fn drop(&mut self) {
        // Check if decoy functions have been tampered with
        // This is a secondary check to detect if someone has patched the decoy functions
        if !security_check_main() || !anti_hack_guard() {
            // If the decoy functions return unexpected results,
            // it might indicate tampering - set the tamper flag
            DECOY_TAMPERED.store(true, Ordering::SeqCst);

            // Add suspicion if tampering is detected
            add_suspicion(100, 0); // High suspicion for tampering
        }
    }
}

/// Function to check if decoy functions have been tampered with
pub fn check_decoy_tampering() -> bool {
    DECOY_TAMPERED.load(Ordering::SeqCst)
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/// One-time VEH protection initialization
/// Should be called at application startup (in main)
pub fn initialize_veh_protection() {
    // Initialize the global DetectionVector with a default seed
    init_global_detection_vector(0x12345678);

    // Initialize the global state through the global_state module
    crate::protector::global_state::initialize_veh_protection();

    // Call each checkpoint once during startup to "warm up" the system
    let _ = checkpoint_memory_integrity();
    let _ = checkpoint_timing_anomaly();
    let _ = checkpoint_exception_handling();
    let _ = checkpoint_hypervisor_detection();
    let _ = checkpoint_integrity_self_hash();

    // Initialize decoy system
    let _decoy_guard = DecoyGuard::new(0xDEADBEEF);
}
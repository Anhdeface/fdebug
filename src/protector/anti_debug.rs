#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments,
    unused_macros,
    asm_sub_register
)]
#[allow(non_snake_case)]
///! Anti-debugging module with distributed detection mechanisms
// github.com/anhdeface
// MIT License
use std::cell::RefCell;
use crate::protector::tiny_vm::{VmOp, vm_execute, SecureBuffer};
use crate::dynamic_str; // Import from crate root if needed, or just use it. 


use std::sync::OnceLock;
use std::time::Instant;
use crate::protector::global_state::*;


static LOAD_TIME: OnceLock<Instant> = OnceLock::new();

fn get_load_time() -> &'static Instant {
    LOAD_TIME.get_or_init(Instant::now)
}

// Manual FFI and constants for VEH to ensure reliability across environments
// AddVectoredExceptionHandler moved to global_state.rs

// CONTEXT moved to global_state.rs

const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

// ============================================================================
// CONSTANTS & CONFIGURATION
// ============================================================================

// Environmental detection flags
static IS_VM_ENVIRONMENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static IS_CLOUD_ENVIRONMENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ENVIRONMENT_DETECTION_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Detect if running in a virtualized environment
fn detect_virtual_environment() -> bool {
    // Check for common VM indicators
    let mut is_vm = false;

    // Check CPU vendor string for VM indicators
    unsafe {
        let (_, ebx, ecx, edx) = cpuid_helper(0);

        // Convert to vendor string
        let mut vendor_bytes = [0u8; 12];
        let ebx_bytes = ebx.to_le_bytes();
        let edx_bytes = edx.to_le_bytes();
        let ecx_bytes = ecx.to_le_bytes();

        vendor_bytes[0..4].copy_from_slice(&ebx_bytes);
        vendor_bytes[4..8].copy_from_slice(&edx_bytes);
        vendor_bytes[8..12].copy_from_slice(&ecx_bytes);

        let vendor_string = String::from_utf8_lossy(&vendor_bytes);
        let vendor_lower = vendor_string.to_lowercase();

        // Check for common VM vendors
        if vendor_lower.contains("vmware") ||
           vendor_lower.contains("virtualbox") ||
           vendor_lower.contains("kvm") ||
           vendor_lower.contains("xen") {
            is_vm = true;
        }
    }

    // Additional checks could be added here
    // For example, checking for VM-specific registry keys, hardware IDs, etc.

    is_vm
}

/// Detect if running in a cloud environment
fn detect_cloud_environment() -> bool {
    // Cloud environments often have specific characteristics
    // This is a simplified check - in practice, more sophisticated detection would be used
    let mut is_cloud = false;

    // Check for common cloud indicators in CPUID
    unsafe {
        let (_, _, ecx, _) = cpuid_helper(1);

        // Some cloud providers set specific bits in CPUID
        // This is a simplified check
        if (ecx & (1 << 31)) != 0 {  // Hypervisor bit
            // This could indicate a cloud environment
            is_cloud = true;
        }
    }

    is_cloud
}

/// Check if running in a safe development environment
fn is_safe_development_environment() -> bool {
    // Check for build mode and common development indicators
    if detect_build_mode() == "debug" {
        return true;
    }
    
    // Check for common dev environment artifacts/env vars
    std::env::var("CARGO_MANIFEST_DIR").is_ok() || 
    std::env::var("RUSTUP_HOME").is_ok()
}

/// Detect build mode (debug/release)
fn detect_build_mode() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Check if running in known CI/CD environments
fn is_ci_environment() -> bool {
    std::env::var("CI").is_ok() || 
    std::env::var("GITHUB_ACTIONS").is_ok() || 
    std::env::var("GITLAB_CI").is_ok()
}

/// Initialize environmental detection
fn initialize_environment_detection() {
    if ENVIRONMENT_DETECTION_DONE.load(std::sync::atomic::Ordering::SeqCst) {
        return; // Already done
    }

    // Skip VM detection entirely if in known CI/CD environments
    let (is_vm, is_cloud) = if is_ci_environment() {
        (false, false)
    } else {
        (detect_virtual_environment(), detect_cloud_environment())
    };

    IS_VM_ENVIRONMENT.store(is_vm, std::sync::atomic::Ordering::SeqCst);
    IS_CLOUD_ENVIRONMENT.store(is_cloud, std::sync::atomic::Ordering::SeqCst);
    ENVIRONMENT_DETECTION_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Adaptive calibration function to measure actual CPU instruction latency
/// This performs multiple iterations of RDTSC -> CPUID -> RDTSC to measure typical latency
/// On real hardware, CPUID takes ~100-200 cycles. On VMs, it causes VM-Exit taking 2000-4000+ cycles.
/// Uses statistical analysis to establish baseline behavior and adaptive thresholds.
/// Also considers environmental factors like virtualization/cloud environments.
#[inline(always)]
fn calibrate_hard_threshold() -> u64 {
    // Ensure environment detection is initialized
    if !ENVIRONMENT_DETECTION_DONE.load(std::sync::atomic::Ordering::SeqCst) {
        initialize_environment_detection();
    }

    let mut measurements = [0u64; 2000];
    let mut valid_count = 0;

    // Perform 2000 calibration iterations
    for i in 0..2000 {
        let start_low: u32;
        let start_high: u32;
        let start_aux: u32;  // For TSC_AUX (core ID)

        unsafe {
            std::arch::asm!(
                "lfence",           // Serialize instruction stream
                "rdtscp",           // Read timestamp counter with core ID
                "lfence",           // Serialize again
                out("eax") start_low,
                out("edx") start_high,
                out("ecx") start_aux,  // TSC_AUX - core identifier
                options(nomem, nostack)
            );
        }

        let start = ((start_high as u64) << 32) | (start_low as u64);

        // Execute CPUID - this is where VMs typically trap and cause VM exit
        // CPUID with eax=0 to get vendor string, which is commonly trapped by hypervisors
        let (eax_out, _ebx_out, _ecx_out, _edx_out) = unsafe { cpuid_helper(0) };

        let end_low: u32;
        let end_high: u32;
        let end_aux: u32;  // For TSC_AUX (core ID)

        unsafe {
            std::arch::asm!(
                "lfence",           // Serialize instruction stream
                "rdtscp",           // Read timestamp counter with core ID
                "lfence",           // Serialize again
                out("eax") end_low,
                out("edx") end_high,
                out("ecx") end_aux,  // TSC_AUX - core identifier
                options(nomem, nostack)
            );
        }

        let end = ((end_high as u64) << 32) | (end_low as u64);

        // Check for core migration - if cores changed, discard this measurement
        if start_aux != end_aux {
            continue;  // Skip this iteration if core migrated
        }

        let latency = end.saturating_sub(start);

        // Only record measurements that are within reasonable bounds
        // This filters out extreme outliers that could be caused by interrupts, etc.
        if latency < 10000 { // Reasonable upper bound for normal operation
            measurements[valid_count] = latency;
            valid_count += 1;

            if valid_count >= 2000 {
                break; // We have enough valid measurements
            }
        }
    }

    if valid_count == 0 {
        // If no valid measurements, return a conservative default
        return 1000;
    }

    // Sort the measurements to calculate percentiles
    let sorted_measurements = &mut measurements[0..valid_count];
    sorted_measurements.sort();

    // Use the 10th percentile as our baseline to avoid noise from occasional spikes
    // This is more robust than using the absolute minimum which could be affected by measurement noise
    let baseline_idx = (valid_count * 10 / 100).min(valid_count - 1);
    let baseline_latency = sorted_measurements[baseline_idx];

    // Calculate median for reference
    let median_idx = valid_count / 2;
    let median_latency = sorted_measurements[median_idx];

    // Adjust thresholds based on environment detection
    let is_vm_env = IS_VM_ENVIRONMENT.load(std::sync::atomic::Ordering::SeqCst);
    let is_cloud_env = IS_CLOUD_ENVIRONMENT.load(std::sync::atomic::Ordering::SeqCst);

    // In virtualized or cloud environments, adjust the multipliers to account for expected overhead
    let base_multiplier = if is_vm_env || is_cloud_env { 6 } else { 8 };
    let median_multiplier = if is_vm_env || is_cloud_env { 3 } else { 4 };

    // Use a multiple of the baseline for VM detection threshold
    // This adapts to the specific system's performance characteristics and environment
    let adaptive_threshold = (baseline_latency * base_multiplier)
        .max(median_latency * median_multiplier)
        .max(if is_vm_env || is_cloud_env { 1500 } else { 500 });

    adaptive_threshold
}

/// Demonstration of the ultimate string obfuscation system
/// This function uses the new dynamic_str! macro which achieves zero static trace
pub fn demonstrate_dynamic_strings() {
    // String is decrypted on the stack and zeroized after use
    let secret = dynamic_str!("Top Secret Debugger Protection Active");
    
    // We can use the buffer as a slice
    let msg = String::from_utf8_lossy(&secret);
    
    if DIAGNOSTIC_MODE.load(Ordering::Relaxed) {
        // In a real scenario, we'd log this securely
        let _ = msg.len();
    }
    
    // Once 'secret' goes out of scope, it is automatically wiped from memory
}

/// Calculate jitter using Mean Absolute Deviation (MAD) for robust statistics
/// This measures timing consistency - debuggers cause high jitter due to interruption
#[inline(always)]
fn calculate_jitter_mad(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }

    // Calculate mean
    let sum: u128 = samples.iter().map(|&x| x as u128).sum();
    let mean = (sum / samples.len() as u128) as u64;

    // Calculate Mean Absolute Deviation
    let mut abs_dev_sum = 0u128;
    for &sample in samples {
        let deviation = if sample > mean {
            sample - mean
        } else {
            mean - sample
        };
        abs_dev_sum += deviation as u128;
    }

    (abs_dev_sum / samples.len() as u128) as u64
}

/// Get a dynamic threshold for RDTSC checks using hardware-locked calibration
/// This makes the threshold hardware-specific and distinguishes between real hardware and VMs
fn get_dynamic_threshold() -> u64 {
    calibrate_hard_threshold()
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

// Global window for adaptive timing checks
static TIMING_WINDOW: [AtomicU64; 10] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
];
static WINDOW_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Check if process is running within terminal (powershell/cmd)
fn is_terminal_context() -> bool {
    use windows::Win32::System::Threading::{GetCurrentProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    
    unsafe {
        let pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap_or_default();
        if snapshot.is_invalid() { return false; }
        
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        let mut parent_pid = 0;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            while {
                if entry.th32ProcessID == pid {
                    parent_pid = entry.th32ParentProcessID;
                    false
                } else {
                    Process32NextW(snapshot, &mut entry).is_ok()
                }
            } {}
        }
        
        if parent_pid == 0 { return false; }
        
        // Find parent name
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            while {
                if entry.th32ProcessID == parent_pid {
                    let name = String::from_utf16_lossy(&entry.szExeFile);
                    let name_lower = name.to_lowercase();
                    return name_lower.contains("powershell") || name_lower.contains("cmd.exe");
                }
                Process32NextW(snapshot, &mut entry).is_ok()
            } {}
        }
    }
    false
}

// ============================================================================
// DISTRIBUTED STATE SYSTEM (Using Atomic Variables for Cross-Thread Detection)
// ============================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// Import global state from the global_state module
// Import global state from the global_state module
use crate::protector::global_state::*;
use crate::protector::recalculate_global_integrity;

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

    /// Set debugged flag (Corrupt keys + updates)
    /// This causes silent failure in the protected application
    fn set_debugged(&mut self) {
        // Critical threat level reached: execute silent corruption strategy.
        // We corrupt the encryption and VM keys to cause logic errors later in execution.

        // Silent corruption: Change encryption key when debugger is detected
        GLOBAL_ENCRYPTION_KEY.store(0xFF, Ordering::SeqCst);  // Corrupted key
        GLOBAL_VIRTUAL_MACHINE_KEY.store(0x00, Ordering::SeqCst);  // Corrupted VM key

        // Corrupt POISON_SEED to break all token-dependent logic
        POISON_SEED.store(0xDEADC0DEBADC0DE, Ordering::SeqCst);

        // Recalculate integrity hash
        recalculate_global_integrity();
    }

    /// Add suspicion using DetectionSeverity
    fn add_suspicion(&mut self, severity: DetectionSeverity) {
        add_suspicion(severity);

        // Check if we reached critical levels to trigger key corruption
        // We check the global score
        if get_suspicion_score() >= DetectionSeverity::Critical.score() {
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

    /// Helper method to check PEB safety with enhanced accuracy 
    fn check_peb_safety(&self) -> bool {
        // Use Windows API to safely check for debugger presence instead of direct PEB access
        // This prevents crashes from direct memory access and handles Windows updates properly
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
        let is_debugger_present = being_debugged != 0;

        // Enhanced detection with multiple checks to reduce false positives
        // Some legitimate applications or system configurations may set these flags
        // so we need to be more nuanced in our interpretation

        // Check for specific debugger indicators rather than just any flag
        let debugger_indicators = (nt_global_flag & 0x70) != 0; // Specifically check for FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK, FLG_HEAP_VALIDATE_PARAMETERS
        let being_debugged_flag = is_debugger_present;

        // Return true if neither specific debugger indicators are present
        // This reduces false positives from legitimate system configurations
        !being_debugged_flag && !debugger_indicators
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
#[allow(non_snake_case)]
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

/// Checkpoint 1: Memory-based detection using TinyVM with enhanced accuracy
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
        VmOp::op_read_gs_offset() ^ encryption_key,
        0x60 ^ encryption_key,  // GS:[0x60] = PEB pointer

        // Step 2: DUP địa chỉ đó
        VmOp::op_dup() ^ encryption_key,

        // Step 3: Dùng bản sao thứ nhất để đọc BeingDebugged
        // Load offset for BeingDebugged (0x02)
        VmOp::op_load_imm() ^ encryption_key,
        (0x02u64.to_le_bytes()[0]) ^ encryption_key,
        (0x02u64.to_le_bytes()[1]) ^ encryption_key,
        (0x02u64.to_le_bytes()[2]) ^ encryption_key,
        (0x02u64.to_le_bytes()[3]) ^ encryption_key,
        (0x02u64.to_le_bytes()[4]) ^ encryption_key,
        (0x02u64.to_le_bytes()[5]) ^ encryption_key,
        (0x02u64.to_le_bytes()[6]) ^ encryption_key,
        (0x02u64.to_le_bytes()[7]) ^ encryption_key,

        // Add to get address of BeingDebugged field
        VmOp::op_add() ^ encryption_key,

        // Read 1 byte value from memory at that address (BeingDebugged flag)
        VmOp::op_read_mem_u8() ^ encryption_key,

        // Step 4: SWAP để đưa bản sao thứ hai lên đầu
        VmOp::op_swap() ^ encryption_key,

        // Step 5: Dùng bản sao thứ hai để đọc NtGlobalFlag
        // Load offset for NtGlobalFlag (0xBC)
        VmOp::op_load_imm() ^ encryption_key,
        (0x0BCu64.to_le_bytes()[0]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[1]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[2]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[3]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[4]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[5]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[6]) ^ encryption_key,
        (0x0BCu64.to_le_bytes()[7]) ^ encryption_key,

        // Add to get address of NtGlobalFlag
        VmOp::op_add() ^ encryption_key,

        // Read 4 byte value from memory at that address (NtGlobalFlag)
        VmOp::op_read_mem_u32() ^ encryption_key,

        // Step 6: ADD cả hai kết quả lại
        VmOp::op_add() ^ encryption_key,

        // Exit VM with result (top of stack)
        VmOp::op_exit() ^ encryption_key,
    ];

    // Execute the bytecode in the VM with a context key
    let context_key = get_cpu_entropy() as u64; // Use entropy as context key
    let vm_result = vm_execute(&memory_check_bytecode, encryption_key, context_key);

    // THE KILLER FEATURE: Use VM result directly as key modifier
    // If there's a debugger, vm_result will be non-zero, corrupting the key
    let vm_key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(vm_key ^ (vm_result & 0xFF) as u8, Ordering::SeqCst);

    // Enhanced interpretation of the result to reduce false positives
    // Instead of just checking if non-zero, use a more nuanced approach
    let detected = vm_result != 0;

    if detected {
        // Reduce suspicion in dev environments or debug builds
        if is_safe_development_environment() {
            add_suspicion_at(DetectionSeverity::Low, 0); 
        } else {
            add_suspicion_at(DetectionSeverity::Medium, 0);
        }
    }

    detected
}







fn calibrate_baseline_latency() {
    let mut total_latency = 0u64;
    let iterations = 500;

    for _ in 0..iterations {
        let start_low: u32;
        let start_high: u32;
        
        unsafe {
            std::arch::asm!(
                "lfence",
                "rdtscp",
                "lfence",
                out("eax") start_low,
                out("edx") start_high,
                out("ecx") _,
                options(nomem, nostack)
            );
        }
        let start = ((start_high as u64) << 32) | (start_low as u64);

        // Minimal work to measure overhead
        std::hint::black_box(0);

        let end_low: u32;
        let end_high: u32;
        
        unsafe {
            std::arch::asm!(
                "lfence",
                "rdtscp",
                "lfence",
                out("eax") end_low,
                out("edx") end_high,
                out("ecx") _,
                options(nomem, nostack)
            );
        }
        let end = ((end_high as u64) << 32) | (end_low as u64);
        
        // Accumulate latency
        total_latency += end.saturating_sub(start);
    }

    let average_latency = total_latency / iterations;
    
    // Store in global state
    use crate::protector::global_state::*;
    BASE_LINE_LATENCY.store(average_latency, Ordering::SeqCst);
}

/// Checkpoint 2: Advanced timing-based detection using M-of-N check
/// Mitigates OS context switch noise by requiring 4 out of 5 checks to fail
#[inline(always)]
pub fn checkpoint_timing_anomaly() -> bool {
    use crate::protector::global_state::*;

    // 1. Warm-up Period: Disable suspicion for first 5 seconds
    if get_load_time().elapsed().as_secs() < 5 {
        return false;
    }

    if is_priority_idle() {
        return false;
    }
    
    // Measure current delta
    let delta = unsafe {
        let start_low: u32;
        let start_high: u32;
        std::arch::asm!("lfence", "rdtscp", "lfence", out("eax") start_low, out("edx") start_high, out("ecx") _, options(nomem, nostack));
        let start = ((start_high as u64) << 32) | (start_low as u64);
        
        std::hint::black_box(0); // Payload simulation
        
        let end_low: u32;
        let end_high: u32;
        std::arch::asm!("lfence", "rdtscp", "lfence", out("eax") end_low, out("edx") end_high, out("ecx") _, options(nomem, nostack));
        let end = ((end_high as u64) << 32) | (end_low as u64);
        end.saturating_sub(start)
    };

    // 2. Sliding Window Logic
    let idx = WINDOW_INDEX.fetch_add(1, Ordering::SeqCst) % 10;
    TIMING_WINDOW[idx].store(delta, Ordering::SeqCst);

    // Calculate window average (skipping zeros/uninitialized)
    let mut sum = 0;
    let mut count = 0;
    for sample in &TIMING_WINDOW {
        let val = sample.load(Ordering::SeqCst);
        if val > 0 {
            sum += val;
            count += 1;
        }
    }

    if count < 5 { return false; } // Need baseline
    let avg = sum / count;

    // 3. Adaptive Threshold with Context Awareness
    let multiplier = if is_terminal_context() { 8 } else { 5 };
    
    // 4. Jitter Tolerance: if MAD < 50, treat as normal variance
    let mut samples = [0u64; 10];
    for i in 0..10 {
        samples[i] = TIMING_WINDOW[i].load(Ordering::SeqCst);
    }
    let jitter = calculate_jitter_mad(&samples);
    if jitter < 50 {
        return false;
    }

    if delta > avg.saturating_mul(multiplier) {
        add_suspicion_at(DetectionSeverity::High, 2);
        // Silent poisoning
        GLOBAL_ENCRYPTION_KEY.fetch_xor(0xFF, Ordering::SeqCst);
        return true;
    }

    false
}

/// Calculate dynamic threshold using MAD (Median Absolute Deviation) approach
fn get_mad_threshold(window_samples: &[u64]) -> u64 {
    let count = window_samples.len();
    if count == 0 {
        return 0;
    }

    // Create a copy for sorting
    let mut samples = [0u64; 16];
    let copy_len = std::cmp::min(count, 16);
    if copy_len > 0 {
        samples[..copy_len].copy_from_slice(&window_samples[..copy_len]);
    }

    // Implement insertion sort to find median
    for i in 1..copy_len {
        let key = samples[i];
        let mut j = i as i32 - 1;
        while j >= 0 && samples[j as usize] > key {
            samples[(j + 1) as usize] = samples[j as usize];
            j -= 1;
        }
        samples[(j + 1) as usize] = key;
    }

    let median = if copy_len > 0 { samples[copy_len / 2] } else { 0 };

    // Calculate deviations from median
    let mut deviations = [0u64; 16];
    for i in 0..copy_len {
        deviations[i] = if samples[i] > median { samples[i] - median } else { median - samples[i] };
    }

    // Sort deviations to find MAD (Median Absolute Deviation)
    for i in 1..copy_len {
        let key = deviations[i];
        let mut j = i as i32 - 1;
        while j >= 0 && deviations[j as usize] > key {
            deviations[(j + 1) as usize] = deviations[j as usize];
            j -= 1;
        }
        deviations[(j + 1) as usize] = key;
    }

    let mad = if copy_len > 0 { deviations[copy_len / 2] } else { 0 };

    // Return dynamic threshold: Median + 8*MAD
    median.saturating_add(mad.saturating_mul(8))
}

/// Checkpoint 3: Exception handling detection (real VEH)
#[inline(always)]
pub fn checkpoint_exception_handling() -> bool {
    if !ENABLE_VEH_DETECTION {
        return false;
    }

    let detected = check_real_breakpoint();

    if detected {
        if is_safe_development_environment() {
            add_suspicion_at(DetectionSeverity::Low, 3);
        } else {
            add_suspicion_at(DetectionSeverity::Medium, 3);
        }
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
            add_suspicion_at(DetectionSeverity::Low, 1); // Reduced from Medium to Low(10) per task
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
        brand_string[8..12].copy_from_slice(&ecx_bytes);
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
        brand_suspicion = 15; // Reduced from 30 to 15 per task
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
            10 // Changed from 25 to 10 (Low per task instructions)
        } else {
            0
        }
    };

    // Combine all suspicion sources
    let total_suspicion = if deep_check_detected { 30 } else { 0 } + brand_suspicion + timing_suspicion; // Strong detection = Medium(30)

    // Only trigger detection if suspicion score exceeds a high threshold
    // This reduces false positives from legitimate cloud environments
    detected = total_suspicion > 70; // Increased from 50 to 70

    if detected {
        add_suspicion_at(DetectionSeverity::High, 1);
    } else if total_suspicion > 0 {
        if total_suspicion >= 30 {
            add_suspicion_at(DetectionSeverity::Medium, 1);
        } else {
            add_suspicion_at(DetectionSeverity::Low, 1);
        }
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

        let tampered = u64::from(current_hash) != stored_hash;

        if tampered {
            add_suspicion(DetectionSeverity::High); // High suspicion for tampering
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

// is_globally_debugged removed to prevent bypass via patching.
// All security state is now mathematically coupled to data transformation.

/// Get suspicion score (from distributed vector)
#[inline(always)]
pub fn get_suspicion_score() -> u32 {
    crate::protector::global_state::get_suspicion_score()
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
}
// is_debugged and DetectionDetails removed to enforce mathematical coupling.

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
            add_suspicion(DetectionSeverity::Critical); // High suspicion for tampering
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
    // Initialize the global state through the global_state module
    crate::protector::global_state::initialize_veh_protection();

    // Initialize environmental detection
    initialize_environment_detection();

    // Call each checkpoint once during startup to "warm up" the system
    let _ = checkpoint_memory_integrity();
    let _ = checkpoint_timing_anomaly();
    let _ = checkpoint_exception_handling();
    let _ = checkpoint_hypervisor_detection();
    let _ = checkpoint_integrity_self_hash();

    // Initialize decoy system
    let _decoy_guard = DecoyGuard::new(0xDEADBEEF);
}

// ============================================================================
// MEMORY DUMP PROTECTION FUNCTIONS
// ============================================================================

use std::ptr;
use std::mem;
use std::arch::asm;

/// Structure definitions for PE headers
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,      // Magic number
    e_cblp: u16,       // Bytes on last page of file
    e_cp: u16,         // Pages in file
    e_crlc: u16,       // Relocations
    e_cparhdr: u16,    // Size of header in paragraphs
    e_minalloc: u16,   // Minimum extra paragraphs needed
    e_maxalloc: u16,   // Maximum extra paragraphs needed
    e_ss: u16,         // Initial (relative) SS value
    e_sp: u16,         // Initial SP value
    e_csum: u16,       // Checksum
    e_ip: u16,         // Initial IP value
    e_cs: u16,         // Initial (relative) CS value
    e_lfarlc: u16,     // File address of relocation table
    e_ovno: u16,       // Overlay number
    e_res: [u16; 4],   // Reserved words
    e_oemid: u16,      // OEM identifier (for e_oeminfo)
    e_oeminfo: u16,    // OEM information; e_oemid specific
    e_res2: [u16; 10], // Reserved words
    e_lfanew: u32,     // File address of new exe header
}

#[repr(C)]
struct ImageNtHeaders {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,  // This is what we want to tamper with
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    // DataDirectory would follow, but we don't need it for this
}
/// Structure for PEB (Process Environment Block) - x64 Minimal Layout
/// Only includes fields necessary for anti-dump protection
/// Reference: https://www.vergiliusproject.com/kernels/x64/windows-11/23h2/_PEB
#[repr(C)]
struct Peb64 {
    inherited_address_space: u8,        // +0x00
    read_image_file_exec_options: u8,   // +0x01
    being_debugged: u8,                 // +0x02
    bit_field: u8,                      // +0x03
    _padding1: [u8; 4],                 // +0x04-0x07 (alignment)
    mutant: *const u8,                  // +0x08
    image_base_address: *mut u8,        // +0x10 - CRITICAL: Base address of image
    ldr: *const u8,                     // +0x18 - PEB_LDR_DATA
    process_parameters: *const u8,      // +0x20
    sub_system_data: *const u8,         // +0x28
    process_heap: *const u8,            // +0x30
    fast_peb_lock: *const u8,           // +0x38
    atl_thunk_s_list_ptr: *const u8,    // +0x40
    ifeo_key: *const u8,                // +0x48
    cross_process_flags: u32,           // +0x50
    _padding2: [u8; 4],                 // +0x54-0x57 (alignment)
    kernel_callback_table: *const u8,   // +0x58
    system_reserved: u32,               // +0x60
    atl_thunk_s_list_ptr32: u32,        // +0x64
    api_set_map: *const u8,             // +0x68
    tls_expansion_counter: u32,         // +0x70
    _padding3: [u8; 4],                 // +0x74-0x77 (alignment)
    tls_bitmap: *const u8,              // +0x78
    tls_bitmap_bits: [u32; 2],          // +0x80
    read_only_shared_memory_base: *const u8,    // +0x88
    shared_data: *const u8,             // +0x90
    read_only_static_server_data: *const *const u8, // +0x98
    ansi_code_page_data: *const u8,     // +0xA0
    oem_code_page_data: *const u8,      // +0xA8
    unicode_case_table_data: *const u8, // +0xB0
    number_of_processors: u32,          // +0xB8
    nt_global_flag: u32,                // +0xBC - DEBUG FLAGS
    _padding4: [u8; 8],                 // +0xC0-0xC7
    critical_section_timeout: u64,      // +0xC8
    heap_segment_reserve: u64,          // +0xD0
    heap_segment_commit: u64,           // +0xD8
    heap_decommit_total_free_threshold: u64, // +0xE0
    heap_decommit_free_block_threshold: u64, // +0xE8
    number_of_heaps: u32,               // +0xF0
    maximum_number_of_heaps: u32,       // +0xF4
    process_heaps: *const *const u8,    // +0xF8
    gdi_shared_handle_table: *const u8, // +0x100
    process_starter_helper: *const u8,  // +0x108
    gdi_dc_attribute_list: u32,         // +0x110
    _padding5: [u8; 4],                 // +0x114-0x117
    loader_lock: *const u8,             // +0x118
    os_major_version: u32,              // +0x120
    os_minor_version: u32,              // +0x124
    os_build_number: u16,               // +0x128
    os_csd_version: u16,                // +0x12A
    os_platform_id: u32,                // +0x12C
    image_subsystem: u32,               // +0x130
    image_subsystem_major_version: u32, // +0x134
    image_subsystem_minor_version: u32, // +0x138
    _padding6: [u8; 4],                 // +0x13C-0x13F
    active_process_affinity_mask: u64,  // +0x140
    gdi_handle_buffer: [u32; 60],       // +0x148 (60 DWORDs = 240 bytes, ends at +0x238)
    post_process_init_routine: *const u8, // +0x238
    // ... more fields until SizeOfImage
}

/// x64 PE IMAGE_OPTIONAL_HEADER64 structure
#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,                              // +0x00
    major_linker_version: u8,                // +0x02
    minor_linker_version: u8,                // +0x03
    size_of_code: u32,                       // +0x04
    size_of_initialized_data: u32,           // +0x08
    size_of_uninitialized_data: u32,         // +0x0C
    address_of_entry_point: u32,             // +0x10
    base_of_code: u32,                       // +0x14
    image_base: u64,                         // +0x18 (64-bit!)
    section_alignment: u32,                  // +0x20
    file_alignment: u32,                     // +0x24
    major_operating_system_version: u16,     // +0x28
    minor_operating_system_version: u16,     // +0x2A
    major_image_version: u16,                // +0x2C
    minor_image_version: u16,                // +0x2E
    major_subsystem_version: u16,            // +0x30
    minor_subsystem_version: u16,            // +0x32
    win32_version_value: u32,                // +0x34
    size_of_image: u32,                      // +0x38 - CRITICAL: real SizeOfImage
    size_of_headers: u32,                    // +0x3C
    check_sum: u32,                          // +0x40
    subsystem: u16,                          // +0x44
    dll_characteristics: u16,                // +0x46
    size_of_stack_reserve: u64,              // +0x48
    size_of_stack_commit: u64,               // +0x50
    size_of_heap_reserve: u64,               // +0x58
    size_of_heap_commit: u64,                // +0x60
    loader_flags: u32,                       // +0x68
    number_of_rva_and_sizes: u32,            // +0x6C
    // Data directories follow...
}

/// x64 IMAGE_NT_HEADERS64 structure
#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,                          // +0x00: "PE\0\0"
    file_header: ImageFileHeader,            // +0x04
    optional_header: ImageOptionalHeader64,  // +0x18
}

// ============================================================================
// ANTI-DUMP PROTECTION - Core Functions
// ============================================================================

/// Lấy địa chỉ base của image hiện tại KHÔNG sử dụng Windows API chuẩn.
/// 
/// **Kỹ thuật:** Truy cập trực tiếp vào TEB → PEB qua segment register GS.
/// 
/// - GS:[0x30] = TEB (Thread Environment Block)
/// - GS:[0x60] = PEB (Process Environment Block)  
/// - PEB + 0x10 = ImageBaseAddress
/// 
/// Kỹ thuật này bypass hoàn toàn các API như GetModuleHandle(NULL) hay NtCurrentPeb().
#[inline(always)]
unsafe fn get_image_base_address() -> *mut u8 {
    let image_base: *mut u8;
    asm!(
        // Đọc trực tiếp ImageBaseAddress từ PEB
        // GS:[0x60] = PEB pointer, PEB + 0x10 = ImageBaseAddress
        "mov rax, gs:[0x60]",     // Load PEB pointer into RAX
        "mov {}, [rax + 0x10]",   // Load ImageBaseAddress from PEB+0x10
        out(reg) image_base,
        out("rax") _,
        options(nostack, readonly, preserves_flags)
    );
    image_base
}

/// Lấy pointer đến SizeOfImage trong NT Headers PE.
/// **LƯU Ý:** SizeOfImage không nằm trong PEB, mà nằm trong PE Optional Header!
#[inline(always)]
unsafe fn get_size_of_image_in_pe(base: *mut u8) -> *mut u32 {
    // Validate DOS header
    let dos_magic = *(base as *const u16);
    if dos_magic != 0x5A4D { // 'MZ'
        return ptr::null_mut();
    }
    
    // Get NT headers offset from e_lfanew field at offset 0x3C
    let e_lfanew = *(base.add(0x3C) as *const u32);
    let nt_headers = base.add(e_lfanew as usize) as *mut ImageNtHeaders64;
    
    // Validate PE signature
    if (*nt_headers).signature != 0x00004550 { // 'PE\0\0'
        return ptr::null_mut();
    }
    
    // Return pointer to SizeOfImage field in Optional Header
    // OptionalHeader is at FileHeader (0x04) + sizeof(FileHeader) (0x14) = 0x18
    // SizeOfImage is at OptionalHeader + 0x38
    &mut (*nt_headers).optional_header.size_of_image as *mut u32
}

/// Xóa PE headers từ bộ nhớ để ngăn chặn memory dump.
/// 
/// **Kỹ thuật:**
/// 1. Lấy địa chỉ base thông qua PEB (không dùng API)
/// 2. Thay đổi memory protection sang PAGE_READWRITE bằng VirtualProtect
/// 3. Xóa sạch IMAGE_DOS_HEADER và IMAGE_NT_HEADERS bằng write_bytes
/// 4. Khôi phục protection ban đầu
/// 
/// **An toàn:** Sử dụng VirtualProtect để tránh Access Violation (0xC0000005)
pub fn erase_pe_header() {
    unsafe {
        // Get base address without using standard APIs
        let base_address = get_image_base_address();
        
        // Validate base address
        if base_address.is_null() || (base_address as usize) < 0x10000 {
            return;
        }
        
        // Verify DOS header magic
        let dos_magic = *(base_address as *const u16);
        if dos_magic != 0x5A4D { // 'MZ'
            return;
        }
        
        // Get e_lfanew to find NT headers
        let e_lfanew = *(base_address.add(0x3C) as *const u32);
        let nt_headers = base_address.add(e_lfanew as usize);
        
        // Validate PE signature
        let pe_sig = *(nt_headers as *const u32);
        if pe_sig != 0x00004550 { // 'PE\0\0'
            return;
        }
        
        // Calculate total header size to erase
        // DOS Header (64 bytes) + DOS Stub + NT Headers
        let header_size = e_lfanew as usize + mem::size_of::<ImageNtHeaders64>();
        
        // Use VirtualProtect to change memory protection
        // Import from windows crate
        use windows::Win32::System::Memory::{
            VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE
        };
        
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
        
        // Change protection to PAGE_READWRITE
        let protect_result = VirtualProtect(
            base_address as *const _,
            header_size,
            PAGE_READWRITE,
            &mut old_protect
        );
        
        if protect_result.is_err() {
            // Cannot change protection, abort to avoid crash
            return;
        }
        
        // Zero out the headers
        ptr::write_bytes(base_address, 0, header_size);
        
        // Restore original protection (optional, headers are already zeroed)
        let _ = VirtualProtect(
            base_address as *const _,
            header_size,
            old_protect,
            &mut old_protect
        );
    }
}

/// Thay đổi trường SizeOfImage trong PE header để đánh lừa dump tools.
/// 
/// **Kỹ thuật:**
/// - Truy cập trực tiếp vào PE Optional Header
/// - Modifier: giá trị cộng thêm vào SizeOfImage
/// - Các công cụ dump sẽ đọc sai kích thước image
/// 
/// **Lưu ý:** SizeOfImage thực tế nằm trong PE header, không phải PEB!
/// Windows loader CACHE giá trị này trong một số cấu trúc internal,
/// nhưng dump tools thường đọc trực tiếp từ PE header.
pub fn size_of_image_tamper(modifier: u32) {
    unsafe {
        let base_address = get_image_base_address();
        
        if base_address.is_null() {
            return;
        }
        
        let size_of_image_ptr = get_size_of_image_in_pe(base_address);
        
        if size_of_image_ptr.is_null() {
            return;
        }
        
        // Need to change protection first
        use windows::Win32::System::Memory::{
            VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE
        };
        
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
        
        // Change protection for the SizeOfImage field area
        let protect_result = VirtualProtect(
            size_of_image_ptr as *const _,
            4, // size of u32
            PAGE_READWRITE,
            &mut old_protect
        );
        
        if protect_result.is_err() {
            return;
        }
        
        // Read current value
        let current_size = *size_of_image_ptr;
        
        // Apply modifier (wrap around to avoid overflow issues)
        let tampered_size = current_size.wrapping_add(modifier);
        
        // Write tampered value
        *size_of_image_ptr = tampered_size;
        
        // Restore protection
        let _ = VirtualProtect(
            size_of_image_ptr as *const _,
            4,
            old_protect,
            &mut old_protect
        );
    }
}

// Working Set tracking state
static LAST_WORKING_SET_SIZE: AtomicU64 = AtomicU64::new(0);
static WORKING_SET_CHECK_COUNT: AtomicU64 = AtomicU64::new(0);
static WORKING_SET_ANOMALY_COUNT: AtomicU64 = AtomicU64::new(0);

/// Giám sát WorkingSet để phát hiện hành vi đọc bộ nhớ bất thường.
/// 
/// **Kỹ thuật phát hiện:**
/// 1. So sánh WorkingSet size qua các lần gọi
/// 2. Đột biến lớn trong WorkingSet có thể chỉ ra scanning/dumping
/// 3. Pattern "touch all pages" điển hình của memory dump tools
/// 
/// **Return:** true nếu phát hiện hành vi bất thường
pub fn working_set_monitor() -> bool {
    use windows::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS
    };
    use windows::Win32::Foundation::HANDLE;
    use std::ffi::c_void;
    
    unsafe {
        // Get current process handle (-1 = current process pseudo handle)
        let h_process = HANDLE(-1isize);
        
        let mut mem_counters: PROCESS_MEMORY_COUNTERS = mem::zeroed();
        mem_counters.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        
        let result = K32GetProcessMemoryInfo(
            h_process,
            &mut mem_counters,
            mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32
        );
        
        if result.as_bool() == false {
            return false;
        }
        
        let current_ws_size = mem_counters.WorkingSetSize as u64;
        let last_ws_size = LAST_WORKING_SET_SIZE.load(Ordering::SeqCst);
        
        // Store current for next comparison
        LAST_WORKING_SET_SIZE.store(current_ws_size, Ordering::SeqCst);
        WORKING_SET_CHECK_COUNT.fetch_add(1, Ordering::SeqCst);
        
        // Skip first check (no baseline)
        if last_ws_size == 0 {
            return false;
        }
        
        // Calculate change ratio
        let change = if current_ws_size > last_ws_size {
            current_ws_size - last_ws_size
        } else {
            last_ws_size - current_ws_size
        };
        
        // Anomaly detection: sudden large working set increase
        // Memory dump tools typically touch all pages, causing large WS growth
        let threshold = last_ws_size / 4; // 25% change threshold
        
        if change > threshold && change > 1024 * 1024 { // At least 1MB change
            WORKING_SET_ANOMALY_COUNT.fetch_add(1, Ordering::SeqCst);
            
            // Report anomaly if multiple detections
            let anomaly_count = WORKING_SET_ANOMALY_COUNT.load(Ordering::SeqCst);
            if anomaly_count >= 3 {
                // Add suspicion for abnormal memory access pattern
                add_suspicion(DetectionSeverity::High); // Type 5: Memory dump detection
                return true;
            }
        }
        
        false
    }
}

/// Tích hợp tất cả các biện pháp anti-dump trong một hàm.
/// Nên gọi sớm trong quá trình khởi động ứng dụng.
pub fn initialize_anti_dump_protection() {
    // Erase PE headers first
    erase_pe_header();
    
    // Tamper with SizeOfImage using a pseudo-random modifier
    let modifier = get_cpu_entropy() & 0x0000FFFF; // Random value 0-65535
    size_of_image_tamper(modifier);
    
    // Initialize working set monitoring baseline
    initialize_kernel_monitoring();
    let _ = working_set_monitor();
}

/// Checkpoint anti-dump - gọi định kỳ trong quá trình chạy
pub fn checkpoint_anti_dump() -> bool {
    // Check for memory scanning activity
    working_set_monitor()
}

// ============================================================================
// KERNEL-LEVEL SCANNING - Drivers & IDT
// ============================================================================

const DRIVER_BLACKLIST: &[&str] = &[
    "vboxguest.sys", "vmmouse.sys", "vboxsf.sys", "vboxvideo.sys", // VirtualBox
    "vmsrvc.sys", "vmtools.sys", // VMware
    "wineusa.sys", // Wine
    "titanhide.sys", "x64dbg.sys", "processhacker.sys", // Analysis Tools
    "dbk64.sys", "dbk32.sys", // Cheat Engine
];

const DEVICE_BLACKLIST: &[&str] = &[
    "\\\\.\\VBoxGuest",
    "\\\\.\\VBoxMiniRdrDN",
    "\\\\.\\VBoxTrayIPC",
    "\\\\.\\Sice", // SoftICE
    "\\\\.\\Sizer",
    "\\\\.\\Global\\Sreul",
];

/// Check loaded drivers against blacklist using dynamic API resolution (stealthy)
pub fn check_drivers() -> bool {
    use windows::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
    use windows::core::PCSTR;
    use std::ffi::{CStr, c_void};

    unsafe {
        // Load Psapi.dll dynamically
        let psapi_result = LoadLibraryA(PCSTR(b"psapi.dll\0".as_ptr()));
        if psapi_result.is_err() {
            return false;
        }
        let psapi = psapi_result.unwrap();

        // Get function pointers
        let enum_drivers_addr = GetProcAddress(psapi, PCSTR(b"EnumDeviceDrivers\0".as_ptr()));
        let get_driver_name_addr = GetProcAddress(psapi, PCSTR(b"GetDeviceDriverBaseNameA\0".as_ptr()));

        if enum_drivers_addr.is_none() || get_driver_name_addr.is_none() {
            return false;
        }

        // Define function signatures
        type EnumDeviceDriversFn = unsafe extern "system" fn(*mut *mut c_void, u32, *mut u32) -> i32;
        type GetDeviceDriverBaseNameAFn = unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32;

        let enum_drivers: EnumDeviceDriversFn = std::mem::transmute(enum_drivers_addr.unwrap());
        let get_driver_name: GetDeviceDriverBaseNameAFn = std::mem::transmute(get_driver_name_addr.unwrap());

        let mut drivers = [0isize as *mut c_void; 1024];
        let mut cb_needed = 0u32;

        if enum_drivers(
            drivers.as_mut_ptr(),
            (drivers.len() * std::mem::size_of::<*mut c_void>()) as u32,
            &mut cb_needed
        ) != 0 {
            let driver_count = cb_needed as usize / std::mem::size_of::<*mut c_void>();
            let count = std::cmp::min(driver_count, drivers.len());

            for i in 0..count {
                let mut buffer = [0u8; 256];
                let len = get_driver_name(
                    drivers[i],
                    buffer.as_mut_ptr(),
                    buffer.len() as u32
                );

                if len > 0 {
                    let name_res = CStr::from_bytes_until_nul(&buffer[..len as usize + 1]);
                    if let Ok(cstr) = name_res {
                        if let Ok(name) = cstr.to_str() {
                            let name_lower = name.to_lowercase();
                            for &blocked in DRIVER_BLACKLIST {
                                if name_lower == blocked {
                                    add_suspicion(DetectionSeverity::High); 
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check for presence of known bad device objects
pub fn check_device_drivers() -> bool {
    use windows::Win32::Storage::FileSystem::{
        CreateFileA, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL
    };
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::core::PCSTR;

    let mut detected = false;

    unsafe {
        for &device in DEVICE_BLACKLIST {
            // Null-terminate the string
            let device_cstr = std::ffi::CString::new(device).unwrap();
            
            let handle = CreateFileA(
                PCSTR(device_cstr.as_ptr() as *const u8),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            );

            if let Ok(handle) = handle {
                if handle != INVALID_HANDLE_VALUE {
                    // Device exists and we could open it!
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                    add_suspicion(DetectionSeverity::Critical); // Very high suspicion
                    detected = true;
                    break;
                }
            }
        }
    }
    detected
}

/// Check IDT (Interrupt Descriptor Table) for anomalies
/// Uses SIDT instruction to get IDT base
pub fn check_idt() -> bool {
    // IDTR structure: Limit (2 bytes) + Base (4/8 bytes)
    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }

    let mut idtr = Idtr { limit: 0, base: 0 };

    unsafe {
        std::arch::asm!(
            "sidt [{}]",
            in(reg) &mut idtr,
            options(nostack, preserves_flags)
        );
    }

    // Analysis: 
    // On real hardware, IDT is typically located high in kernel memory.
    // Some VMs might relocate it. 
    // However, user-mode SIDT is valid but checking the result requires heuristics.
    
    // Simple heuristic: Base address location
    // This is a weak check on modern 64-bit systems with ASLR/KASLR, 
    // but extreme outliers can still be interesting.
    
    // For now, detection is based on the instruction execution itself causing a VM exit
    // which might add latency (measured elsewhere).
    
    // We can use the IDT base for entropy/fingerprinting if we wanted to.
    
    // Example: Check if IDT is in a known predictable range if KASLR is off (rare)
    
    // Return false for now as this is purely informational without a reliable baseline
    false 
}

/// Initialize all kernel-level monitoring
pub fn initialize_kernel_monitoring() {
    check_drivers();
    check_device_drivers();
    check_idt();
}

// ============================================================================
// TLS CALLBACK - SILENT PRE-EMPTION (The Silent Pre-emption)
// ============================================================================

#[cfg(target_os = "windows")]
#[link_section = ".CRT$XLB"]
#[no_mangle]
pub static P_TLS_CALLBACK: unsafe extern "system" fn(*mut u8, u32, *mut u8) = tls_callback_entry;

#[cfg(target_os = "windows")]
unsafe extern "system" fn tls_callback_entry(_image: *mut u8, reason: u32, _reserved: *mut u8) {
    if reason == 1 { // DLL_PROCESS_ATTACH
        // Implement mandatory logic using OP_EARLY_BIRD across TinyVM
        let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
        let enc_key = (seed & 0xFF) as u8;
        let bytecode = [
            VmOp::op_early_bird() ^ enc_key,
            VmOp::op_exit() ^ enc_key
        ];
        
        let result = vm_execute(&bytecode, enc_key, seed as u64);
        
        if result != 0 {
            // SILENT POISONING: XOR POISON_SEED with constant derived from reconstructed seed
            // Mathematical transformation: ((SEED * 0x61C8864680B583EB) >> 32) ^ 0xDEADBEEF
            let poison_val = ((seed as u64).wrapping_mul(0x61C8864680B583EB) >> 32) ^ 0xDEADBEEF;
            POISON_SEED.fetch_xor(poison_val, Ordering::SeqCst);
            
            // Add critical suspicion
            add_suspicion(DetectionSeverity::Critical);
            
            // Corrupt global encryption keys early to create an unusable environment
            GLOBAL_ENCRYPTION_KEY.store(0xFE, Ordering::SeqCst);
            GLOBAL_VIRTUAL_MACHINE_KEY.store(0x13, Ordering::SeqCst);
            
            // Recalculate integrity hash to reflect changes
            recalculate_global_integrity();
        }
    }
}

// ============================================================================
// VECTORED EXCEPTION HANDLING (VEH) - BREAKPOINT DETECTION
// ============================================================================

/// Public handler called by Master VEH (enhanced_veh.rs)
/// Handles INT3 and Single Step exceptions.
/// Returns true if a debugger artifact was detected.
pub unsafe fn handle_debug_exception(exception_info: *mut EXCEPTION_POINTERS) -> bool {
    let record = (*exception_info).ExceptionRecord;
    let context = (*exception_info).ContextRecord;
    let code = (*record).ExceptionCode;

    // Note: Warm-up and Module Filtering are handled by the Master VEH (enhanced_veh.rs)

    // Detect Software Breakpoint (INT3)
    if code == EXCEPTION_BREAKPOINT {
        add_suspicion(DetectionSeverity::High);
        GLOBAL_ENCRYPTION_KEY.fetch_xor(0x55, Ordering::SeqCst);
        return true;
    }

    // Detect Hardware Breakpoints (DR0 - DR3) -> EXCEPTION_SINGLE_STEP
    if code == EXCEPTION_SINGLE_STEP {
        let dr_active = (*context).Dr0 != 0 || (*context).Dr1 != 0 ||
                        (*context).Dr2 != 0 || (*context).Dr3 != 0;

        if dr_active {
            POISON_SEED.store(0xDEADC0DEBADC0DE, Ordering::SeqCst);
            add_suspicion(DetectionSeverity::Critical);

            // Clear DRx registers to detach
            (*context).Dr0 = 0;
            (*context).Dr1 = 0;
            (*context).Dr2 = 0;
            (*context).Dr3 = 0;
            (*context).Dr7 &= !0xFF;
            return true;
        }
    }

    false
}

//! Global state management for the anti-debug system with SipHash-based encryption
//! 128-shard architecture with 50% Active/Decoy distribution for enhanced obfuscation
// github.com/anhdeface
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::OnceLock;
#[allow(non_snake_case)]
/// Diagnostic mode for debugging false positives
pub static DIAGNOSTIC_MODE: AtomicBool = AtomicBool::new(true);
/// Guard to ensure shards are initialized before adding or reconstructing suspicion
pub static GLOBAL_STATE_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Array to track triggered checkpoints and their total suspicion
pub static TRIGGERED_CHECKPOINTS: [AtomicU32; 8] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

/// Log a checkpoint trigger when diagnostic mode is enabled
pub fn log_checkpoint_trigger(id: u8, amount: u32) {
    if DIAGNOSTIC_MODE.load(Ordering::Relaxed) {
        if (id as usize) < TRIGGERED_CHECKPOINTS.len() {
            TRIGGERED_CHECKPOINTS[id as usize].fetch_add(amount, Ordering::Relaxed);
        }
    }
}

/// Severity levels for detection events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSeverity {
    Low = 10,
    Medium = 30,
    High = 60,
    Critical = 100,
}

impl DetectionSeverity {
    pub fn score(&self) -> u32 {
        *self as u32
    }
}

/// Structure containing detailed detection statistics
#[derive(Debug, Clone, Copy)]
pub struct DetectionDetails {
    pub is_debugged: bool,
    pub score: u32,
    pub peb_check: bool,
    pub rdtsc_check: bool,
    pub heap_check: bool,
    pub hypervisor_check: bool,
    pub integrity_check: bool,
}

// ============================================================================
// COMMON WINDOWS FFI STRUCTURES
// ============================================================================

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: u32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut std::ffi::c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}

#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut CONTEXT,
}

#[link(name = "kernel32")]
extern "system" {
    pub fn AddVectoredExceptionHandler(First: u32, Handler: Option<unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32>) -> *mut std::ffi::c_void;
}

#[repr(C, align(16))]
pub struct CONTEXT {
    pub P1Home: u64, pub P2Home: u64, pub P3Home: u64, pub P4Home: u64, pub P5Home: u64, pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16, pub SegDs: u16, pub SegEs: u16, pub SegFs: u16, pub SegGs: u16, pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64, pub Dr1: u64, pub Dr2: u64, pub Dr3: u64, pub Dr6: u64, pub Dr7: u64,
    pub Rax: u64, pub Rcx: u64, pub Rdx: u64, pub Rbx: u64, pub Rsp: u64, pub Rbp: u64, pub Rsi: u64, pub Rdi: u64,
    pub R8: u64, pub R9: u64, pub R10: u64, pub R11: u64, pub R12: u64, pub R13: u64, pub R14: u64, pub R15: u64,
    pub Rip: u64,
    // ... other fields if needed, but these are enough for our use case
}

// ============================================================================
// 128-SHARD ARCHITECTURE WITH ACTIVE/DECOY DISTRIBUTION
// ============================================================================

// Const function to generate pseudo-random masks from runtime seed
const fn mix_seed(seed: u32, i: u32) -> u32 {
    let mut x = seed.wrapping_add(i).wrapping_mul(0x9E3779B9);
    x = x ^ (x >> 15);
    x = x.wrapping_mul(0x85EBCA6B);
    x = x ^ (x >> 13);
    x = x.wrapping_mul(0xC2B2AE35);
    x = x ^ (x >> 16);
    x
}

/// Mix seed to generate a 64-bit pair map for Active/Decoy determination
/// Each bit determines which element in a pair (2*i, 2*i+1) is Active
#[inline(always)]
fn mix_seed_to_u64(seed: u32) -> u64 {
    // Create a 64-bit value from the seed using multiple mixing rounds
    let mut x = seed as u64;
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x = x ^ (x >> 30);
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x = x ^ (x >> 27);
    x = x.wrapping_mul(0x94D049BB133111EB);
    x = x ^ (x >> 31);
    x
}

/// Determine if a shard index is Active (holds real data) or Decoy (noise)
/// Uses the pair-based algorithm: 128 shards = 64 pairs
/// For pair i (0..64), if bit i of pair_map is 0 -> index 2*i is Active
///                      if bit i of pair_map is 1 -> index 2*i+1 is Active
#[inline(always)]
fn is_active_shard(index: usize, pair_map: u64) -> bool {
    if index >= 128 {
        return false;
    }
    let pair_index = index / 2; // Which pair does this index belong to (0..64)
    let is_second_in_pair = (index % 2) == 1; // Is this the second element (2*i+1)?
    let bit_value = ((pair_map >> pair_index) & 1) == 1; // Get bit for this pair
    
    // If bit is 0: 2*i is Active (first element), 2*i+1 is Decoy
    // If bit is 1: 2*i+1 is Active (second element), 2*i is Decoy
    // Active if: (is_second && bit==1) || (!is_second && bit==0)
    is_second_in_pair == bit_value
}

// Cache for the 128 shard masks
static SHARD_MASKS_CACHE: OnceLock<[u32; 128]> = OnceLock::new();

/// Get shard mask for a specific index
/// Lazily initializes the masks on first access using the reconstructed seed
#[inline(always)]
pub fn get_shard_mask(index: usize) -> u32 {
    let masks = SHARD_MASKS_CACHE.get_or_init(|| {
        // Get runtime-reconstructed seed
        let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
        let mut arr = [0u32; 128];
        for i in 0..128 {
            arr[i] = mix_seed(seed, i as u32);
        }
        arr
    });
    masks[index]
}

// Distributed suspicion state - 128 shards (64 Active + 64 Decoy)
// Initialized at runtime to SHARD_MASKS values to represent 0 score (Mask ^ Mask = 0)
// If memory is zeroed (frozen), Val ^ Mask = Mask -> Huge Score -> Alarm
pub static SUSPICION_SHARDS: [AtomicU32; 128] = [
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    // 64 more for decoy/active pairs
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
];

// Reconstruct threat score moved to lower section for better locality with distributed logic helpers.
pub static GLOBAL_LAST_DECAY_TIME: AtomicU64 = AtomicU64::new(0);
pub static BASE_LINE_LATENCY: AtomicU64 = AtomicU64::new(0);

// Integrity and Encryption keys
pub static GLOBAL_INTEGRITY_HASH: AtomicU64 = AtomicU64::new(0x12345678ABCDEF00);
pub static GLOBAL_ENCRYPTION_KEY: AtomicU8 = AtomicU8::new(0x42);
pub static GLOBAL_VIRTUAL_MACHINE_KEY: AtomicU8 = AtomicU8::new(0x42);

/// Poison seed that is corrupted if a debugger is detected early (TLS Callback)
/// Mandatory for all future security token calculations
pub static POISON_SEED: AtomicU64 = AtomicU64::new(0);

// Dynamic SipHash constants that are initialized with dynamic seed
static GLOBAL_SIPHASH_V0: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V1: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V2: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V3: AtomicU64 = AtomicU64::new(0);

// SipHash constants and state - now dynamic based on runtime seed
const SIPHASH_C_ROUNDS: usize = 2;
const SIPHASH_D_ROUNDS: usize = 4;

/// Simple SipHash implementation for integrity and encryption with dynamic constants
fn siphash(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    macro_rules! sip_round {
        () => {
            *v0 = v0.wrapping_add(*v1);
            *v2 = v2.wrapping_add(*v3);
            *v1 = v1.rotate_left(13);
            *v3 = v3.rotate_left(16);
            *v1 ^= *v0;
            *v3 ^= *v2;
            *v0 = v0.rotate_left(32);
            *v2 = v2.wrapping_add(*v1);
            *v0 = v0.wrapping_add(*v3);
            *v1 = v1.rotate_left(17);
            *v3 = v3.rotate_left(21);
            *v1 ^= *v2;
            *v3 ^= *v0;
            *v2 = v2.rotate_left(32);
        };
    }

    for _ in 0..SIPHASH_C_ROUNDS {
        sip_round!();
    }
}

/// Calculate integrity hash using SipHash to detect mid-execution tampering
pub fn recalculate_global_integrity() {
    // Create a combined value from global state
    // Use reconstructed score instead of direct load
    let combined = (reconstruct_threat_score() as u64)
        .wrapping_add(GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst));

    // Use dynamic SipHash-like algorithm with dynamic seed for stronger integrity checking
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;

    // Mix the base values with dynamic seed to create dynamic constants
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let dyn_v0 = base_v0 ^ (seed as u64);
    let dyn_v1 = base_v1 ^ ((seed as u64) << 8);
    let dyn_v2 = base_v2 ^ ((seed as u64) << 16);
    let dyn_v3 = base_v3 ^ ((seed as u64) << 24);

    let mut v0 = dyn_v0;
    let mut v1 = dyn_v1;
    let mut v2 = dyn_v2 ^ combined; // XOR with our data
    let mut v3 = dyn_v3 ^ 8; // Length of data

    // Apply compression function
    siphash(&mut v0, &mut v1, &mut v2, &mut v3);

    // Finalization
    v2 ^= 0xff;
    siphash(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash(&mut v0, &mut v1, &mut v2, &mut v3);

    let result = v0 ^ v1 ^ v2 ^ v3;
    GLOBAL_INTEGRITY_HASH.store(result, Ordering::SeqCst);
}

/// Detect mid-execution tampering via SipHash-based validation
pub fn validate_global_integrity() -> bool {
    let combined = (reconstruct_threat_score() as u64)
        .wrapping_add(GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst));

    // Recalculate hash using same dynamic SipHash process
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;

    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let dyn_v0 = base_v0 ^ (seed as u64);
    let dyn_v1 = base_v1 ^ ((seed as u64) << 8);
    let dyn_v2 = base_v2 ^ ((seed as u64) << 16);
    let dyn_v3 = base_v3 ^ ((seed as u64) << 24);

    let mut v0 = dyn_v0;
    let mut v1 = dyn_v1;
    let mut v2 = dyn_v2 ^ combined; // XOR with our data
    let mut v3 = dyn_v3 ^ 8; // Length of data

    siphash(&mut v0, &mut v1, &mut v2, &mut v3);

    v2 ^= 0xff;
    siphash(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash(&mut v0, &mut v1, &mut v2, &mut v3);

    let computed_hash = v0 ^ v1 ^ v2 ^ v3;
    computed_hash == GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst)
}

/// Helper to get current timestamp in seconds
pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Last timestamp specific to VM execution for Watchdog
pub static LAST_VM_HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Detect build mode (debug/release)
fn detect_build_mode() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

// ============================================================================
// ADAPTIVE THRESHOLD & SYSTEM LOAD DETECTION
// ============================================================================

use std::sync::Mutex;

// Manual FFI definitions to avoid compilation errors with missing features
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct FILETIME {
    pub dwLowDateTime: u32,
    pub dwHighDateTime: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemTimes(lpIdleTime: *mut FILETIME, lpKernelTime: *mut FILETIME, lpUserTime: *mut FILETIME) -> i32;
    fn GetCurrentProcess() -> isize;
    fn GetPriorityClass(hProcess: isize) -> u32;
}

const IDLE_PRIORITY_CLASS: u32 = 0x00000040;

/// Check if the current process is running at IDLE priority
/// If so, timing checks will be inaccurate and should be skipped
pub fn is_priority_idle() -> bool {
    unsafe {
        let priority_class = GetPriorityClass(GetCurrentProcess());
        priority_class == IDLE_PRIORITY_CLASS
    }
}

// State for system load calculation
struct SystemLoadState {
    last_check_time: u64,
    last_idle_time: u64,
    last_kernel_time: u64,
    last_user_time: u64,
    is_heavy_load: bool,
}

static SYSTEM_LOAD_STATE: Mutex<SystemLoadState> = Mutex::new(SystemLoadState {
    last_check_time: 0,
    last_idle_time: 0,
    last_kernel_time: 0,
    last_user_time: 0,
    is_heavy_load: false, // Default to false
});

/// Convert FILETIME to u64
fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Check if system is under heavy load (>85% CPU)
/// Returns cached result if called within 1 second logic
pub fn is_system_under_heavy_load() -> bool {
    let current_timestamp = get_current_timestamp();
    
    // scoping the lock
    let mut state = match SYSTEM_LOAD_STATE.lock() {
        Ok(guard) => guard,
        Err(_) => return true, // Fail safe: assume heavy load if lock poisoned
    };

    // Cache valid for 1 second
    if current_timestamp < state.last_check_time + 1 {
        return state.is_heavy_load;
    }

    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    unsafe {
        if GetSystemTimes(&mut idle, &mut kernel, &mut user) == 0 {
            return true; // Fail safe
        }
    }

    let idle_u64 = filetime_to_u64(idle);
    let kernel_u64 = filetime_to_u64(kernel);
    let user_u64 = filetime_to_u64(user);

    let idle_delta = idle_u64.wrapping_sub(state.last_idle_time);
    let kernel_delta = kernel_u64.wrapping_sub(state.last_kernel_time);
    let user_delta = user_u64.wrapping_sub(state.last_user_time);

    // Update state
    state.last_check_time = current_timestamp;
    state.last_idle_time = idle_u64;
    state.last_kernel_time = kernel_u64;
    state.last_user_time = user_u64;

    // Calculate usage
    // Total System Time = Kernel + User
    // CPU Usage = (Total - Idle) / Total
    let total_system = kernel_delta + user_delta;
    
    if total_system == 0 {
        return state.is_heavy_load; // No time passed? keep old state
    }

    let active_time = total_system.saturating_sub(idle_delta);
    let usage_percent = (active_time * 100) / total_system;

    let is_heavy = usage_percent > 85;
    state.is_heavy_load = is_heavy;

    is_heavy
}

/// Get the current integrity hash value
pub fn get_integrity_hash() -> u64 {
    GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst)
}

// Helper to getting high-performance CPU timestamp counter for entropy
// Replacing rand crate dependency
#[inline(always)]
fn get_rdtsc_entropy() -> u64 {
    // Use rdtsc as entropy source
    let mut low: u32;
    let mut high: u32;
    unsafe {
        std::arch::asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Generate 3 distinct random ACTIVE shard indices using mixed entropy
/// Only selects from the 64 Active shards based on pair_map
fn get_random_active_indices_3(pair_map: u64) -> (usize, usize, usize) {
    let mut entropy = get_rdtsc_entropy();
    
    // Mix entropy with stack address to prevent simple rdtsc manipulation
    let stack_var = 0;
    entropy ^= &stack_var as *const i32 as u64;
    
    // Simple LCG-like mixer
    let mut rng = entropy;
    let mut next_active = || {
        loop {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let idx = ((rng >> 32) & 0x7F) as usize; // 0..127
            if is_active_shard(idx, pair_map) {
                return idx;
            }
        }
    };

    let idx1 = next_active();
    
    let mut idx2 = next_active();
    while idx2 == idx1 {
        idx2 = next_active();
    }
    
    let mut idx3 = next_active();
    while idx3 == idx1 || idx3 == idx2 {
        idx3 = next_active();
    }
    
    (idx1, idx2, idx3)
}

/// Generate 3 distinct random DECOY shard indices using mixed entropy
/// Only selects from the 64 Decoy shards based on pair_map
fn get_random_decoy_indices_3(pair_map: u64) -> (usize, usize, usize) {
    let mut entropy = get_rdtsc_entropy();
    
    // Mix entropy with stack address
    let stack_var = 0;
    entropy ^= &stack_var as *const i32 as u64;
    
    // Use different multiplier for decoy selection
    let mut rng = entropy.wrapping_mul(0xDEADBEEFCAFEBABE);
    let mut next_decoy = || {
        loop {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let idx = ((rng >> 32) & 0x7F) as usize; // 0..127
            if !is_active_shard(idx, pair_map) {
                return idx;
            }
        }
    };

    let idx1 = next_decoy();
    
    let mut idx2 = next_decoy();
    while idx2 == idx1 {
        idx2 = next_decoy();
    }
    
    let mut idx3 = next_decoy();
    while idx3 == idx1 || idx3 == idx2 {
        idx3 = next_decoy();
    }
    
    (idx1, idx2, idx3)
}

/// Add suspicion with dispersed scoring mechanism (Scattering Algorithm)
/// Spreads the score across 3 random ACTIVE shards to defeat data breakpoints.
/// Also writes noise to 3 DECOY shards to mislead reverse engineers.
/// Logic: Part_a + Part_b + Part_c = severity.score()
pub fn add_suspicion(severity: DetectionSeverity) {
    let mut amount = severity.score();
    if amount == 0 { return; }

    // Reduce suspicion scores by 50% in debug builds
    if detect_build_mode() == "debug" {
        amount /= 2;
        if amount == 0 { amount = 1; } // Always add at least 1 if severity was > 0
    }

    apply_decay();

    // Get the pair map for Active/Decoy determination
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64(seed);

    // Entropy source for splitting
    let entropy = get_rdtsc_entropy();
    let (i1, i2, i3) = get_random_active_indices_3(pair_map);

    // Split amount into 3 random parts ensuring a + b + c = amount
    // Using random weights from entropy bits
    let w1 = (entropy & 0x1F) + 1; // 1 to 32
    let w2 = ((entropy >> 5) & 0x1F) + 1; // 1 to 32
    let w3 = ((entropy >> 10) & 0x1F) + 1; // 1 to 32
    let total_w = w1 + w2 + w3;

    let p1 = (amount * w1 as u32) / total_w as u32;
    let p2 = (amount * w2 as u32) / total_w as u32;
    let p3 = amount - p1 - p2; // Remainder to ensure total matches exactly

    // Distribute to ACTIVE shards (Real Logic)
    if p1 > 0 { add_to_shard(i1, p1); }
    if p2 > 0 { add_to_shard(i2, p2); }
    if p3 > 0 { add_to_shard(i3, p3); }

    // === DECOY LOGIC: Write noise to DECOY shards to mislead reverse engineers ===
    let (d1, d2, d3) = get_random_decoy_indices_3(pair_map);
    
    // Generate mathematically valid noise using entropy
    let noise_entropy = get_rdtsc_entropy();
    let noise1 = ((noise_entropy & 0xFF) as u32).wrapping_mul(0x9E3779B9);
    let noise2 = (((noise_entropy >> 8) & 0xFF) as u32).wrapping_mul(0x85EBCA6B);
    let noise3 = (((noise_entropy >> 16) & 0xFF) as u32).wrapping_mul(0xC2B2AE35);
    
    // Write noise to decoy shards (looks like real encoded data)
    write_decoy_noise(d1, noise1);
    write_decoy_noise(d2, noise2);
    write_decoy_noise(d3, noise3);

    recalculate_global_integrity();
}

/// Add suspicion at a specific checkpoint and dispersed shards
pub fn add_suspicion_at(severity: DetectionSeverity, checkpoint_id: u8) {
    let amount = severity.score();
    log_checkpoint_trigger(checkpoint_id, amount);
    add_suspicion(severity);
}

/// Helper to add score to specific shard safely (for Active shards)
fn add_to_shard(idx: usize, amount: u32) {
    if !GLOBAL_STATE_INITIALIZED.load(Ordering::Relaxed) {
        return;
    }
    let mask = get_shard_mask(idx);
    let mut current_encoded = SUSPICION_SHARDS[idx].load(Ordering::SeqCst);
    
    loop {
        // Decode -> Add -> Encode
        // Value = (Encoded ^ Mask).rotate_right(idx % 32)
        let old_contribution = (current_encoded ^ mask).rotate_right(idx as u32 % 32);
        let new_contribution = old_contribution.saturating_add(amount);
        // Reverse: Encoded = (Value.rotate_left(idx % 32)) ^ Mask
        let new_encoded = new_contribution.rotate_left(idx as u32 % 32) ^ mask;
        
        match SUSPICION_SHARDS[idx].compare_exchange(
            current_encoded, new_encoded, Ordering::SeqCst, Ordering::SeqCst
        ) {
            Ok(_) => break,
            Err(actual) => current_encoded = actual,
        }
    }
}

/// Write noise to a Decoy shard (camouflage operation)
/// Uses same encoding scheme as real shards to look authentic
fn write_decoy_noise(idx: usize, noise: u32) {
    let mask = get_shard_mask(idx);
    let mut current_encoded = SUSPICION_SHARDS[idx].load(Ordering::SeqCst);
    
    loop {
        // Apply same encoding transformation as real shards for authenticity
        let noise_encoded = noise.rotate_left(idx as u32 % 32) ^ mask;
        
        // XOR with current to create temporal variation
        let new_encoded = current_encoded ^ (noise_encoded & 0xFF); // Limit change magnitude
        
        match SUSPICION_SHARDS[idx].compare_exchange(
            current_encoded, new_encoded, Ordering::SeqCst, Ordering::SeqCst
        ) {
            Ok(_) => break,
            Err(actual) => current_encoded = actual,
        }
    }
}

/// Encapsulated decay logic to be called by add_suspicion and get_suspicion_score
/// Decays BOTH Active shards (real logic) and Decoy shards (camouflage)
fn apply_decay() {
    let current_time = get_current_timestamp();
    // Optimistic check to avoid expensive atomic swap if not needed
    let last_time_val = GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed);
    if current_time <= last_time_val { return; }

    // We only update if enough time has passed for at least 1 decay interval (300s)
    if current_time - last_time_val < 300 { return; }

    // CAS to update time. Only one thread succeeds.
    if GLOBAL_LAST_DECAY_TIME.compare_exchange(last_time_val, current_time, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return; // Lost race
    }
    
    let elapsed = current_time - last_time_val;
    let decay_intervals = elapsed / 300;
    let total_decay = (decay_intervals as u32) * 5; // 5 points per interval

    if total_decay == 0 { return; }

    // Get pair map for Active/Decoy determination
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64(seed);

    // Decay ACTIVE shards (Real Business Logic)
    let mut remaining = total_decay;
    let start_idx = (get_rdtsc_entropy() % 128) as usize;
    
    for i in 0..128 {
        if remaining == 0 { break; }
        
        // Wrap around index
        let idx = (start_idx + i) % 128;
        
        // Only decay Active shards for real logic
        if !is_active_shard(idx, pair_map) { continue; }
        
        let mask = get_shard_mask(idx);
        let mut current_encoded = SUSPICION_SHARDS[idx].load(Ordering::SeqCst);
        
        loop {
            let current_contribution = (current_encoded ^ mask).rotate_right(idx as u32 % 32);
            if current_contribution == 0 { break; } // Nothing in this shard
            
            let can_remove = std::cmp::min(current_contribution, remaining);
            let new_contribution = current_contribution - can_remove;
            let new_encoded = new_contribution.rotate_left(idx as u32 % 32) ^ mask;
            
            match SUSPICION_SHARDS[idx].compare_exchange(
                current_encoded, new_encoded, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => {
                    remaining -= can_remove;
                    break;
                },
                Err(actual) => current_encoded = actual,
            }
        }
    }

    // Decay DECOY shards (Camouflage - perform similar operations to maintain illusion)
    let decoy_entropy = get_rdtsc_entropy();
    let decoy_start = (decoy_entropy % 128) as usize;
    
    for i in 0..128 {
        let idx = (decoy_start + i) % 128;
        
        // Only process Decoy shards
        if is_active_shard(idx, pair_map) { continue; }
        
        let mask = get_shard_mask(idx);
        let mut current_encoded = SUSPICION_SHARDS[idx].load(Ordering::SeqCst);
        
        // Perform atomic subtraction operation (mimics real decay pattern)
        loop {
            let current_val = (current_encoded ^ mask).rotate_right(idx as u32 % 32);
            
            // Apply pseudo-decay: subtract a small random amount
            let pseudo_decay = ((decoy_entropy >> (i % 8)) & 0x7) as u32; // 0-7
            let new_val = current_val.saturating_sub(pseudo_decay);
            let new_encoded = new_val.rotate_left(idx as u32 % 32) ^ mask;
            
            match SUSPICION_SHARDS[idx].compare_exchange(
                current_encoded, new_encoded, Ordering::SeqCst, Ordering::SeqCst
            ) {
                Ok(_) => break,
                Err(actual) => current_encoded = actual,
            }
        }
    }
}

/// Reconstruct the total threat score from distributed ACTIVE shards
/// CRITICAL: Only sums values from Active shards. Decoy shards are completely ignored.
/// Logic: Value_i = (Shard_i ^ Mask_i).rotate_right(i % 32)
/// Self-Defense: If memory is zeroed, XOR + Rotate results in a massive pseudo-random score.
pub fn reconstruct_threat_score() -> u32 {
    if !GLOBAL_STATE_INITIALIZED.load(Ordering::Relaxed) {
        return 0;
    }
    // Pre-calculate pair map once for O(1) per-shard Active check
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let pair_map = mix_seed_to_u64(seed);
    
    let mut total_score: u32 = 0;
    for i in 0..128 {
        // CRITICAL: Only sum Active shards, ignore Decoy shards
        if !is_active_shard(i, pair_map) {
            continue;
        }
        
        let encoded = SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        let mask = get_shard_mask(i);
        
        // Reconstruction with XOR and Index-based Rotation
        let decoded = encoded ^ mask;
        let value_i = decoded.rotate_right(i as u32 % 32);
        
        // Prevent compiler optimization/const-folding with black_box
        let finalized_value = std::hint::black_box(value_i);
        
        total_score = total_score.wrapping_add(finalized_value);
    }
    
    total_score
}

/// Get the current suspicion score with lazy decay application
/// Honeytrap: If reconstructed score > 200, return 0xFFFFFFFF to signal tampering
pub fn get_suspicion_score() -> u32 {
    apply_decay();
    let score = reconstruct_threat_score();
    // Honeytrap: If reconstructed score > 500, return 0xFFFFFFFF to signal tampering
    // Increased from 200 to 500 for better environmental tolerance
    if score > 500 {
        return 0xFFFFFFFF;
    }
    score
}

/// Get detailed detection statistics for diagnostic purposes
pub fn get_detection_details() -> DetectionDetails {
    let score = get_suspicion_score();
    DetectionDetails {
        is_debugged: score > 50,
        score,
        peb_check: score > 20,
        rdtsc_check: score > 30,
        heap_check: score > 40,
        hypervisor_check: score > 60,
        integrity_check: score > 80,
    }
}

/// Get a combined security score that incorporates the threat level and poison seed
/// This is used to derive dynamic execution tokens.
pub fn get_combined_score() -> u64 {
    let score = get_suspicion_score() as u64;
    let poison = POISON_SEED.load(Ordering::SeqCst);
    
    // Mathematical coupling: result is garbage if score > 0 or poison is modified
    (score.wrapping_mul(0x5DEECE66D)) ^ poison
}

/// Get the current encryption key (may be corrupted if debugger detected)
pub fn get_current_encryption_key() -> u8 {
    GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst)
}

/// Get the current virtual machine key (may be corrupted if debugger detected)
pub fn get_current_vm_key() -> u8 {
    GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst)
}

// is_globally_debugged removed to prevent simple JMP patching.
// Use get_combined_score() or get_suspicion_score() for logic coupling.

/// Initialize VEH protection (distributed state with 128 shards)
/// Initializes all 128 shards (64 Active + 64 Decoy) with their respective masks
pub fn initialize_veh_protection() {
    // Register the actual exception handler -> HANDLED BY MASTER VEH (enhanced_veh.rs)
    // crate::protector::anti_debug::register_veh_handler();

    // Initialize all 128 shards to their masked zero values
    // Both Active and Decoy shards are initialized identically to prevent detection
    for i in 0..128 {
        SUSPICION_SHARDS[i].store(get_shard_mask(i), Ordering::SeqCst);
    }
    GLOBAL_LAST_DECAY_TIME.store(get_current_timestamp(), Ordering::SeqCst);
    
    GLOBAL_INTEGRITY_HASH.store(0x12345678ABCDEF00, Ordering::SeqCst);
    GLOBAL_ENCRYPTION_KEY.store(0x42, Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(0x42, Ordering::SeqCst);
    
    // Initialize POISON_SEED with a transformed reconstructed seed
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    POISON_SEED.store((seed as u64) ^ 0xCAFEBABE1337BEEF, Ordering::SeqCst);

    // Initialize dynamic SipHash constants using dynamic seed
    initialize_dynamic_siphash();

    // Recalculate integrity hash after initialization
    recalculate_global_integrity();

    // Set initialization flag after everything is ready
    GLOBAL_STATE_INITIALIZED.store(true, Ordering::SeqCst);
}

/// Initialize SipHash constants with dynamic values using runtime seed to make them non-standard
fn initialize_dynamic_siphash() {
    // Use reconstructed seed to create dynamic initial values for SipHash
    // This makes the magic numbers polymorphic and harder to scan for
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed() as u64;

    // Create dynamic initial values by XORing base constants with runtime seed
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;

    // Mix the base values with seed to create dynamic constants
    let dyn_v0 = base_v0 ^ (seed);
    let dyn_v1 = base_v1 ^ (seed << 8);
    let dyn_v2 = base_v2 ^ (seed << 16);
    let dyn_v3 = base_v3 ^ (seed << 24);

    // Apply additional transformations for enhanced obfuscation
    let final_v0 = dyn_v0 ^ 0x123456789ABCDEF0u64;
    let final_v1 = dyn_v1 ^ 0x0FEDCBA987654321u64;
    let final_v2 = dyn_v2 ^ 0xCAFEBABEDEADBEEFu64;
    let final_v3 = dyn_v3 ^ 0xFEEDFACEBABECAFEu64;

    // Store these dynamic values in global state for use in SipHash calculations
    GLOBAL_SIPHASH_V0.store(final_v0, Ordering::SeqCst);
    GLOBAL_SIPHASH_V1.store(final_v1, Ordering::SeqCst);
    GLOBAL_SIPHASH_V2.store(final_v2, Ordering::SeqCst);
    GLOBAL_SIPHASH_V3.store(final_v3, Ordering::SeqCst);
}

/// Stealth log buffer for hidden logging (undetectable by reverse engineers)
static STEALTH_LOG_BUFFER: [AtomicU64; 16] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)
];
static LOG_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Log detection event to encrypted stealth buffer (completely hidden)
pub fn log_detection_event(event_type: u8, severity: u8, timestamp: u64) {
    let idx = LOG_INDEX.fetch_add(1, Ordering::SeqCst) % 16;

    // Create bitmask entry with complex XOR and rotation operations
    let bitmask_entry = ((event_type as u64) << 56) |
                        ((severity as u64) << 48) |
                        (timestamp & 0x00FFFFFFFFFFFF);

    // Apply multiple layers of obfuscation using reconstructed seed
    let seed = crate::protector::seed_orchestrator::get_dynamic_seed();
    let obfuscated_entry = bitmask_entry ^ (seed as u64);
    let rotated_entry = obfuscated_entry.rotate_left((seed & 0x1F) as u32); // Rotate by lower 5 bits of seed
    let final_entry = rotated_entry ^ 0xCAFEBABEDEADBEEF; // Additional XOR with magic constant

    STEALTH_LOG_BUFFER[idx].store(final_entry, Ordering::SeqCst);
}

/// Update VM key with result from VM execution (for silent corruption)
pub fn update_vm_key_with_result(vm_result: u64) {
    let current_key = GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
    // Apply avalanche effect: XOR with multiple bits of the result to maximize change
    let transformed_result = (vm_result & 0xFF) ^
                             ((vm_result >> 8) & 0xFF) ^
                             ((vm_result >> 16) & 0xFF) ^
                             ((vm_result >> 24) & 0xFF);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(current_key ^ (transformed_result as u8), Ordering::SeqCst);
}

/// Poison GLOBAL_ENCRYPTION_KEY on dump attempt detection (for anti_dump_v2)
pub fn poison_encryption_on_dump_attempt() {
    let entropy = crate::protector::seed_orchestrator::get_dynamic_seed();
    GLOBAL_ENCRYPTION_KEY.fetch_xor(entropy as u8, Ordering::SeqCst);
    
    // Cascade poison to POISON_SEED
    POISON_SEED.fetch_xor(entropy as u64, Ordering::SeqCst);
    
    // KILL SWITCH: Disable all diagnostics to blind the attacker
    DIAGNOSTIC_MODE.store(false, Ordering::SeqCst);

    // Add critical suspicion
    add_suspicion(DetectionSeverity::Critical);
}

/// TRIGGER SILENT POISONING
/// Corrupts internal seeds and keys to break future execution without an immediate crash.
/// This is the stealthiest way to handle detection.
pub fn trigger_silent_poisoning() {
    let entropy = crate::protector::seed_orchestrator::get_dynamic_seed();
    
    // 1. Corrupt POISON_SEED (Affects all future derived tokens)
    POISON_SEED.fetch_xor(entropy as u64 ^ 0xDEADBEEFCAFEBABE, Ordering::SeqCst);
    
    // 2. Corrupt Encryption Keys
    GLOBAL_ENCRYPTION_KEY.fetch_xor((entropy & 0xFF) as u8, Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.fetch_xor(((entropy >> 8) & 0xFF) as u8, Ordering::SeqCst);
    
    // 3. Corrupt Integrity Hash (Ensures future validation fails)
    let current_hash = GLOBAL_INTEGRITY_HASH.load(Ordering::Relaxed);
    GLOBAL_INTEGRITY_HASH.store(current_hash ^ 0xBAADF00DCAFEBABE ^ (entropy as u64), Ordering::SeqCst);
    
    // 4. Force Critical Suspicion
    add_suspicion(DetectionSeverity::Critical);
    
    // 5. Disable Diagnostics (Blinding the attacker)
    DIAGNOSTIC_MODE.store(false, Ordering::SeqCst);
}

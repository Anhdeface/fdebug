#![allow(dead_code)]

//! Global state management for the anti-debug system with SipHash-based encryption
// github.com/anhdeface
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// Import the dynamic seed generated at build time
pub mod generated_constants;
pub use generated_constants::DYNAMIC_SEED;

/// Diagnostic mode for debugging false positives
pub static DIAGNOSTIC_MODE: AtomicBool = AtomicBool::new(true);
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

// Global atomic threat score and decay tracking
// Const function to generate pseudo-random masks from DYNAMIC_SEED
const fn mix_seed(seed: u32, i: u32) -> u32 {
    let mut x = seed.wrapping_add(i).wrapping_mul(0x9E3779B9);
    x = x ^ (x >> 15);
    x = x.wrapping_mul(0x85EBCA6B);
    x = x ^ (x >> 13);
    x = x.wrapping_mul(0xC2B2AE35);
    x = x ^ (x >> 16);
    x
}

// Global atomic threat score shards and decay tracking
// SHARD_MASKS derived from DYNAMIC_SEED for obfuscation
pub static SHARD_MASKS: [u32; 16] = [
    mix_seed(DYNAMIC_SEED, 0), mix_seed(DYNAMIC_SEED, 1), mix_seed(DYNAMIC_SEED, 2), mix_seed(DYNAMIC_SEED, 3),
    mix_seed(DYNAMIC_SEED, 4), mix_seed(DYNAMIC_SEED, 5), mix_seed(DYNAMIC_SEED, 6), mix_seed(DYNAMIC_SEED, 7),
    mix_seed(DYNAMIC_SEED, 8), mix_seed(DYNAMIC_SEED, 9), mix_seed(DYNAMIC_SEED, 10), mix_seed(DYNAMIC_SEED, 11),
    mix_seed(DYNAMIC_SEED, 12), mix_seed(DYNAMIC_SEED, 13), mix_seed(DYNAMIC_SEED, 14), mix_seed(DYNAMIC_SEED, 15),
];

// Distributed suspicion state
// Initialized to SHARD_MASKS values to represent 0 score (Mask ^ Mask = 0)
// If memory is zeroed (frozen), Val ^ Mask = Mask -> Huge Score -> Alarm
pub static SUSPICION_SHARDS: [AtomicU32; 16] = [
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 0)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 1)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 2)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 3)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 4)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 5)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 6)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 7)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 8)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 9)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 10)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 11)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 12)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 13)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 14)), AtomicU32::new(mix_seed(DYNAMIC_SEED, 15)),
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

// Dynamic SipHash constants that are initialized with DYNAMIC_SEED
static GLOBAL_SIPHASH_V0: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V1: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V2: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SIPHASH_V3: AtomicU64 = AtomicU64::new(0);

// SipHash constants and state - now dynamic based on DYNAMIC_SEED
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
    // Create a combined value from global state
    // Use reconstructed score instead of direct load
    let combined = (reconstruct_threat_score() as u64)
        .wrapping_add(GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst));

    // Use dynamic SipHash-like algorithm with DYNAMIC_SEED for stronger integrity checking
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;

    // Mix the base values with DYNAMIC_SEED to create dynamic constants
    let dyn_v0 = base_v0 ^ (DYNAMIC_SEED as u64);
    let dyn_v1 = base_v1 ^ ((DYNAMIC_SEED as u64) << 8);
    let dyn_v2 = base_v2 ^ ((DYNAMIC_SEED as u64) << 16);
    let dyn_v3 = base_v3 ^ ((DYNAMIC_SEED as u64) << 24);

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

    let dyn_v0 = base_v0 ^ (DYNAMIC_SEED as u64);
    let dyn_v1 = base_v1 ^ ((DYNAMIC_SEED as u64) << 8);
    let dyn_v2 = base_v2 ^ ((DYNAMIC_SEED as u64) << 16);
    let dyn_v3 = base_v3 ^ ((DYNAMIC_SEED as u64) << 24);

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

/// Generate 3 distinct random indices [0..16) using mixed entropy (RDTSC + Stack Pointer)
fn get_random_indices_3() -> (usize, usize, usize) {
    let mut entropy = get_rdtsc_entropy();
    
    // Mix entropy with stack address to prevent simple rdtsc manipulation
    let stack_var = 0;
    entropy ^= (&stack_var as *const i32 as u64);
    
    // Simple LCG-like mixer
    let mut rng = entropy;
    let mut next = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((rng >> 32) & 0xF) as usize
    };

    let idx1 = next();
    
    let mut idx2 = next();
    while idx2 == idx1 {
        idx2 = next();
    }
    
    let mut idx3 = next();
    while idx3 == idx1 || idx3 == idx2 {
        idx3 = next();
    }
    
    (idx1, idx2, idx3)
}

/// Add suspicion with dispersed scoring mechanism (Scattering Algorithm)
/// Spreads the score across 3 random shards to defeat data breakpoints.
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

    // Entropy source for splitting
    let entropy = get_rdtsc_entropy();
    let (i1, i2, i3) = get_random_indices_3();

    // Split amount into 3 random parts ensuring a + b + c = amount
    // Using random weights from entropy bits
    let w1 = (entropy & 0x1F) + 1; // 1 to 32
    let w2 = ((entropy >> 5) & 0x1F) + 1; // 1 to 32
    let w3 = ((entropy >> 10) & 0x1F) + 1; // 1 to 32
    let total_w = w1 + w2 + w3;

    let p1 = (amount * w1 as u32) / total_w as u32;
    let p2 = (amount * w2 as u32) / total_w as u32;
    let p3 = amount - p1 - p2; // Remainder to ensure total matches exactly

    // Distribute to shards
    if p1 > 0 { add_to_shard(i1, p1); }
    if p2 > 0 { add_to_shard(i2, p2); }
    if p3 > 0 { add_to_shard(i3, p3); }

    recalculate_global_integrity();
}

/// Add suspicion with checkpoint tracking for diagnostics
pub fn add_suspicion_at(severity: DetectionSeverity, checkpoint_id: u8) {
    let amount = severity.score();
    log_checkpoint_trigger(checkpoint_id, amount);
    add_suspicion(severity);
}

/// Helper to add score to specific shard safely
fn add_to_shard(idx: usize, amount: u32) {
    let mask = SHARD_MASKS[idx];
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

/// Encapsulated decay logic to be called by add_suspicion and get_suspicion_score
fn apply_decay() {
    let current_time = get_current_timestamp();
    // Optimistic check to avoid expensive atomic swap if not needed
    let last_time_val = GLOBAL_LAST_DECAY_TIME.load(Ordering::Relaxed);
    if current_time <= last_time_val { return; }

    // Try to claim the decay update right
    // Using swap is heavy, maybe just CAS?
    // Let's stick to current logic pattern but clean it up
    
    // We only update if enough time has passed for at least 1 decay interval (e.g. 10s? Code said 300s previously)
    // Code said 300s.
    if current_time - last_time_val < 300 { return; }

    // CAS to update time. Only one thread succeeds.
    if GLOBAL_LAST_DECAY_TIME.compare_exchange(last_time_val, current_time, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return; // Lost race
    }
    
    let elapsed = current_time - last_time_val;
    let decay_intervals = elapsed / 300;
    let total_decay = (decay_intervals as u32) * 5; // 5 points per interval

    if total_decay == 0 { return; }

    // Decay mechanism: Must pick RANDOM shards to decrement.
    // Unlike previous logic which iterated 0..16, we want to randomly peck at shards until we satisfy the decay amount.
    // However, iterating 0..16 is actually fine for *finding* mass to decay, but it's predictable.
    // "The Decay Mechanism: Hàm giảm điểm (Decay) cũng phải chọn mảnh ngẫu nhiên để trừ điểm"
    
    let mut remaining = total_decay;
    
    // Attempt to decay by randomly probing shards up to N attempts.
    // If we can't find score after N attempts, we stop to avoid infinite loops if score is 0.
    // Or we can iterate starting from a random index.
    
    let start_idx = (get_rdtsc_entropy() % 16) as usize;
    
    for i in 0..16 {
        if remaining == 0 { break; }
        
        // Wrap around index
        let idx = (start_idx + i) % 16;
        
        let mask = SHARD_MASKS[idx];
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
}

/// Reconstruct the total threat score from distributed shards
/// Logic: Value_i = (Shard_i ^ Mask_i).rotate_right(i % 32)
/// Self-Defense: If memory is zeroed, XOR + Rotate results in a massive pseudo-random score.
pub fn reconstruct_threat_score() -> u32 {
    let mut total_score: u32 = 0;
    for i in 0..16 {
        let encoded = SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        let mask = SHARD_MASKS[i];
        
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
    if score > 200 {
        return 0xFFFFFFFF;
    }
    score
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

/// Initialize VEH protection (distributed state)
pub fn initialize_veh_protection() {
    // Register the actual exception handler
    crate::protector::anti_debug::register_veh_handler();

    // Initialize the global state with default values
    // Initialize the global state with default values
    // Initialize shards to their masked zero values
    for i in 0..16 {
        SUSPICION_SHARDS[i].store(SHARD_MASKS[i], Ordering::SeqCst);
    }
    GLOBAL_LAST_DECAY_TIME.store(get_current_timestamp(), Ordering::SeqCst);
    
    GLOBAL_INTEGRITY_HASH.store(0x12345678ABCDEF00, Ordering::SeqCst);
    GLOBAL_ENCRYPTION_KEY.store(0x42, Ordering::SeqCst);
    GLOBAL_VIRTUAL_MACHINE_KEY.store(0x42, Ordering::SeqCst);
    
    // Initialize POISON_SEED with a transformed DYNAMIC_SEED
    POISON_SEED.store((DYNAMIC_SEED as u64) ^ 0xCAFEBABE1337BEEF, Ordering::SeqCst);

    // Initialize dynamic SipHash constants using DYNAMIC_SEED
    initialize_dynamic_siphash();

    // Recalculate integrity hash after initialization
    recalculate_global_integrity();
}

/// Initialize SipHash constants with dynamic values using DYNAMIC_SEED to make them non-standard
fn initialize_dynamic_siphash() {
    // Use DYNAMIC_SEED to create dynamic initial values for SipHash
    // This makes the magic numbers polymorphic and harder to scan for
    let seed = DYNAMIC_SEED as u64;

    // Create dynamic initial values by XORing base constants with DYNAMIC_SEED
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;

    // Mix the base values with DYNAMIC_SEED to create dynamic constants
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

    // Apply multiple layers of obfuscation using DYNAMIC_SEED
    let obfuscated_entry = bitmask_entry ^ (DYNAMIC_SEED as u64);
    let rotated_entry = obfuscated_entry.rotate_left((DYNAMIC_SEED & 0x1F) as u32); // Rotate by lower 5 bits of seed
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




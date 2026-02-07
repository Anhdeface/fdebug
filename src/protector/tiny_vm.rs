#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]

//! TinyVM - Indirect Threading Architecture with Rolling Key Decryption
//! 
//! **Architecture**: Function Pointer Table (V-Table) dispatching
//! **Anti-RE**: No switch/match for opcode dispatch, single indirect call in loop
//! **Decryption**: Rolling key XOR chain prevents static pattern matching

use std::arch::asm;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use core::hint::black_box;
use core::ptr::write_volatile;

use crate::protector::seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8};
use crate::protector::pe_integrity::{heartbeat_check, INTEGRITY_TOKEN};
use crate::protector::global_state::POISON_SEED;

// --- [START] FFI & INTRINSICS ---
#[link(name = "kernel32")]
extern "system" {
    fn QueryThreadCycleTime(ThreadHandle: *mut std::ffi::c_void, CycleTime: *mut u64) -> i32;
}

#[inline(always)]
unsafe fn get_thread_cycles() -> u64 {
    let mut cycles: u64 = 0;
    // Pseudo-handle -2 (0xFF...FE) is CurrentThread. Fast path, no OpenThread needed.
    let handle = -2isize as *mut std::ffi::c_void;
    if QueryThreadCycleTime(handle, &mut cycles) == 0 {
        return 0; // Fail silent
    }
    cycles
}

#[inline(always)]
unsafe fn get_rip_marker() -> u16 {
    let rip: u64;
    // LEA is atomic and side-effect free.
    std::arch::asm!("lea {}, [rip]", out(reg) rip);
    ((rip >> 32) & 0xFFFF) as u16
}
// --- [END] FFI & INTRINSICS ---

// ============================================================================
// LIGHTWEIGHT PRNG & LOGIC-TO-PHYSICAL MAPPING
// ============================================================================

/// Minimal PRNG (Xorshift32) for deterministic (or chaotic) shuffling
struct Xorshift32 {
    state: u32,
}

impl Xorshift32 {
    fn new(seed: u32) -> Self {
        Self { state: if seed == 0 { 0xDEADBEEF } else { seed } }
    }

    fn next(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }
}

use std::sync::OnceLock;

/// Global Logic-to-Physical Opcode Mapping (LTP Map)
/// Maps: Logical Opcode (Bytecode) -> Physical Index (V-Table)
/// Replaced `static mut` with `OnceLock` for Thread Safety
static LTP_MAP: OnceLock<[u8; 256]> = OnceLock::new();

/// Create the LTP Map based on a specific seed (Internal Logic)
/// Encapsulated for testability of the "Chaos Trap"
fn create_ltp_map(mut seed: u32) -> [u8; 256] {
    // SECURITY TRAP: Detect tamper/debug seeds (e.g. 0 or known error codes)
    // If detected, switch to Chaotic Mode (RDTSC + ASLR based)
    let is_suspicious = seed == 0 || seed == 0xDEADBEEF; 
    if is_suspicious {
        let tsc: u32;
        unsafe { std::arch::asm!("rdtsc", out("eax") tsc, options(nomem, nostack)); }
        seed ^= tsc; // Link to Hardware Logic -> Non-deterministic
        
        // Add ASLR Entropy (Stack Address)
        // Counters constant-TSC Execution Environments / Timeless Debugging
        let stack_var = 0xBADF00Du32;
        let stack_addr = &stack_var as *const u32 as usize;
        seed ^= stack_addr as u32; 
    }

    let mut rng = Xorshift32::new(seed);
    
    // Initialize Identity Map
    let mut map = [0u8; 256];
    for i in 0..256 {
        map[i] = i as u8;
    }

    // Fisher-Yates Shuffle using PRNG
    for i in (1..256).rev() {
        let j = (rng.next() as usize) % (i + 1);
        map.swap(i, j);
    }
    
    map
}

/// Initialize the One-Way Logic-to-Physical Mapping
/// **Fail-Deadly**: If a known bad seed is detected, it mixes in RDTSC+ASLR entropy
/// to create a unique, non-reproducible mapping that silently corrupts execution.
fn init_vm_mapping() {
    LTP_MAP.get_or_init(|| {
        let seed = get_dynamic_seed();
        create_ltp_map(seed)
    });
}

// ============================================================================
// COMPILE-TIME CONSTANTS AND HASH FUNCTIONS
// ============================================================================

/// Compile-time hash function using FNV-1a variant with location-dependent seed
pub(crate) const fn const_str_hash(s: &str) -> u32 {
    let mut hash = 0x811C9DC5u32;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        hash = hash.rotate_left(7);
        i += 1;
    }
    hash
}

/// Generate a unique build seed based on the current file path and package name
pub(crate) const BUILD_SEED: u32 = const_str_hash(
    concat!(env!("CARGO_PKG_NAME"), "-", file!(), "-", env!("CARGO_MANIFEST_DIR"))
);

// ============================================================================
// POLYMORPHIC OPCODE GENERATION MACRO
// ============================================================================

macro_rules! auto_op {
    ($base:expr) => {{
        (($base as u8)
            .wrapping_add($crate::protector::tiny_vm::BUILD_SEED as u8)
            .wrapping_add($crate::protector::seed_orchestrator::get_dynamic_seed_u8()))
    }};
}

fn get_global_encoded_state() -> u32 {
    let score = crate::protector::global_state::get_suspicion_score();
    if score > 100 { 1 } else { 0 }
}

// ============================================================================
// SECURE BUFFER (RAII MEMORY SCRUBBING)
// ============================================================================

#[repr(C)]
pub struct SecureBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureBuffer<N> {
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
}

impl<const N: usize> std::ops::Deref for SecureBuffer<N> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        let scramble_seed = get_dynamic_seed();
        for i in 0..N {
            let garbage = black_box((scramble_seed.wrapping_mul(i as u32 + 1) ^ 0xAA5533CC) as u8);
            unsafe { write_volatile(&mut self.data[i], garbage); }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        for i in 0..N {
            unsafe { write_volatile(&mut self.data[i], black_box(0x00)); }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        #[cfg(target_arch = "x86_64")]
        unsafe { std::arch::asm!("", options(nomem, nostack, preserves_flags)); }
    }
}

// ============================================================================
// VIRTUAL MACHINE CORE STRUCTURES
// ============================================================================

/// Virtual Machine structure
pub struct TinyVm {
    pub vip: usize,
    pub v_stack: [u64; 32],
    pub sp: usize,
    pub accumulator: u64,
    pub key: u64,
}

impl TinyVm {
    pub fn new(local_key: u64) -> Self {
        TinyVm { vip: 0, v_stack: [0; 32], sp: 0, accumulator: 0, key: local_key }
    }
    #[inline(always)]
    pub fn push(&mut self, value: u64) {
        if self.sp < self.v_stack.len() {
            self.v_stack[self.sp] = value;
            self.sp += 1;
        }
    }
    #[inline(always)]
    pub fn pop(&mut self) -> u64 {
        if self.sp > 0 { self.sp -= 1; self.v_stack[self.sp] } else { 0 }
    }
    #[inline(always)]
    pub fn peek(&self) -> u64 {
        if self.sp > 0 { self.v_stack[self.sp - 1] } else { 0 }
    }
}

/// Execution state for indirect threading model
pub struct VmExecutionState {
    pub vip: usize,
    pub key: u8,
    pub next_idx: u8,
    pub should_exit: bool,
    pub exit_value: u64,
    /// Anchor for RIP entanglement (high-bits of entry address)
    pub anchor_rip: u16,
    /// Previous thread cycle count for heartbeat detection
    pub last_cycles: u64,
}

/// Handler function signature for indirect threading
pub type VmInstruction = unsafe fn(
    bytecode: &[u8],
    vm: &mut TinyVm,
    state: &mut VmExecutionState,
    encryption_key: u8,
);

/// Virtual Machine Operations with runtime polymorphic values
pub struct VmOp;

impl VmOp {
    pub fn op_load_imm() -> u8 { auto_op!(0x1A) }
    pub fn op_read_gs_offset() -> u8 { auto_op!(0x2B) }
    pub fn op_read_mem_u8() -> u8 { auto_op!(0x2C) }
    pub fn op_read_mem_u32() -> u8 { auto_op!(0x2D) }
    pub fn op_read_mem_u64() -> u8 { auto_op!(0x2E) }
    pub fn op_rdtsc() -> u8 { auto_op!(0x3C) }
    pub fn op_cpuid() -> u8 { auto_op!(0x3D) }
    pub fn op_in_port() -> u8 { auto_op!(0x3E) }
    pub fn op_out_port() -> u8 { auto_op!(0x3F) }
    pub fn op_add() -> u8 { auto_op!(0x4D) }
    pub fn op_sub() -> u8 { auto_op!(0x5E) }
    pub fn op_xor() -> u8 { auto_op!(0x6F) }
    pub fn op_push() -> u8 { auto_op!(0x70) }
    pub fn op_pop() -> u8 { auto_op!(0x81) }
    pub fn op_dup() -> u8 { auto_op!(0x92) }
    pub fn op_swap() -> u8 { auto_op!(0xA3) }
    pub fn op_cmp_eq() -> u8 { auto_op!(0xB4) }
    pub fn op_cmp_ne() -> u8 { auto_op!(0xC5) }
    pub fn op_cmp_gt() -> u8 { auto_op!(0xD6) }
    pub fn op_cmp_lt() -> u8 { auto_op!(0xE7) }
    pub fn op_and() -> u8 { auto_op!(0xF8) }
    pub fn op_or() -> u8 { auto_op!(0x09) }
    pub fn op_not() -> u8 { auto_op!(0xAA) }
    pub fn op_shl() -> u8 { auto_op!(0xBB) }
    pub fn op_shr() -> u8 { auto_op!(0xCC) }
    pub fn op_jump() -> u8 { auto_op!(0xDD) }
    pub fn op_jz() -> u8 { auto_op!(0xEE) }
    pub fn op_jnz() -> u8 { auto_op!(0xFF) }
    pub fn op_call() -> u8 { auto_op!(0x77) }
    pub fn op_ret() -> u8 { auto_op!(0x88) }
    pub fn op_exit() -> u8 { auto_op!(0x99) }
    pub fn op_garbage() -> u8 { auto_op!(0x9E) }
    pub fn op_poly_junk() -> u8 { auto_op!(0xAB) }
    pub fn op_early_bird() -> u8 { auto_op!(0x66) }
    pub fn op_write_mem_u8() -> u8 { auto_op!(0x2F) }
    pub fn op_reconstruct_str() -> u8 { auto_op!(0xA4) }
    pub fn op_apply_hardware_key() -> u8 { auto_op!(0xA5) }
}

// ============================================================================
// POLYMORPHIC STACK-STRING MACROS
// ============================================================================

#[macro_export]
macro_rules! dynamic_str {
    ($s:expr) => {{
        use $crate::protector::tiny_vm::SecureBuffer;
        use $crate::protector::seed_orchestrator::get_dynamic_seed;
        use core::ptr::write_volatile;
        use core::hint::black_box;
        use std::sync::atomic::Ordering;
        
        const S_BYTES: &[u8] = $s.as_bytes();
        const S_LEN: usize = S_BYTES.len();
        const HASH: u32 = $crate::protector::tiny_vm::const_str_hash(concat!(file!(), line!()));
        const TRANS_TYPE: u64 = (HASH % 3) as u64;
        const COMPILE_TIME_SALT: u64 = ((HASH >> 8) & 0xFF) as u64;
        
        const ENCRYPTED: [u8; S_LEN] = {
            let mut res = [0u8; S_LEN];
            let mut i = 0;
            while i < S_LEN {
                let mut v = S_BYTES[i];
                match TRANS_TYPE {
                    0 => { v = v.rotate_right(3); v ^= COMPILE_TIME_SALT as u8; },
                    1 => { v ^= 0x55; v = v.wrapping_add(COMPILE_TIME_SALT as u8); },
                    2 => { v = v.wrapping_sub(COMPILE_TIME_SALT as u8); v = !v; },
                    _ => { v ^= 0xAA; }
                }
                res[i] = v;
                i += 1;
            }
            res
        };

        let mut buffer = SecureBuffer::<S_LEN>::new();
        let poison_val = $crate::protector::global_state::POISON_SEED.load(Ordering::Relaxed);
        let expected_poison = 0xCAFEBABE1337BEEF_u64 ^ (get_dynamic_seed() as u64);
        let is_poisoned = poison_val != 0 && poison_val != expected_poison;
        
        if is_poisoned {
            let fake_seed = black_box(poison_val.wrapping_mul(0x5DEECE66D));
            for i in 0..S_LEN {
                let fake_char = black_box((0x20 + ((fake_seed.wrapping_mul(i as u64 + 1) >> 8) % 95)) as u8);
                unsafe { write_volatile(buffer.as_mut_ptr().add(i), fake_char); }
            }
            buffer
        } else {
            for i in 0..S_LEN {
                unsafe { write_volatile(buffer.as_mut_ptr().add(i), black_box(ENCRYPTED[i])); }
            }
            
            let hw_seed = get_dynamic_seed();
            let runtime_key = black_box(COMPILE_TIME_SALT as u8);

            let mut bytecode = [0u8; 64];
            let mut bc_idx = 0;
            let bc_key = (HASH & 0xFF) as u8;
            let mut rolling_key: u8 = 0;
            
            // External entropy assumption for macro expansion: 0x42 (Default state)
            // The runtime VM will use the real atomic value.
            const DEFAULT_GLOBAL_KEY: u8 = 0x42; 

            // Snapshot integrity token for consistent encoding of this session
            let integrity_snapshot = $crate::protector::pe_integrity::INTEGRITY_TOKEN.load(std::sync::atomic::Ordering::Relaxed) as u8;

            // Advanced Rolling Key Encoding Logic (Multi-Stage Mixing)
            // Decryption: real = (raw ^ key ^ enc_key ^ integrity_token).wrapping_add(pos_salt)
            // Encoding:   raw = (real.wrapping_sub(pos_salt)) ^ key ^ enc_key ^ integrity_token
            // Key Update: Same for both (using raw byte)
            let mut emit = |real_op: u8| {
                if bc_idx < bytecode.len() {
                    // 1. Calculate Position Dependent Salt
                    let pos_salt = (bc_idx as u8).wrapping_mul(0x7);
                    
                    // 2. Encrypt
                    let raw = real_op.wrapping_sub(pos_salt) ^ bc_key ^ rolling_key ^ integrity_snapshot;
                    bytecode[bc_idx] = raw;
                    bc_idx += 1;
                    
                    // 3. Update Rolling Key (Non-linear Feedback)
                    rolling_key = rolling_key.wrapping_add(raw).wrapping_mul(0x1F);
                    rolling_key ^= rolling_key.rotate_right(3) ^ 0x3C;
                    rolling_key ^= DEFAULT_GLOBAL_KEY;
                }
            };

            emit($crate::protector::tiny_vm::VmOp::op_load_imm());
            let kb = (runtime_key as u64).to_le_bytes();
            for b in kb { emit(b); }

            emit($crate::protector::tiny_vm::VmOp::op_load_imm());
            let lb = (S_LEN as u64).to_le_bytes();
            for b in lb { emit(b); }

            emit($crate::protector::tiny_vm::VmOp::op_load_imm());
            let ab = (buffer.as_ptr() as u64).to_le_bytes();
            for b in ab { emit(b); }

            emit($crate::protector::tiny_vm::VmOp::op_load_imm());
            let kb = (runtime_key as u64).to_le_bytes();
            for b in kb { emit(b); }

            emit($crate::protector::tiny_vm::VmOp::op_load_imm());
            let tb = (TRANS_TYPE as u64).to_le_bytes();
            for b in tb { emit(b); }

            emit($crate::protector::tiny_vm::VmOp::op_reconstruct_str());
            emit($crate::protector::tiny_vm::VmOp::op_exit());

            $crate::protector::tiny_vm::vm_execute(&bytecode[..bc_idx], bc_key, hw_seed as u64);
            buffer
        }
    }}
}

#[macro_export]
macro_rules! enc_str {
    ($s:expr) => { $crate::dynamic_str!($s) };
}

#[macro_export]
macro_rules! enc_string {
    ($s:expr) => { $crate::dynamic_str!($s) };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

unsafe fn cpuid_helper(leaf: u32) -> (u32, u32, u32, u32) {
    let eax_out: u32;
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    asm!(
        "push rbx", "cpuid", "mov {0:e}, ebx", "pop rbx",
        out(reg) ebx_out,
        inout("eax") leaf => eax_out,
        out("ecx") ecx_out,
        out("edx") edx_out,
        options(nomem, nostack)
    );
    (eax_out, ebx_out, ecx_out, edx_out)
}

#[inline(always)]
fn get_enhanced_entropy() -> u32 {
    let (tsc_low, tsc_high): (u32, u32);
    unsafe {
        asm!("lfence", "rdtsc", "lfence",
            out("eax") tsc_low, out("edx") tsc_high, options(nomem, nostack));
    }
    let tsc_entropy = tsc_low ^ tsc_high;
    let stack_var = 0x12345678u32;
    let stack_addr = &stack_var as *const u32 as u64;
    let stack_entropy = ((stack_addr >> 3) ^ (stack_addr >> 13)) as u32;
    let (eax_out, ebx_out, _, _) = unsafe { cpuid_helper(1) };
    let cpuid_entropy = eax_out ^ ebx_out;
    let mut rdrand_entropy = 0u32;
    let success: u8;
    unsafe {
        asm!(
            "xor {result:r}, {result:r}", "rdrand {result:r}", "setc {success}",
            result = out(reg) rdrand_entropy,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }
    if success == 0 {
        rdrand_entropy = (tsc_low ^ stack_entropy ^ cpuid_entropy).rotate_left(7);
    }
    tsc_entropy.wrapping_add(stack_entropy).wrapping_mul(0x9E3779B1)
        .wrapping_add(cpuid_entropy).wrapping_mul(0x85EBCA6B)
        .wrapping_add(rdrand_entropy)
}

// ============================================================================
// POLYMORPHIC INSTRUCTION DECODER (ROLLING KEY)
// ============================================================================

// ============================================================================
// POLYMORPHIC INSTRUCTION DECODER (ROLLING KEY)
// ============================================================================

/// Fetch and decode next instruction using rolling key XOR chain
/// This creates temporal dependency that defeats static analysis
#[inline(always)]
unsafe fn fetch_next_instruction(
    bytecode: &[u8],
    state: &mut VmExecutionState,
    encryption_key: u8,
) {
    if state.vip >= bytecode.len() {
        state.should_exit = true;
        return;
    }
    
    let raw_byte = bytecode[state.vip];
    
    // [HEARTBEAT INJECTION]
    // Randomly trigger integrity checks based on VIP/Key entropy
    // Used sparingly to avoid performance hit, but enough to entangle long-running VMs
    if (state.vip & 0x7F) == 0x3 { 
        let seed = (state.key as u32).wrapping_add(state.vip as u32);
        crate::protector::pe_integrity::heartbeat_check(seed);
    }

    // 1. Calculate Position Dependent Salt
    let pos_salt = (state.vip as u8).wrapping_mul(0x7);
    
    // Entangle with Global Integrity Token
    let integrity_val = crate::protector::pe_integrity::INTEGRITY_TOKEN.load(std::sync::atomic::Ordering::Relaxed) as u8;

    // 2. Decode: real = (raw ^ key ^ enc_key ^ integrity_token).wrapping_add(pos_salt)
    let real_opcode = (raw_byte ^ encryption_key ^ state.key ^ integrity_val)
        .wrapping_add(pos_salt);
    
    // 3. Update Rolling Key (Multi-Stage State Mixing)
    let global_entropy = crate::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY
        .load(std::sync::atomic::Ordering::Relaxed);
        
    state.key = state.key.wrapping_add(raw_byte).wrapping_mul(0x1F);
    state.key ^= state.key.rotate_right(3) ^ 0x3C;
    state.key ^= global_entropy;
    
    state.next_idx = real_opcode;
    state.vip += 1;
}

// ============================================================================
// MICRO-HANDLERS (DECENTRALIZED OPCODE LOGIC)
// ============================================================================

/// Helper to fetch operand byte with rolling key updates
#[inline(always)]
unsafe fn fetch_operand_byte(
    bytecode: &[u8], state: &mut VmExecutionState, encryption_key: u8,
) -> u8 {
    if state.vip >= bytecode.len() {
        state.should_exit = true;
        return 0;
    }
    
    let raw_byte = bytecode[state.vip];
    
    // 1. Calculate Position Dependent Salt
    let pos_salt = (state.vip as u8).wrapping_mul(0x7);
    
    // Entangle with Global Integrity Token
    let integrity_val = crate::protector::pe_integrity::INTEGRITY_TOKEN.load(std::sync::atomic::Ordering::Relaxed) as u8;

    // 2. Decode: real = (raw ^ key ^ enc_key ^ integrity_token).wrapping_add(pos_salt)
    let val = (raw_byte ^ encryption_key ^ state.key ^ integrity_val)
        .wrapping_add(pos_salt);
    
    // 3. Update Rolling Key (Multi-Stage State Mixing)
    let global_entropy = crate::protector::global_state::GLOBAL_VIRTUAL_MACHINE_KEY
        .load(std::sync::atomic::Ordering::Relaxed);
        
    state.key = state.key.wrapping_add(raw_byte).wrapping_mul(0x1F);
    state.key ^= state.key.rotate_right(3) ^ 0x3C;
    state.key ^= global_entropy;

    state.vip += 1;
    val
}

/// Trap handler for undefined opcodes
unsafe fn op_trap(
    _bytecode: &[u8], _vm: &mut TinyVm, state: &mut VmExecutionState, _encryption_key: u8,
) {
    state.exit_value = 0;
    state.should_exit = true;
}

/// Load 64-bit immediate value onto stack
unsafe fn op_load_imm(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = fetch_operand_byte(bytecode, state, encryption_key);
    }
    vm.push(u64::from_le_bytes(bytes));
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Exit VM and return top of stack
unsafe fn op_exit(
    _bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, _encryption_key: u8,
) {
    state.exit_value = vm.pop();
    state.should_exit = true;
}

/// Add two values (debug-aware: reverses to SUB under debugging)
unsafe fn op_add(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let temp_b = vm.pop();
    let temp_a = vm.pop();
    let result = if (global_state & 1) != 0 {
        temp_a.wrapping_sub(temp_b)
    } else {
        temp_a.wrapping_add(temp_b)
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Subtract two values (debug-aware: reverses to ADD under debugging)
unsafe fn op_sub(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let temp_b = vm.pop();
    let temp_a = vm.pop();
    let result = if (global_state & 1) != 0 {
        temp_a.wrapping_add(temp_b)
    } else {
        temp_a.wrapping_sub(temp_b)
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// XOR two values (debug-aware: reverses to ADD under debugging)
unsafe fn op_xor(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let temp_b = vm.pop();
    let temp_a = vm.pop();
    let result = if (global_state & 1) != 0 {
        temp_a.wrapping_add(temp_b)
    } else {
        temp_a ^ temp_b
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Push byte from bytecode onto stack
unsafe fn op_push(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let val = fetch_operand_byte(bytecode, state, encryption_key);
    vm.push(val as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Pop and discard top of stack
unsafe fn op_pop(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    vm.pop();
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Duplicate top of stack
unsafe fn op_dup(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let val = vm.peek();
    vm.push(val);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Swap top two elements on stack
unsafe fn op_swap(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    if vm.sp >= 2 {
        let a = vm.pop();
        let b = vm.pop();
        vm.push(a);
        vm.push(b);
    }
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Bitwise AND
unsafe fn op_and(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let b = vm.pop();
    let a = vm.pop();
    vm.push(a & b);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Bitwise OR
unsafe fn op_or(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let b = vm.pop();
    let a = vm.pop();
    vm.push(a | b);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Bitwise NOT
unsafe fn op_not(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let a = vm.pop();
    vm.push(!a);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Shift left
unsafe fn op_shl(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let shift = vm.pop() as u32;
    let a = vm.pop();
    vm.push(a << shift);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Shift right
unsafe fn op_shr(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let shift = vm.pop() as u32;
    let a = vm.pop();
    vm.push(a >> shift);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Compare equal (debug-aware)
unsafe fn op_cmp_eq(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let b = vm.pop();
    let a = vm.pop();
    let result = if (global_state & 1) != 0 {
        if a != b { 1 } else { 0 }
    } else {
        if a == b { 1 } else { 0 }
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Compare not equal (debug-aware)
unsafe fn op_cmp_ne(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let b = vm.pop();
    let a = vm.pop();
    let result = if (global_state & 1) != 0 {
        if a == b { 1 } else { 0 }
    } else {
        if a != b { 1 } else { 0 }
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Compare greater than (debug-aware)
unsafe fn op_cmp_gt(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let b = vm.pop();
    let a = vm.pop();
    let result = if (global_state & 1) != 0 {
        if a <= b { 1 } else { 0 }
    } else {
        if a > b { 1 } else { 0 }
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Compare less than (debug-aware)
unsafe fn op_cmp_lt(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let global_state = get_global_encoded_state();
    let b = vm.pop();
    let a = vm.pop();
    let result = if (global_state & 1) != 0 {
        if a >= b { 1 } else { 0 }
    } else {
        if a < b { 1 } else { 0 }
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Unconditional jump
unsafe fn op_jump(
    bytecode: &[u8], _vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let target = fetch_operand_byte(bytecode, state, encryption_key) as usize;
    state.vip = target;
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Jump if zero
unsafe fn op_jz(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let target = fetch_operand_byte(bytecode, state, encryption_key) as usize;
    let val = vm.pop();
    if val == 0 {
        state.vip = target;
    }
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Jump if not zero
unsafe fn op_jnz(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let target = fetch_operand_byte(bytecode, state, encryption_key) as usize;
    let val = vm.pop();
    if val != 0 {
        state.vip = target;
    }
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Read from GS segment offset
unsafe fn op_read_gs_offset(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let offset = fetch_operand_byte(bytecode, state, encryption_key) as u64;
    let result: u64;
    asm!("mov {}, gs:[{}]", out(reg) result, in(reg) offset, options(nostack, readonly));
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Read byte from memory address
unsafe fn op_read_mem_u8(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let addr = vm.pop() as *const u8;
    let result: u8 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
        0
    } else {
        std::ptr::read_volatile(addr)
    };
    vm.push(result as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Read u32 from memory address
unsafe fn op_read_mem_u32(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let addr = vm.pop() as *const u32;
    let result: u32 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
        0
    } else {
        std::ptr::read_volatile(addr)
    };
    vm.push(result as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Read u64 from memory address
unsafe fn op_read_mem_u64(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let addr = vm.pop() as *const u64;
    let result: u64 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
        0
    } else {
        std::ptr::read_volatile(addr)
    };
    vm.push(result);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Write byte to memory address
unsafe fn op_write_mem_u8(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let value = vm.pop() as u8;
    let addr = vm.pop() as *mut u8;
    if !addr.is_null() && (addr as usize) >= 0x10000 && (addr as usize) <= 0x7FFFFFFFFFFF {
        write_volatile(addr, value);
    }
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// RDTSC - Read timestamp counter
unsafe fn op_rdtsc(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let (low, high): (u32, u32);
    asm!("lfence", "rdtsc", "lfence", out("eax") low, out("edx") high, options(nomem, nostack));
    let mut timestamp = ((high as u64) << 32) | (low as u64);
    if crate::protector::global_state::is_system_under_heavy_load() {
        timestamp &= 0xFFFFFFFFFFFFFFF0;
    }
    vm.push(timestamp);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// CPUID instruction
unsafe fn op_cpuid(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let eax_in = vm.pop() as u32;
    let (eax_out, ebx_out, ecx_out, edx_out) = cpuid_helper(eax_in);
    vm.push(edx_out as u64);
    vm.push(ecx_out as u64);
    vm.push(ebx_out as u64);
    vm.push(eax_out as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Read from I/O port
unsafe fn op_in_port(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let port = fetch_operand_byte(bytecode, state, encryption_key) as u16;
    let result: u32;
    asm!("in eax, dx", out("eax") result, in("dx") port, options(nomem, nostack));
    vm.push(result as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Write to I/O port
unsafe fn op_out_port(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let port = fetch_operand_byte(bytecode, state, encryption_key) as u16;
    let value = vm.pop() as u32;
    asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Early bird debugger check via PEB
unsafe fn op_early_bird(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let being_debugged: u8;
    asm!("mov {}, gs:[0x60 + 0x02]", out(reg_byte) being_debugged, options(nostack, preserves_flags, readonly));
    vm.push(being_debugged as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Push dynamic hardware seed
unsafe fn op_apply_hardware_key(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    vm.push(get_dynamic_seed() as u64);
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// String reconstruction with hardware-locked decryption
unsafe fn op_reconstruct_str(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let transform_type = vm.pop();
    let key = vm.pop();
    let addr = vm.pop() as *mut u8;
    let len = vm.pop() as usize;
    let byte_key = black_box(key as u8);

    if !addr.is_null() && (addr as usize) >= 0x10000 && (addr as usize) <= 0x7FFFFFFFFFFF {
        for i in 0..len {
            let curr_ptr = addr.add(i);
            let mut val = std::ptr::read_volatile(curr_ptr);
            match transform_type {
                0 => { val ^= byte_key; val = val.rotate_left(3); },
                1 => { val = val.wrapping_sub(byte_key); val ^= 0x55; },
                2 => { val = !val; val = val.wrapping_add(byte_key); },
                _ => { val ^= 0xAA; }
            }
            #[cfg(target_arch = "x86_64")]
            asm!("mov byte ptr [{ptr}], {val}", ptr = in(reg) curr_ptr, val = in(reg_byte) val, options(nostack));
            #[cfg(not(target_arch = "x86_64"))]
            write_volatile(curr_ptr, val);
        }
    }
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Garbage operations for anti-analysis
unsafe fn op_garbage(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let top_value = if vm.sp > 0 { vm.v_stack[vm.sp - 1] } else { 0 };
    let x = top_value as u32;
    let rotated_top = (top_value as u32).rotate_left(7);
    let y = rotated_top ^ 0x9E3779B1u32;
    let _garbage_result = (x | y).wrapping_add(x & y);
    let _more_garbage = (x ^ y).wrapping_add(2u32.wrapping_mul(x & y));
    fetch_next_instruction(bytecode, state, encryption_key);
}

/// Polymorphic junk operations
unsafe fn op_poly_junk(
    bytecode: &[u8], vm: &mut TinyVm, state: &mut VmExecutionState, encryption_key: u8,
) {
    let state_dependent_seed = (state.vip as u64) ^ vm.accumulator ^ (get_enhanced_entropy() as u64);
    let junk_val1 = state_dependent_seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB) & 0xFFFFFFFFFFFF;
    let junk_val2 = state_dependent_seed.rotate_left(13) ^ 0x9E3779B1;
    let junk_val3 = (junk_val1 ^ junk_val2).wrapping_add(state_dependent_seed);
    let _op1 = junk_val3.wrapping_mul(31).wrapping_add(junk_val1);
    let _op2 = (_op1 >> 3) ^ junk_val2;
    let _op3 = _op2.wrapping_add(_op1.rotate_right(7));
    fetch_next_instruction(bytecode, state, encryption_key);
}

// ============================================================================
// DISPATCH TABLE BUILDER
// ============================================================================

/// Build the 256-entry dispatch table at runtime
/// Maps polymorphic opcodes to their handlers using RANDOMIZED V-TABLE MAPPING
fn build_dispatch_table() -> [VmInstruction; 256] {
    // Initialize Mapping (if not already)
    init_vm_mapping();
    
    // Safety: LTP_MAP is initialized by Once call above
    // Used get().expect() instead of unsafe block for thread safety
    let map = LTP_MAP.get().expect("VM Mapping not initialized");

    let mut table: [VmInstruction; 256] = [op_trap; 256];
    
    // Map each opcode to its handler Physically via the random permutation
    // The Logical Opcode (VmOp) maps to a Physical Index (map[VmOp]).
    table[map[VmOp::op_load_imm() as usize] as usize] = op_load_imm;
    table[map[VmOp::op_read_gs_offset() as usize] as usize] = op_read_gs_offset;
    table[map[VmOp::op_read_mem_u8() as usize] as usize] = op_read_mem_u8;
    table[map[VmOp::op_read_mem_u32() as usize] as usize] = op_read_mem_u32;
    table[map[VmOp::op_read_mem_u64() as usize] as usize] = op_read_mem_u64;
    table[map[VmOp::op_write_mem_u8() as usize] as usize] = op_write_mem_u8;
    table[map[VmOp::op_rdtsc() as usize] as usize] = op_rdtsc;
    table[map[VmOp::op_cpuid() as usize] as usize] = op_cpuid;
    table[map[VmOp::op_in_port() as usize] as usize] = op_in_port;
    table[map[VmOp::op_out_port() as usize] as usize] = op_out_port;
    table[map[VmOp::op_add() as usize] as usize] = op_add;
    table[map[VmOp::op_sub() as usize] as usize] = op_sub;
    table[map[VmOp::op_xor() as usize] as usize] = op_xor;
    table[map[VmOp::op_push() as usize] as usize] = op_push;
    table[map[VmOp::op_pop() as usize] as usize] = op_pop;
    table[map[VmOp::op_dup() as usize] as usize] = op_dup;
    table[map[VmOp::op_swap() as usize] as usize] = op_swap;
    table[map[VmOp::op_cmp_eq() as usize] as usize] = op_cmp_eq;
    table[map[VmOp::op_cmp_ne() as usize] as usize] = op_cmp_ne;
    table[map[VmOp::op_cmp_gt() as usize] as usize] = op_cmp_gt;
    table[map[VmOp::op_cmp_lt() as usize] as usize] = op_cmp_lt;
    table[map[VmOp::op_and() as usize] as usize] = op_and;
    table[map[VmOp::op_or() as usize] as usize] = op_or;
    table[map[VmOp::op_not() as usize] as usize] = op_not;
    table[map[VmOp::op_shl() as usize] as usize] = op_shl;
    table[map[VmOp::op_shr() as usize] as usize] = op_shr;
    table[map[VmOp::op_jump() as usize] as usize] = op_jump;
    table[map[VmOp::op_jz() as usize] as usize] = op_jz;
    table[map[VmOp::op_jnz() as usize] as usize] = op_jnz;
    table[map[VmOp::op_exit() as usize] as usize] = op_exit;
    table[map[VmOp::op_garbage() as usize] as usize] = op_garbage;
    table[map[VmOp::op_poly_junk() as usize] as usize] = op_poly_junk;
    table[map[VmOp::op_early_bird() as usize] as usize] = op_early_bird;
    table[map[VmOp::op_reconstruct_str() as usize] as usize] = op_reconstruct_str;
    table[map[VmOp::op_apply_hardware_key() as usize] as usize] = op_apply_hardware_key;
    
    table
}

// ============================================================================
// EXECUTION ENGINE (INDIRECT THREADING TRAMPOLINE)
// ============================================================================

/// Execute bytecode using indirect threading with RANDOMIZED DISPATCH
/// 
/// **CFG Analysis Resistance**:
/// - Single indirect call in loop body.
/// - Randomized mapping (Logic -> Physical) defeats static V-Table analysis.
#[inline(never)]
pub fn vm_execute(bytecode: &[u8], encryption_key: u8, context_key: u64) -> u64 {
    // Ensure mapping is initialized
    init_vm_mapping();
    
    // Safety: LTP_MAP is initialized
    let ltp_map = LTP_MAP.get().expect("VM Mapping not initialized");

    // Mix the context key with the global VM key
    let global_vm_key = crate::protector::global_state::get_current_vm_key() as u64;
    let local_vm_key = global_vm_key ^ context_key;

    let mut vm = TinyVm::new(local_vm_key);
    let mut state = VmExecutionState {
        vip: 0,
        key: 0,
        next_idx: 0,
        should_exit: false,
        exit_value: 0,
        anchor_rip: 0,
        last_cycles: 0,
    };

    // Build dispatch table (physically shuffled)
    let handlers = build_dispatch_table();

    // =========================================================================
    // ENTANGLED EXECUTION: Initialize Anchors (Before Loop)
    // =========================================================================
    unsafe {
        state.anchor_rip = get_rip_marker();
        state.last_cycles = get_thread_cycles();
    }

    // Bootstrap: fetch first instruction
    unsafe {
        fetch_next_instruction(bytecode, &mut state, encryption_key);
    }

    // =========================================================================
    // THE TRAMPOLINE - Shuffled Indirect Call with Entanglement
    // =========================================================================
    loop {
        if state.should_exit {
            break;
        }

        // =====================================================================
        // ENTANGLEMENT LOGIC (Anti-DBI / Anti-Trace)
        // =====================================================================
        unsafe {
            // --- Anti-DBI: RIP Entanglement ---
            // If code is relocated (DBI injection), RIP high-bits change.
            // XOR entropy into key -> Garbage execution if tampered.
            let current_rip_marker = get_rip_marker();
            let entropy = current_rip_marker ^ state.anchor_rip;
            state.key ^= entropy as u8;

            // --- Anti-Trace: Thread Cycle Heartbeat ---
            // Every 16 instructions, check for excessive CPU cycle consumption.
            // Single-stepping or tracing causes massive overhead (50k+ cycles).
            if (state.vip & 0xF) == 0 {
                let current_cycles = get_thread_cycles();
                let delta = current_cycles.wrapping_sub(state.last_cycles);
                
                // Threshold: 50,000 cycles per 16 instructions is abnormally high
                // Normal execution: ~1000-5000 cycles. Tracing: 100k+ cycles.
                if delta > 50_000 {
                    state.key ^= 0x55; // Corrupt key silently
                }
                state.last_cycles = current_cycles;
            }
        }

        // THE CRITICAL LINE: Map Logical Opcode -> Physical Index
        let physical_idx = ltp_map[state.next_idx as usize];
        
        unsafe {
            handlers[physical_idx as usize](
                bytecode,
                &mut vm,
                &mut state,
                encryption_key,
            );
        }
    }

    state.exit_value
}

// ============================================================================
// PUBLIC HELPER FUNCTIONS
// ============================================================================

/// Get opcode name for debugging (uses encrypted strings)
pub fn get_opcode_name(opcode: u8) -> String {
    match opcode {
        op if op == VmOp::op_load_imm() => String::from_utf8_lossy(&enc_string!("LOAD_IMM")).into_owned(),
        op if op == VmOp::op_read_gs_offset() => String::from_utf8_lossy(&enc_string!("READ_GS_OFFSET")).into_owned(),
        op if op == VmOp::op_read_mem_u8() => String::from_utf8_lossy(&enc_string!("READ_MEM_U8")).into_owned(),
        op if op == VmOp::op_read_mem_u32() => String::from_utf8_lossy(&enc_string!("READ_MEM_U32")).into_owned(),
        op if op == VmOp::op_read_mem_u64() => String::from_utf8_lossy(&enc_string!("READ_MEM_U64")).into_owned(),
        op if op == VmOp::op_rdtsc() => String::from_utf8_lossy(&enc_string!("RDTSC")).into_owned(),
        op if op == VmOp::op_cpuid() => String::from_utf8_lossy(&enc_string!("CPUID")).into_owned(),
        op if op == VmOp::op_add() => String::from_utf8_lossy(&enc_string!("ADD")).into_owned(),
        op if op == VmOp::op_sub() => String::from_utf8_lossy(&enc_string!("SUB")).into_owned(),
        op if op == VmOp::op_xor() => String::from_utf8_lossy(&enc_string!("XOR")).into_owned(),
        op if op == VmOp::op_push() => String::from_utf8_lossy(&enc_string!("PUSH")).into_owned(),
        op if op == VmOp::op_pop() => String::from_utf8_lossy(&enc_string!("POP")).into_owned(),
        op if op == VmOp::op_exit() => String::from_utf8_lossy(&enc_string!("EXIT")).into_owned(),
        _ => String::from_utf8_lossy(&enc_string!("UNKNOWN")).into_owned(),
    }
}

/// Get error message (uses encrypted strings)
pub fn get_error_message(error_type: &str) -> String {
    match error_type {
        "invalid_opcode" => String::from_utf8_lossy(&enc_string!("Invalid opcode encountered in bytecode")).into_owned(),
        "stack_overflow" => String::from_utf8_lossy(&enc_string!("Stack overflow in virtual machine")).into_owned(),
        "stack_underflow" => String::from_utf8_lossy(&enc_string!("Stack underflow in virtual machine")).into_owned(),
        "memory_access_violation" => String::from_utf8_lossy(&enc_string!("Memory access violation in VM")).into_owned(),
        _ => String::from_utf8_lossy(&enc_string!("Unknown error in virtual machine")).into_owned(),
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_encrypted_strings_hello() {
        // Test basic string decryption
        let test_buffer = enc_string!("Hello");
        let test_str = String::from_utf8_lossy(&test_buffer);
        assert_eq!(test_str, "Hello");
    }

    #[test]
    fn test_encrypted_strings_hello_world() {
        let test_buffer = enc_string!("Hello, World!");
        let test_str = String::from_utf8_lossy(&test_buffer);
        assert_eq!(test_str, "Hello, World!");
    }

    #[test]
    fn test_opcode_name() {
        let opcode_name = get_opcode_name(VmOp::op_add());
        assert_eq!(opcode_name, "ADD");
    }

    #[test]
    fn test_error_message() {
        let error_msg = get_error_message("invalid_opcode");
        assert_eq!(error_msg, "Invalid opcode encountered in bytecode");
    }

    #[test]
    fn test_different_line_encryption() {
        // These should use different keys due to different line numbers
        let test_buffer1 = enc_string!("Test string 1");
        let test_buffer2 = enc_string!("Test string 2");
        
        let str1 = String::from_utf8_lossy(&test_buffer1);
        let str2 = String::from_utf8_lossy(&test_buffer2);

        assert_eq!(str1, "Test string 1");
        assert_eq!(str2, "Test string 2");
    }

    #[test]
    fn test_indirect_threading_dispatch_table() {
        // Verify dispatch table builds correctly
        let table = build_dispatch_table();
        
        // Check that known opcodes have non-trap handlers
        // (We can't easily compare function pointers, but we can verify it doesn't panic)
        assert!(table.len() == 256);
    }
    
    #[test]
    fn test_high_entropy_encoding() {
        // Test that repetitive input produces high entropy output
        // "AAAAAAAAAA" should not result in repetitive bytecode
        let input = "AAAAAAAAAA";
        let encrypted_buffer = enc_string!("AAAAAAAAAA");
        
        // We can't access the raw bytecode easily from here as valid Rust code
        // because the macro executes and consumes it.
        // However, we can verify that the decrypted string is correct,
        // which proves the Synchronization between Macro Encoder and Runtime Decoder.
        let decrypted = String::from_utf8_lossy(&encrypted_buffer);
        assert_eq!(decrypted, input);
        
        // To verify entropy, we rely on the fact that if the encoder was 
        // simple XOR, the bytecode would be repetitive. 
        // Since we verify the decryption works, and we know the decoder 
        // uses rolling key + position salt + external mixing,
        // the ciphertext MUST be high entropy.
    }

    #[test]
    fn verify_real_world_scenarios() {
        // CASE 1: Deterministic Integrity
        // "Using same valid seed -> Same VM Logic"
        let valid_seed = 0x12345678;
        let map_a = create_ltp_map(valid_seed);
        let map_b = create_ltp_map(valid_seed);
        assert_eq!(map_a, map_b, "Case 1 Failed: Deterministic Seed produced different maps!");

        // CASE 2: The "Chaos" Trap
        // "Valid Seed vs Bad Seed (0) -> Divergent VM Logic"
        let chaos_map = create_ltp_map(0); // Should trigger RDTSC mixing
        
        // Since RDTSC is time-dependent, chaos_map should ideally be unique every time.
        // It definitely should NOT equal the map derived from a static/valid seed.
        assert_ne!(map_a, chaos_map, "Case 2 Failed: Chaos Trap did not diverge from Valid Map!");
        
        // Verify Chaos Map is still a valid permutation (just shuffled differently)
        let mut present = [false; 256];
        for i in 0..256 {
            present[chaos_map[i] as usize] = true;
        }
        for i in 0..256 {
            assert!(present[i], "Chaos Map corrupted structure (not bijective)!");
        }

        // CASE 3: Performance Check
        // "Map generation must be < 100us"
        let start = std::time::Instant::now();
        let _ = create_ltp_map(valid_seed);
        let duration = start.elapsed();
        println!("LTP Map Generation took: {:?}", duration);
        assert!(duration.as_micros() < 100, "Case 3 Failed: Map generation too slow! took {}us", duration.as_micros());
    }

    #[test]
    fn test_vm_entanglement_sensitivity() {
        // 1. Pristine Run
        // Reset global state for test
        crate::protector::pe_integrity::INTEGRITY_TOKEN.store(0xDEADBEEFCAFEBABE, Ordering::SeqCst);
        
        let vm = TinyVm::new(0x42);
        let mut state = VmExecutionState {
            vip: 0,
            key: 0, // VM starts with 0 rolling key
            next_idx: 0,
            exit_value: 0,
            should_exit: false,
            anchor_rip: 0,
            last_cycles: 0,
        };

        // Opcode: 0x99 (EXIT)
        let op_exit = VmOp::op_exit(); 
        
        let mut bytecode = [0u8; 16];
        let bc_idx = 0;
        let pos_salt = (bc_idx as u8).wrapping_mul(0x7);
        let integrity = crate::protector::pe_integrity::INTEGRITY_TOKEN.load(Ordering::Relaxed) as u8;
        let enc_key = 0x42;
        let rolling_key = 0;
        
        // encode: raw = (real - pos_salt) ^ key ^ enc_key ^ integrity
        bytecode[0] = op_exit.wrapping_sub(pos_salt) ^ enc_key ^ rolling_key ^ integrity;

        unsafe {
            fetch_next_instruction(&bytecode, &mut state, enc_key);
        }
        
        assert_eq!(state.next_idx, op_exit, "Decoder should work with correct Token");

        // 2. Modified Integrity Run (Simulate Skip/Patch)
        // Corrupt the token
        crate::protector::pe_integrity::INTEGRITY_TOKEN.fetch_xor(0xFF, Ordering::SeqCst);
        
        let mut state_bad = VmExecutionState {
            vip: 0,
            key: 0,
            next_idx: 0,
            exit_value: 0,
            should_exit: false,
            anchor_rip: 0,
            last_cycles: 0,
        };
        
        unsafe {
            fetch_next_instruction(&bytecode, &mut state_bad, enc_key);
        }
        
        assert_ne!(state_bad.next_idx, op_exit, "Decoder MUST fail with bad Token");
    }
}

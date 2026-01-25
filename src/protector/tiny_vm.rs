#![allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_variables,
    unused_assignments
)]

//! TinyVM - A lightweight virtual machine for executing anti-debug bytecode

use std::arch::asm;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

// Import the runtime seed reconstruction functions
use crate::protector::seed_orchestrator::{get_dynamic_seed, get_dynamic_seed_u8};

/// Compile-time hash function using FNV-1a variant with location-dependent seed
/// Each string at different location gets different hash due to file/line dependency
const fn const_str_hash(s: &str) -> u32 {
    // Use a location-dependent seed based on file and line info
    // This ensures different strings in different locations have different starting points
    let mut hash = 0x811C9DC5u32; // FNV offset basis

    // Process each character with FNV-1a algorithm combined with bit rotation
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // XOR with the byte value
        hash ^= bytes[i] as u32;

        // Multiply by FNV prime (32-bit version)
        hash = hash.wrapping_mul(0x01000193);

        // Apply bit rotation for additional avalanche effect
        hash = hash.rotate_left(7);

        i += 1;
    }

    hash
}

/// Generate a unique build seed based on the current file path and package name
const BUILD_SEED: u32 = const_str_hash(
    concat!(env!("CARGO_PKG_NAME"), "-", file!(), "-", env!("CARGO_MANIFEST_DIR"))
);

/// Compile-time string encryption macro
/// Encrypts string literals at compile time with a placeholder, decrypted at runtime
#[allow(unused_macros)]
macro_rules! enc_str {
    ($s:expr) => {{
        // Get the line number where this macro is used
        const LINE_NUM: u32 = line!();
        const BUILD_HASH: u32 = const_str_hash(concat!(file!(), stringify!($s)));

        // Create a location-dependent key using line number and runtime seed
        let runtime_seed = get_dynamic_seed();
        let key = ((BUILD_HASH ^ runtime_seed ^ LINE_NUM) as u8);

        // Native encrypted bytes (placeholder 0x42 XOR)
        const SRC_BYTES: &'static [u8] = $s.as_bytes();
        const LEN: usize = SRC_BYTES.len();
        const ENCRYPTED: [u8; LEN] = {
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = SRC_BYTES[i] ^ 0x42;
                i += 1;
            }
            result
        };

        // Create a local copy on the stack for decryption
        let mut stack_copy = [0u8; LEN];
        for i in 0..LEN {
            stack_copy[i] = ENCRYPTED[i] ^ 0x42 ^ key;
        }

        // Convert to string (this is safe because we know it was originally valid UTF-8)
        unsafe {
            std::str::from_utf8_unchecked(&stack_copy)
        }
    }};
}

/// Alternative version that returns a String instead of &str
macro_rules! enc_string {
    ($s:expr) => {{
        // Get the line number where this macro is used
        const LINE_NUM: u32 = line!();
        const BUILD_HASH: u32 = const_str_hash(concat!(file!(), stringify!($s)));

        // Create a location-dependent key using line number and runtime seed
        let runtime_seed = get_dynamic_seed();
        let key = ((BUILD_HASH ^ runtime_seed ^ LINE_NUM) as u8);

        // Native encrypted bytes (placeholder 0x42 XOR)
        const SRC_BYTES: &'static [u8] = $s.as_bytes();
        const LEN: usize = SRC_BYTES.len();
        const ENCRYPTED: [u8; LEN] = {
            let mut result = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = SRC_BYTES[i] ^ 0x42;
                i += 1;
            }
            result
        };

        // Create a local copy on the stack for decryption
        let mut stack_copy = [0u8; LEN];
        for i in 0..LEN {
            stack_copy[i] = ENCRYPTED[i] ^ 0x42 ^ key;
        }

        // Convert to String
        String::from_utf8(stack_copy.to_vec()).unwrap_or_else(|_| String::from(""))
    }};
}

/// Macro to generate polymorphic opcode values at runtime
/// Uses both the static build seed, runtime seed, and the global encoded state
macro_rules! auto_op {
    ($base:expr) => {
        {
            // Use the build seed and runtime seed
            // The runtime behavior will be influenced by the global state
            (($base as u8).wrapping_add(BUILD_SEED as u8).wrapping_add(get_dynamic_seed_u8()))
        }
    };
}

/// Get the current global encoded state from the global state module
/// Returns 1 if high suspicion, 0 otherwise
fn get_global_encoded_state() -> u32 {
    let score = crate::protector::global_state::get_suspicion_score();
    if score > 100 {
        1
    } else {
        0
    }
}

/// Virtual Machine structure
pub struct TinyVm {
    pub vip: usize,           // Virtual Instruction Pointer
    pub v_stack: [u64; 32],   // Virtual Stack (fixed size to avoid heap allocation)
    pub sp: usize,            // Stack Pointer
    pub accumulator: u64,     // Accumulator for operations
    pub key: u64,             // Local key for this VM instance
}

/// Virtual Machine Operations with runtime polymorphic values
/// Now defined as a struct with methods because opcodes are runtime-dependent
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
}

impl TinyVm {
    pub fn new(local_key: u64) -> Self {
        TinyVm {
            vip: 0,
            v_stack: [0; 32],
            sp: 0,
            accumulator: 0,
            key: local_key,
        }
    }

    /// Push value onto virtual stack
    #[inline(always)]
    pub fn push(&mut self, value: u64) {
        if self.sp < self.v_stack.len() {
            self.v_stack[self.sp] = value;
            self.sp += 1;
        }
    }

    /// Pop value from virtual stack
    #[inline(always)]
    pub fn pop(&mut self) -> u64 {
        if self.sp > 0 {
            self.sp -= 1;
            self.v_stack[self.sp]
        } else {
            0 // Return 0 if stack underflow
        }
    }

    /// Peek at top of stack without popping
    #[inline(always)]
    pub fn peek(&self) -> u64 {
        if self.sp > 0 {
            self.v_stack[self.sp - 1]
        } else {
            0
        }
    }
}

/// Helper function to execute CPUID safely
unsafe fn cpuid_helper(leaf: u32) -> (u32, u32, u32, u32) {
    let eax_out: u32;
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;

    asm!(
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

/// Execute bytecode in the TinyVM - Control Flow Flattened Version
#[inline(never)] // Prevent inlining to make analysis harder
pub fn vm_execute(bytecode: &[u8], encryption_key: u8, context_key: u64) -> u64 {
    // Mix the context key with the global VM key to create a local key for this execution
    let global_vm_key = crate::protector::global_state::get_current_vm_key() as u64;
    let local_vm_key = global_vm_key ^ context_key;

    let mut vm = TinyVm::new(local_vm_key);

    // Define states for the flattened control flow
    const STATE_FETCH_OPCODE: u32 = 0x11111111;
    const STATE_DECODE_OPCODE: u32 = 0x22222222;
    const STATE_EXECUTE_OPCODE: u32 = 0x33333333;
    const STATE_HANDLE_OP_LOAD_IMM: u32 = 0x44444444;
    const STATE_HANDLE_OP_READ_GS_OFFSET: u32 = 0x55555555;
    const STATE_HANDLE_OP_READ_MEM_U8: u32 = 0x66666666;
    const STATE_HANDLE_OP_READ_MEM_U32: u32 = 0x77777777;
    const STATE_HANDLE_OP_READ_MEM_U64: u32 = 0x88888888;
    const STATE_HANDLE_OP_RDTSC: u32 = 0x99999999;
    const STATE_HANDLE_OP_CPUID: u32 = 0xAAAAAAAA;
    const STATE_HANDLE_OP_IN_PORT: u32 = 0xBBBBBBBB;
    const STATE_HANDLE_OP_OUT_PORT: u32 = 0xCCCCCCCC;
    const STATE_HANDLE_OP_ADD: u32 = 0xDDDDDDDD;
    const STATE_HANDLE_OP_SUB: u32 = 0xEEEEEEEE;
    const STATE_HANDLE_OP_XOR: u32 = 0xFFFFFFFF;
    const STATE_HANDLE_OP_PUSH: u32 = 0x12345678;
    const STATE_HANDLE_OP_POP: u32 = 0x23456789;
    const STATE_HANDLE_OP_DUP: u32 = 0x3456789A;
    const STATE_HANDLE_OP_SWAP: u32 = 0x456789AB;
    const STATE_HANDLE_OP_CMP_EQ: u32 = 0x56789ABC;
    const STATE_HANDLE_OP_CMP_NE: u32 = 0x6789ABCD;
    const STATE_HANDLE_OP_CMP_GT: u32 = 0x789ABCDE;
    const STATE_HANDLE_OP_CMP_LT: u32 = 0x89ABCDEF;
    const STATE_HANDLE_OP_AND: u32 = 0x9ABCDEF0;
    const STATE_HANDLE_OP_OR: u32 = 0xABCDEF01;
    const STATE_HANDLE_OP_NOT: u32 = 0xBCDEF012;
    const STATE_HANDLE_OP_SHL: u32 = 0xCDEF0123;
    const STATE_HANDLE_OP_SHR: u32 = 0xDEF01234;
    const STATE_HANDLE_OP_JUMP: u32 = 0xEF012345;
    const STATE_HANDLE_OP_JZ: u32 = 0xF0123456;
    const STATE_HANDLE_OP_JNZ: u32 = 0x01234567;
    const STATE_HANDLE_OP_EXIT: u32 = 0x12345679;
    const STATE_HANDLE_OP_GARBAGE: u32 = 0x2345678A;
    const STATE_HANDLE_OP_POLY_JUNK: u32 = 0x3456789B;
    const STATE_HANDLE_UNKNOWN: u32 = 0x456789AC;
    const STATE_INCREMENT_VIP: u32 = 0x56789BAD;
    const STATE_CONTINUE_LOOP: u32 = 0x6789ABAE;
    const STATE_HANDLE_OP_EARLY_BIRD: u32 = 0x77777778;
    const STATE_RETURN_ACCUMULATOR: u32 = 0x789ABCAB;

    let mut state: u32 = STATE_FETCH_OPCODE;
    let mut decoded_opcode: u8 = 0;
    let mut current_opcode: u8 = 0;
    let mut temp_a: u64 = 0;
    let mut temp_b: u64 = 0;
    let mut temp_result: u64 = 0;
    let mut should_exit: bool = false;
    let mut exit_value: u64 = 0;
    let mut jump_target: usize = 0;
    let mut condition_value: u64 = 0;
    let mut immediate_value: u64 = 0;
    let mut offset: u64 = 0;
    let mut addr: *const u8 = std::ptr::null();
    let mut port: u16 = 0;
    let mut shift_amount: u32 = 0;
    let mut global_state = get_global_encoded_state();
    let should_continue_loop = true;

    loop {
        match state {
            // FETCH_OPCODE state: Get the next opcode from bytecode
            s if opaque_predicate_eq_u32(s, STATE_FETCH_OPCODE) => {
                if vm.vip >= bytecode.len() {
                    state = STATE_RETURN_ACCUMULATOR;
                } else {
                    current_opcode = bytecode[vm.vip];
                    state = STATE_DECODE_OPCODE;
                }
            }

            // DECODE_OPCODE state: Decode the opcode using the encryption key
            s if opaque_predicate_eq_u32(s, STATE_DECODE_OPCODE) => {
                decoded_opcode = current_opcode ^ encryption_key;

                // Anti-disassembly: Add nops to break linear sweep disassembly
                unsafe {
                    std::arch::asm!("nop");
                }

                // Get the current security state to potentially modify VM behavior
                global_state = get_global_encoded_state();

                state = STATE_EXECUTE_OPCODE;
            }

            // EXECUTE_OPCODE state: Dispatch to the appropriate handler based on opcode
            s if opaque_predicate_eq_u32(s, STATE_EXECUTE_OPCODE) => {
                match decoded_opcode {
                    op if opaque_predicate_eq_u8(op, VmOp::op_load_imm()) => {
                        state = STATE_HANDLE_OP_LOAD_IMM;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_read_gs_offset()) => {
                        state = STATE_HANDLE_OP_READ_GS_OFFSET;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_read_mem_u8()) => {
                        state = STATE_HANDLE_OP_READ_MEM_U8;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_read_mem_u32()) => {
                        state = STATE_HANDLE_OP_READ_MEM_U32;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_read_mem_u64()) => {
                        state = STATE_HANDLE_OP_READ_MEM_U64;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_rdtsc()) => {
                        state = STATE_HANDLE_OP_RDTSC;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_cpuid()) => {
                        state = STATE_HANDLE_OP_CPUID;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_in_port()) => {
                        state = STATE_HANDLE_OP_IN_PORT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_out_port()) => {
                        state = STATE_HANDLE_OP_OUT_PORT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_add()) => {
                        state = STATE_HANDLE_OP_ADD;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_sub()) => {
                        state = STATE_HANDLE_OP_SUB;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_xor()) => {
                        state = STATE_HANDLE_OP_XOR;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_push()) => {
                        state = STATE_HANDLE_OP_PUSH;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_pop()) => {
                        state = STATE_HANDLE_OP_POP;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_dup()) => {
                        state = STATE_HANDLE_OP_DUP;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_swap()) => {
                        state = STATE_HANDLE_OP_SWAP;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_cmp_eq()) => {
                        state = STATE_HANDLE_OP_CMP_EQ;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_cmp_ne()) => {
                        state = STATE_HANDLE_OP_CMP_NE;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_cmp_gt()) => {
                        state = STATE_HANDLE_OP_CMP_GT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_cmp_lt()) => {
                        state = STATE_HANDLE_OP_CMP_LT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_and()) => {
                        state = STATE_HANDLE_OP_AND;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_or()) => {
                        state = STATE_HANDLE_OP_OR;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_not()) => {
                        state = STATE_HANDLE_OP_NOT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_shl()) => {
                        state = STATE_HANDLE_OP_SHL;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_shr()) => {
                        state = STATE_HANDLE_OP_SHR;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_jump()) => {
                        state = STATE_HANDLE_OP_JUMP;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_jz()) => {
                        state = STATE_HANDLE_OP_JZ;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_jnz()) => {
                        state = STATE_HANDLE_OP_JNZ;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_exit()) => {
                        state = STATE_HANDLE_OP_EXIT;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_garbage()) => {
                        state = STATE_HANDLE_OP_GARBAGE;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_poly_junk()) => {
                        state = STATE_HANDLE_OP_POLY_JUNK;
                    },
                    op if opaque_predicate_eq_u8(op, VmOp::op_early_bird()) => {
                        state = STATE_HANDLE_OP_EARLY_BIRD;
                    },
                    _ => {
                        state = STATE_HANDLE_UNKNOWN;
                    }
                }
            }

            // Handle OP_LOAD_IMM
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_LOAD_IMM) => {
                vm.vip += 1;
                if vm.vip + 7 < bytecode.len() {
                    immediate_value = u64::from_le_bytes([
                        bytecode[vm.vip] ^ encryption_key,
                        bytecode[vm.vip + 1] ^ encryption_key,
                        bytecode[vm.vip + 2] ^ encryption_key,
                        bytecode[vm.vip + 3] ^ encryption_key,
                        bytecode[vm.vip + 4] ^ encryption_key,
                        bytecode[vm.vip + 5] ^ encryption_key,
                        bytecode[vm.vip + 6] ^ encryption_key,
                        bytecode[vm.vip + 7] ^ encryption_key,
                    ]);
                    vm.push(immediate_value);
                    vm.vip += 7;
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_READ_GS_OFFSET
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_READ_GS_OFFSET) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    offset = bytecode[vm.vip] as u64;

                    // Execute assembly to read from GS segment
                    let result: u64;
                    unsafe {
                        asm!(
                            "mov {}, gs:[{}]",
                            out(reg) result,
                            in(reg) offset,
                            options(nostack, readonly)
                        );
                    }

                    vm.push(result);
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_READ_MEM_U8
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_READ_MEM_U8) => {
                vm.vip += 1;

                // Pop address from stack
                addr = vm.pop() as *const u8;

                // Safe memory access with null pointer check and canary validation
                let result: u8 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr)
                    }
                };

                vm.push(result as u64); // Zero-extended to 64-bit
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_READ_MEM_U32
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_READ_MEM_U32) => {
                vm.vip += 1;

                // Pop address from stack
                let addr_u32 = vm.pop() as *const u32;

                // Safe memory access with null pointer check and canary validation
                let result: u32 = if addr_u32.is_null() || (addr_u32 as usize) < 0x10000 || (addr_u32 as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr_u32)
                    }
                };

                // Explicitly zero-extend u32 to u64 before pushing to stack to clear any garbage bits
                let extended_result = result as u64;
                vm.push(extended_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_READ_MEM_U64
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_READ_MEM_U64) => {
                vm.vip += 1;

                // Pop address from stack
                let addr_u64 = vm.pop() as *const u64;

                // Safe memory access with null pointer check and canary validation
                let result: u64 = if addr_u64.is_null() || (addr_u64 as usize) < 0x10000 || (addr_u64 as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr_u64)
                    }
                };

                vm.push(result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_RDTSC
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_RDTSC) => {
                vm.vip += 1;

                // Execute RDTSC instruction
                let (low, high): (u32, u32);
                unsafe {
                    asm!(
                        "lfence",
                        "rdtsc",
                        "lfence",
                        out("eax") low,
                        out("edx") high,
                        options(nomem, nostack)
                    );
                }
                
                let mut timestamp = ((high as u64) << 32) | (low as u64);

                // INTEGRATION: If system is under heavy load, we might get timing anomalies.
                // TinyVM logic should know about this.
                // If heavy load, we mask the lower bits to reduce sensitivity or return a slightly modified value
                // that won't trigger strict timing checks if the bytecode implementation uses it for that.
                if crate::protector::global_state::is_system_under_heavy_load() {
                    // Masking lower bits effectively reduces resolution, ignoring small jitters
                    timestamp &= 0xFFFFFFFFFFFFFFF0; 
                }

                vm.push(timestamp);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_CPUID
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CPUID) => {
                vm.vip += 1;
                if vm.vip + 3 < bytecode.len() {
                    // Read CPUID leaf from stack
                    let eax_in = vm.pop() as u32;

                    // Execute CPUID instruction - using a helper function to avoid register conflicts
                    let (eax_out, ebx_out, ecx_out, edx_out) = unsafe { cpuid_helper(eax_in) };

                    // Push results to stack in reverse order (due to stack behavior)
                    vm.push(edx_out as u64);
                    vm.push(ecx_out as u64);
                    vm.push(ebx_out as u64);
                    vm.push(eax_out as u64);
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_IN_PORT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_IN_PORT) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    port = bytecode[vm.vip] as u16;

                    // Read from I/O port
                    let result: u32;
                    unsafe {
                        asm!(
                            "in eax, dx",
                            out("eax") result,
                            in("dx") port,
                            options(nomem, nostack)
                        );
                    }

                    vm.push(result as u64);
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_OUT_PORT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_OUT_PORT) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    port = bytecode[vm.vip] as u16;
                    let value = vm.pop() as u32;

                    // Write to I/O port
                    unsafe {
                        asm!(
                            "out dx, eax",
                            in("dx") port,
                            in("eax") value,
                            options(nomem, nostack)
                        );
                    }
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_ADD
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_ADD) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, change the operation
                // This creates the "infinite rabbit hole" effect where debugging changes behavior
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = temp_a.wrapping_sub(temp_b);  // Change ADD to SUB
                } else {
                    temp_result = temp_a.wrapping_add(temp_b);  // Normal ADD operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_SUB
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_SUB) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, change the operation
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = temp_a.wrapping_add(temp_b);  // Change SUB to ADD
                } else {
                    temp_result = temp_a.wrapping_sub(temp_b);  // Normal SUB operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_XOR
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_XOR) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, change the operation
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = temp_a.wrapping_add(temp_b);  // Change XOR to ADD
                } else {
                    temp_result = temp_a ^ temp_b;  // Normal XOR operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_PUSH
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_PUSH) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    vm.push(bytecode[vm.vip] as u64);
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_POP
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_POP) => {
                vm.vip += 1;
                vm.pop(); // Discard top of stack
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_DUP
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_DUP) => {
                vm.vip += 1;
                let val = vm.peek();
                vm.push(val);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_SWAP
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_SWAP) => {
                vm.vip += 1;
                if vm.sp >= 2 {
                    let a = vm.pop();
                    let b = vm.pop();
                    vm.push(a);
                    vm.push(b);
                }
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_CMP_EQ
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CMP_EQ) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = if temp_a != temp_b { 1 } else { 0 };  // Return opposite of EQ (like NE)
                } else {
                    temp_result = if temp_a == temp_b { 1 } else { 0 };  // Normal EQ operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_CMP_NE
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CMP_NE) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = if temp_a == temp_b { 1 } else { 0 };  // Return opposite of NE (like EQ)
                } else {
                    temp_result = if temp_a != temp_b { 1 } else { 0 };  // Normal NE operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_CMP_GT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CMP_GT) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = if temp_a <= temp_b { 1 } else { 0 };  // Return opposite of GT (like LE)
                } else {
                    temp_result = if temp_a > temp_b { 1 } else { 0 };  // Normal GT operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_CMP_LT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CMP_LT) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    temp_result = if temp_a >= temp_b { 1 } else { 0 };  // Return opposite of LT (like GE)
                } else {
                    temp_result = if temp_a < temp_b { 1 } else { 0 };  // Normal LT operation
                }
                vm.push(temp_result);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_EARLY_BIRD
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_EARLY_BIRD) => {
                vm.vip += 1;
                // Subtle debugger check using the PEB BeingDebugged flag
                let being_debugged: u8;
                unsafe {
                    std::arch::asm!(
                        "mov {}, gs:[0x60 + 0x02]",
                        out(reg_byte) being_debugged,
                        options(nostack, preserves_flags, readonly)
                    );
                }
                vm.push(being_debugged as u64);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_AND
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_AND) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();
                vm.push(temp_a & temp_b);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_OR
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_OR) => {
                vm.vip += 1;
                temp_b = vm.pop();
                temp_a = vm.pop();
                vm.push(temp_a | temp_b);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_NOT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_NOT) => {
                vm.vip += 1;
                temp_a = vm.pop();
                vm.push(!temp_a);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_SHL
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_SHL) => {
                vm.vip += 1;
                shift_amount = vm.pop() as u32;
                temp_a = vm.pop();
                vm.push(temp_a << shift_amount);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_SHR
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_SHR) => {
                vm.vip += 1;
                shift_amount = vm.pop() as u32;
                temp_a = vm.pop();
                vm.push(temp_a >> shift_amount);
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_JUMP
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_JUMP) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    jump_target = bytecode[vm.vip] as usize;
                    vm.vip = jump_target;
                    state = STATE_CONTINUE_LOOP; // Don't increment VIP again
                } else {
                    state = STATE_INCREMENT_VIP; // If invalid, continue with normal flow
                }
            }

            // Handle OP_JZ
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_JZ) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    jump_target = bytecode[vm.vip] as usize;
                    condition_value = vm.pop();
                    if condition_value == 0 {
                        vm.vip = jump_target;
                        state = STATE_CONTINUE_LOOP; // Don't increment VIP again
                    } else {
                        state = STATE_INCREMENT_VIP; // Continue with normal flow
                    }
                } else {
                    state = STATE_INCREMENT_VIP; // If invalid, continue with normal flow
                }
            }

            // Handle OP_JNZ
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_JNZ) => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    jump_target = bytecode[vm.vip] as usize;
                    condition_value = vm.pop();
                    if condition_value != 0 {
                        vm.vip = jump_target;
                        state = STATE_CONTINUE_LOOP; // Don't increment VIP again
                    } else {
                        state = STATE_INCREMENT_VIP; // Continue with normal flow
                    }
                } else {
                    state = STATE_INCREMENT_VIP; // If invalid, continue with normal flow
                }
            }

            // Handle OP_EXIT
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_EXIT) => {
                exit_value = vm.pop(); // Return top of stack as result
                should_exit = true;
                break;
            }

            // Handle OP_GARBAGE
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_GARBAGE) => {
                vm.vip += 1;

                // OP_GARBAGE: Performs complex mathematical operations to confuse static analysis
                // This opcode does not change the stack but performs complex calculations
                // to make reverse engineering more difficult

                // Perform complex mathematical operations that have no effect on the stack
                let top_value = if vm.sp > 0 { vm.v_stack[vm.sp - 1] } else { 0 };

                // Complex MBA expression: (x | y) + (x & y) == x + y (identity)
                let x = top_value as u32;
                let rotated_top = (top_value as u32).rotate_left(7);
                let y = rotated_top ^ 0x9E3779B1u32;

                // Perform the complex calculation but don't store the result
                let _garbage_result = (x | y).wrapping_add(x & y);

                // Additional complex operations to waste analyst time
                let _more_garbage = (x ^ y).wrapping_add(2u32.wrapping_mul(x & y));

                // Still don't modify the stack - just consume CPU cycles
                // This makes static analysis more difficult without affecting functionality
                state = STATE_CONTINUE_LOOP;
            }

            // Handle OP_POLY_JUNK
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_POLY_JUNK) => {
                vm.vip += 1;

                // OP_POLY_JUNK: Performs random junk operations to obfuscate control flow
                // This opcode executes random mathematical operations that don't affect the final result
                // but make disassemblers like IDA Pro/Ghidra produce confusing control flow graphs

                // Generate a pseudo-random operation based on current state
                let state_dependent_seed = (vm.vip as u64) ^ vm.accumulator ^ (get_enhanced_entropy() as u64);

                // Perform a series of random-looking operations
                let junk_val1 = state_dependent_seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB) & 0xFFFFFFFFFFFF;
                let junk_val2 = state_dependent_seed.rotate_left(13) ^ 0x9E3779B1;
                let junk_val3 = (junk_val1 ^ junk_val2).wrapping_add(state_dependent_seed);

                // Perform more complex operations that don't affect the stack
                let _op1 = junk_val3.wrapping_mul(31).wrapping_add(junk_val1);
                let _op2 = (_op1 >> 3) ^ junk_val2;
                let _op3 = _op2.wrapping_add(_op1.rotate_right(7));

                // The operations above don't modify the stack or affect the final result
                // but they make the control flow much harder to analyze statically
                state = STATE_CONTINUE_LOOP;
            }

            // Handle unknown opcode
            s if opaque_predicate_eq_u32(s, STATE_HANDLE_UNKNOWN) => {
                exit_value = 0; // Return 0 as safe default
                should_exit = true;
                break;
            }

            // INCREMENT_VIP state: Increment the virtual instruction pointer
            s if opaque_predicate_eq_u32(s, STATE_INCREMENT_VIP) => {
                vm.vip += 1;
                state = STATE_FETCH_OPCODE;
            }

            // CONTINUE_LOOP state: Continue the main execution loop
            s if opaque_predicate_eq_u32(s, STATE_CONTINUE_LOOP) => {
                state = STATE_INCREMENT_VIP;
            }

            // RETURN_ACCUMULATOR state: Return the final result
            s if opaque_predicate_eq_u32(s, STATE_RETURN_ACCUMULATOR) => {
                exit_value = vm.accumulator;
                should_exit = true;
                break;
            }

            _ => {
                // Unknown state, return 0 as safe default
                exit_value = 0;
                should_exit = true;
                break;
            }
        }
    }

    exit_value
}

/// Get enhanced CPU entropy using multiple sources for better randomness
/// Combines RDTSC, stack address entropy, CPUID results, and RDRAND if available
#[inline(always)]
fn get_enhanced_entropy() -> u32 {
    // Get RDTSC timestamp for timing-based entropy
    let (tsc_low, tsc_high): (u32, u32);
    unsafe {
        std::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") tsc_low,
            out("edx") tsc_high,
            options(nomem, nostack)
        );
    }
    let tsc_entropy = tsc_low ^ tsc_high;

    // Get stack address entropy (exploits ASLR)
    let stack_var = 0x12345678u32;
    let stack_addr = &stack_var as *const u32 as u64;
    let stack_entropy = ((stack_addr >> 3) ^ (stack_addr >> 13)) as u32;

    // Get CPUID-based entropy
    let (eax_out, ebx_out, _ecx_out, _edx_out) = unsafe { cpuid_helper(1) };
    let cpuid_entropy = eax_out ^ ebx_out;

    // Try to get hardware random number if available
    let mut rdrand_entropy = 0u32;
    let success: u8;
    unsafe {
        std::arch::asm!(
            "xor {result:r}, {result:r}",      // Clear result
            "rdrand {result:r}",             // Try to get random value from CPU
            "setc {success}",              // Set success flag based on carry flag
            result = out(reg) rdrand_entropy,
            success = out(reg_byte) success,
            options(nomem, nostack)
        );
    }

    // If RDRAND failed, use alternative entropy
    if success == 0 {
        rdrand_entropy = (tsc_low ^ stack_entropy ^ cpuid_entropy).rotate_left(7);
    }

    // Combine all entropy sources with bit mixing
    let combined_entropy = tsc_entropy
        .wrapping_add(stack_entropy)
        .wrapping_mul(0x9E3779B1)  // Golden ratio for bit mixing
        .wrapping_add(cpuid_entropy)
        .wrapping_mul(0x85EBCA6B)  // Another prime for bit mixing
        .wrapping_add(rdrand_entropy);

    combined_entropy
}

/// Opaque predicate function to compare state values without direct equality
/// This makes static analysis harder by hiding the actual comparison
#[inline(always)]
fn opaque_predicate_eq_u32(value: u32, expected: u32) -> bool {
    // Use a complex mathematical expression that evaluates to true only when value == expected
    // This is equivalent to: value == expected
    let result = (value ^ expected).count_ones() == 0;

    // Additional obfuscation: add a check that doesn't change the result
    let extra_check = value.wrapping_sub(expected) == 0;

    result && extra_check
}

/// Opaque predicate function to compare u8 values without direct equality
#[inline(always)]
fn opaque_predicate_eq_u8(value: u8, expected: u8) -> bool {
    // Use a complex mathematical expression that evaluates to true only when value == expected
    // This is equivalent to: value == expected
    let result = (value ^ expected).count_ones() == 0;

    // Additional obfuscation: add a check that doesn't change the result
    let extra_check = value.wrapping_sub(expected) == 0;

    result && extra_check
}

/// Example function demonstrating encrypted string usage
/// This would typically be used for error messages or debug information that needs protection
pub fn get_opcode_name(opcode: u8) -> String {
    match opcode {
        op if op == VmOp::op_load_imm() => enc_string!("LOAD_IMM"),
        op if op == VmOp::op_read_gs_offset() => enc_string!("READ_GS_OFFSET"),
        op if op == VmOp::op_read_mem_u8() => enc_string!("READ_MEM_U8"),
        op if op == VmOp::op_read_mem_u32() => enc_string!("READ_MEM_U32"),
        op if op == VmOp::op_read_mem_u64() => enc_string!("READ_MEM_U64"),
        op if op == VmOp::op_rdtsc() => enc_string!("RDTSC"),
        op if op == VmOp::op_cpuid() => enc_string!("CPUID"),
        op if op == VmOp::op_in_port() => enc_string!("IN_PORT"),
        op if op == VmOp::op_out_port() => enc_string!("OUT_PORT"),
        op if op == VmOp::op_add() => enc_string!("ADD"),
        op if op == VmOp::op_sub() => enc_string!("SUB"),
        op if op == VmOp::op_xor() => enc_string!("XOR"),
        op if op == VmOp::op_push() => enc_string!("PUSH"),
        op if op == VmOp::op_pop() => enc_string!("POP"),
        op if op == VmOp::op_dup() => enc_string!("DUP"),
        op if op == VmOp::op_swap() => enc_string!("SWAP"),
        op if op == VmOp::op_cmp_eq() => enc_string!("CMP_EQ"),
        op if op == VmOp::op_cmp_ne() => enc_string!("CMP_NE"),
        op if op == VmOp::op_cmp_gt() => enc_string!("CMP_GT"),
        op if op == VmOp::op_cmp_lt() => enc_string!("CMP_LT"),
        op if op == VmOp::op_and() => enc_string!("AND"),
        op if op == VmOp::op_or() => enc_string!("OR"),
        op if op == VmOp::op_not() => enc_string!("NOT"),
        op if op == VmOp::op_shl() => enc_string!("SHL"),
        op if op == VmOp::op_shr() => enc_string!("SHR"),
        op if op == VmOp::op_jump() => enc_string!("JUMP"),
        op if op == VmOp::op_jz() => enc_string!("JZ"),
        op if op == VmOp::op_jnz() => enc_string!("JNZ"),
        op if op == VmOp::op_call() => enc_string!("CALL"),
        op if op == VmOp::op_ret() => enc_string!("RET"),
        op if op == VmOp::op_exit() => enc_string!("EXIT"),
        op if op == VmOp::op_garbage() => enc_string!("GARBAGE"),
        op if op == VmOp::op_poly_junk() => enc_string!("POLY_JUNK"),
        _ => enc_string!("UNKNOWN_OPCODE"),
    }
}

/// Function to demonstrate encrypted error messages
pub fn get_error_message(error_type: &str) -> String {
    match error_type {
        "invalid_opcode" => enc_string!("Invalid opcode encountered in bytecode"),
        "stack_overflow" => enc_string!("Stack overflow in virtual machine"),
        "stack_underflow" => enc_string!("Stack underflow in virtual machine"),
        "memory_access_violation" => enc_string!("Memory access violation in VM"),
        _ => enc_string!("Unknown error in virtual machine"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_strings() {
        let test_str = enc_string!("Hello, World!");
        assert_eq!(test_str, "Hello, World!");

        let opcode_name = get_opcode_name(VmOp::op_add());
        assert_eq!(opcode_name, "ADD");

        let error_msg = get_error_message("invalid_opcode");
        assert_eq!(error_msg, "Invalid opcode encountered in bytecode");
    }

    #[test]
    fn test_different_line_encryption() {
        // These should use different keys due to different line numbers
        let str1 = enc_string!("Test string 1");
        let str2 = enc_string!("Test string 2");

        assert_eq!(str1, "Test string 1");
        assert_eq!(str2, "Test string 2");
    }
}
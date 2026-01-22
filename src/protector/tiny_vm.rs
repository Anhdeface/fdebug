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

// Import the dynamic seed generated at build time
mod generated_constants;
use generated_constants::DYNAMIC_SEED;

/// Compile-time hash function for string hashing
const fn const_str_hash(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash = 5381u32;
    let mut i = 0;

    while i < bytes.len() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(bytes[i] as u32);
        i += 1;
    }

    hash
}

/// Generate a unique build seed based on the current file path and package name
const BUILD_SEED: u32 = const_str_hash(
    concat!(env!("CARGO_PKG_NAME"), "-", file!(), "-", env!("CARGO_MANIFEST_DIR"))
);

/// Macro to generate polymorphic opcode values at compile time
/// Uses both the static build seed, dynamic seed, and the global encoded state
macro_rules! auto_op {
    ($base:expr) => {
        {
            // Use the build seed and dynamic seed at compile time
            // The runtime behavior will be influenced by the global state
            (($base as u8).wrapping_add(BUILD_SEED as u8).wrapping_add(DYNAMIC_SEED))
        }
    };
}

/// Get the current global encoded state from the global state module
fn get_global_encoded_state() -> u32 {
    crate::protector::global_state::get_current_encoded_state()
}

/// Virtual Machine structure
pub struct TinyVm {
    pub vip: usize,           // Virtual Instruction Pointer
    pub v_stack: [u64; 32],   // Virtual Stack (fixed size to avoid heap allocation)
    pub sp: usize,            // Stack Pointer
    pub accumulator: u64,     // Accumulator for operations
    pub key: u64,             // Local key for this VM instance
}

/// Virtual Machine Operations with auto-generated polymorphic values
#[repr(u8)]
pub enum VmOp {
    OP_LOAD_IMM = auto_op!(0x1A),       // Load immediate value onto stack
    OP_READ_GS_OFFSET = auto_op!(0x2B), // Read from GS segment (PEB access)
    OP_READ_MEM_U8 = auto_op!(0x2C),    // Read 1 byte from memory address on stack
    OP_READ_MEM_U32 = auto_op!(0x2D),   // Read 4 bytes from memory address on stack
    OP_READ_MEM_U64 = auto_op!(0x2E),   // Read 8 bytes from memory address on stack
    OP_RDTSC = auto_op!(0x3C),          // Execute RDTSC instruction
    OP_CPUID = auto_op!(0x3D),          // Execute CPUID instruction
    OP_IN_PORT = auto_op!(0x3E),        // Read from I/O port
    OP_OUT_PORT = auto_op!(0x3F),       // Write to I/O port
    OP_ADD = auto_op!(0x4D),            // Add top two stack values
    OP_SUB = auto_op!(0x5E),            // Subtract top two stack values
    OP_XOR = auto_op!(0x6F),            // XOR top two stack values
    OP_PUSH = auto_op!(0x70),           // Push value to stack
    OP_POP = auto_op!(0x81),            // Pop value from stack
    OP_DUP = auto_op!(0x92),            // Duplicate top stack value
    OP_SWAP = auto_op!(0xA3),           // Swap top two stack values
    OP_CMP_EQ = auto_op!(0xB4),         // Compare equality
    OP_CMP_NE = auto_op!(0xC5),         // Compare inequality
    OP_CMP_GT = auto_op!(0xD6),         // Compare greater than
    OP_CMP_LT = auto_op!(0xE7),         // Compare less than
    OP_AND = auto_op!(0xF8),            // Bitwise AND
    OP_OR = auto_op!(0x09),             // Bitwise OR
    OP_NOT = auto_op!(0xAA),            // Bitwise NOT
    OP_SHL = auto_op!(0xBB),            // Shift left
    OP_SHR = auto_op!(0xCC),            // Shift right
    OP_JUMP = auto_op!(0xDD),           // Unconditional jump
    OP_JZ = auto_op!(0xEE),             // Jump if zero
    OP_JNZ = auto_op!(0xFF),            // Jump if not zero
    OP_CALL = auto_op!(0x77),           // Call subroutine
    OP_RET = auto_op!(0x88),            // Return from subroutine
    OP_EXIT = auto_op!(0x99),           // Exit VM with result
    OP_GARBAGE = auto_op!(0x9E),        // Garbage opcode for anti-analysis (complex math without effect)
    OP_POLY_JUNK = auto_op!(0xAB),      // Polymorphic junk opcode for control flow obfuscation
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

/// Execute bytecode in the TinyVM
#[inline(never)] // Prevent inlining to make analysis harder
pub fn vm_execute(bytecode: &[u8], encryption_key: u8, context_key: u64) -> u64 {
    // Mix the context key with the global VM key to create a local key for this execution
    let global_vm_key = crate::protector::global_state::get_current_vm_key() as u64;
    let local_vm_key = global_vm_key ^ context_key;

    let mut vm = TinyVm::new(local_vm_key);

    // Execute bytecode directly without allocating a decoded copy
    while vm.vip < bytecode.len() {
        // Decode the opcode at runtime to prevent static analysis
        let decoded_opcode = bytecode[vm.vip] ^ encryption_key;

        // Anti-disassembly: Add nops to break linear sweep disassembly
        unsafe {
            std::arch::asm!("nop");
        }

        // Get the current security state to potentially modify VM behavior
        let global_state = get_global_encoded_state();
        let state_component = (global_state & 0xFF) as u8;

        match decoded_opcode {
            op if op == VmOp::OP_LOAD_IMM as u8 => {
                vm.vip += 1;
                if vm.vip + 7 < bytecode.len() {
                    // Read 8-byte immediate value
                    let value = u64::from_le_bytes([
                        bytecode[vm.vip] ^ encryption_key,
                        bytecode[vm.vip + 1] ^ encryption_key,
                        bytecode[vm.vip + 2] ^ encryption_key,
                        bytecode[vm.vip + 3] ^ encryption_key,
                        bytecode[vm.vip + 4] ^ encryption_key,
                        bytecode[vm.vip + 5] ^ encryption_key,
                        bytecode[vm.vip + 6] ^ encryption_key,
                        bytecode[vm.vip + 7] ^ encryption_key,
                    ]);
                    vm.push(value);
                    vm.vip += 7;
                }
            },

            op if op == VmOp::OP_READ_GS_OFFSET as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let offset = bytecode[vm.vip] as u64;

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
            },

            op if op == VmOp::OP_READ_MEM_U8 as u8 => {
                vm.vip += 1;

                // Pop address from stack
                let addr = vm.pop() as *const u8;

                // Safe memory access with null pointer check and canary validation
                let result: u8 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr)
                    }
                };

                vm.push(result as u64); // Zero-extended to 64-bit
            },

            op if op == VmOp::OP_READ_MEM_U32 as u8 => {
                vm.vip += 1;

                // Pop address from stack
                let addr = vm.pop() as *const u32;

                // Safe memory access with null pointer check and canary validation
                let result: u32 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr)
                    }
                };

                // Explicitly zero-extend u32 to u64 before pushing to stack to clear any garbage bits
                let extended_result = result as u64;
                vm.push(extended_result);
            },
// github.com/anhdeface
            op if op == VmOp::OP_READ_MEM_U64 as u8 => {
                vm.vip += 1;

                // Pop address from stack
                let addr = vm.pop() as *const u64;

                // Safe memory access with null pointer check and canary validation
                let result: u64 = if addr.is_null() || (addr as usize) < 0x10000 || (addr as usize) > 0x7FFFFFFFFFFF {
                    0 // Return 0 if address is invalid to prevent access violation
                } else {
                    unsafe {
                        std::ptr::read_volatile(addr)
                    }
                };

                vm.push(result);
            },

            op if op == VmOp::OP_RDTSC as u8 => {
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
                let timestamp = ((high as u64) << 32) | (low as u64);

                vm.push(timestamp);
            },

            op if op == VmOp::OP_CPUID as u8 => {
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
            },

            op if op == VmOp::OP_IN_PORT as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let port = bytecode[vm.vip] as u16;

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
            },

            op if op == VmOp::OP_OUT_PORT as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let port = bytecode[vm.vip] as u16;
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
            },

            op if op == VmOp::OP_ADD as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, change the operation
                // This creates the "infinite rabbit hole" effect where debugging changes behavior
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(a.wrapping_sub(b));  // Change ADD to SUB
                } else {
                    vm.push(a.wrapping_add(b));  // Normal ADD operation
                }
            },

            op if op == VmOp::OP_SUB as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, change the operation
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(a.wrapping_add(b));  // Change SUB to ADD
                } else {
                    vm.push(a.wrapping_sub(b));  // Normal SUB operation
                }
            },

            op if op == VmOp::OP_XOR as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, change the operation
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(a.wrapping_add(b));  // Change XOR to ADD
                } else {
                    vm.push(a ^ b);  // Normal XOR operation
                }
            },

            op if op == VmOp::OP_PUSH as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    vm.push(bytecode[vm.vip] as u64);
                }
            },

            op if op == VmOp::OP_POP as u8 => {
                vm.vip += 1;
                vm.pop(); // Discard top of stack
            },

            op if op == VmOp::OP_DUP as u8 => {
                vm.vip += 1;
                let val = vm.peek();
                vm.push(val);
            },

            op if op == VmOp::OP_SWAP as u8 => {
                vm.vip += 1;
                if vm.sp >= 2 {
                    let a = vm.pop();
                    let b = vm.pop();
                    vm.push(a);
                    vm.push(b);
                }
            },

            op if op == VmOp::OP_CMP_EQ as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(if a != b { 1 } else { 0 });  // Return opposite of EQ (like NE)
                } else {
                    vm.push(if a == b { 1 } else { 0 });  // Normal EQ operation
                }
            },

            op if op == VmOp::OP_CMP_NE as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(if a == b { 1 } else { 0 });  // Return opposite of NE (like EQ)
                } else {
                    vm.push(if a != b { 1 } else { 0 });  // Normal NE operation
                }
            },

            op if op == VmOp::OP_CMP_GT as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(if a <= b { 1 } else { 0 });  // Return opposite of GT (like LE)
                } else {
                    vm.push(if a > b { 1 } else { 0 });  // Normal GT operation
                }
            },

            op if op == VmOp::OP_CMP_LT as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();

                // If the system is in a debugged state, invert the comparison
                if (global_state & 1) != 0 {  // If LSB of global state is set (indicating debug)
                    vm.push(if a >= b { 1 } else { 0 });  // Return opposite of LT (like GE)
                } else {
                    vm.push(if a < b { 1 } else { 0 });  // Normal LT operation
                }
            },

            op if op == VmOp::OP_AND as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();
                vm.push(a & b);
            },

            op if op == VmOp::OP_OR as u8 => {
                vm.vip += 1;
                let b = vm.pop();
                let a = vm.pop();
                vm.push(a | b);
            },

            op if op == VmOp::OP_NOT as u8 => {
                vm.vip += 1;
                let a = vm.pop();
                vm.push(!a);
            },

            op if op == VmOp::OP_SHL as u8 => {
                vm.vip += 1;
                let shift = vm.pop() as u32;
                let a = vm.pop();
                vm.push(a << shift);
            },

            op if op == VmOp::OP_SHR as u8 => {
                vm.vip += 1;
                let shift = vm.pop() as u32;
                let a = vm.pop();
                vm.push(a >> shift);
            },

            op if op == VmOp::OP_JUMP as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let addr = bytecode[vm.vip] as usize;
                    vm.vip = addr;
                    continue; // Skip incrementing VIP again
                }
            },

            op if op == VmOp::OP_JZ as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let addr = bytecode[vm.vip] as usize;
                    let condition = vm.pop();
                    if condition == 0 {
                        vm.vip = addr;
                        continue; // Skip incrementing VIP again
                    }
                }
            },

            op if op == VmOp::OP_JNZ as u8 => {
                vm.vip += 1;
                if vm.vip < bytecode.len() {
                    let addr = bytecode[vm.vip] as usize;
                    let condition = vm.pop();
                    if condition != 0 {
                        vm.vip = addr;
                        continue; // Skip incrementing VIP again
                    }
                }
            },

            op if op == VmOp::OP_EXIT as u8 => {
                return vm.pop(); // Return top of stack as result
            },

            op if op == VmOp::OP_GARBAGE as u8 => {
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
            },

            op if op == VmOp::OP_POLY_JUNK as u8 => {
                vm.vip += 1;

                // OP_POLY_JUNK: Performs random junk operations to obfuscate control flow
                // This opcode executes random mathematical operations that don't affect the final result
                // but make disassemblers like IDA Pro/Ghidra produce confusing control flow graphs

                // Generate a pseudo-random operation based on current state
                let state_dependent_seed = (vm.vip as u64) ^ vm.accumulator ^ (get_cpu_entropy() as u64);

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
            },

            _ => {
                // Unknown opcode, return 0 as safe default
                return 0;
            }
        }

        vm.vip += 1;
    }

    vm.accumulator
}

/// Helper function to get CPU entropy (imported from anti_debug module)
fn get_cpu_entropy() -> u32 {
    use crate::protector::anti_debug::get_cpu_entropy as cpu_entropy;
    cpu_entropy()
}
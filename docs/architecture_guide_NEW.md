# Technical Architecture Guide - FDebug Anti-Debug Protection System

This document provides an in-depth analysis of the **fdebug** module - a comprehensive anti-debugging protection system for Rust applications. The system employs a multi-layered defense strategy designed to detect and silently corrupt execution when debugging attempts are detected.

## Executive Overview

**fdebug** is built on three fundamental principles:

1. **Silent Corruption over Hard Crashes** - Rather than crashing when a debugger is detected, the system corrupts sensitive calculations in a way that appears legitimate but produces incorrect results.
2. **Distributed State Management** - Detection scores are scattered across 16 independent atomic shards, making it extremely difficult to freeze or manipulate the state with simple memory breakpoints.
3. **Mathematical Coupling** - Security tokens are cryptographically bound to actual business logic, forcing developers to incorporate defense mechanisms into their algorithms.

---

## Architecture Layer 1: Multi-Vector Detection System

The fdebug module employs a decentralized detection architecture that monitors the system from multiple angles simultaneously.

### 1.1 Vectored Exception Handling (VEH) - First-Responder Detection

Instead of relying on standard exception handlers (which can be easily hooked), fdebug registers a custom Vectored Exception Handler via the Windows API `AddVectoredExceptionHandler`. This handler intercepts:

- **EXCEPTION_BREAKPOINT (INT3)** - Triggered when a debugger sets a software breakpoint
- **EXCEPTION_SINGLE_STEP (0x80000004)** - Triggered when single-stepping is enabled

When an unexpected breakpoint or single-step exception occurs, the system immediately calls `add_suspicion(DetectionSeverity::High)`.

**Implementation Concept:**
```rust
// Within the VEH callback (anti_debug.rs)
unsafe extern "system" fn veh_handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
    if (*(*ep).ExceptionRecord).ExceptionCode == EXCEPTION_BREAKPOINT {
        // Unexpected breakpoint detected
        add_suspicion(DetectionSeverity::High);
        return EXCEPTION_CONTINUE_SEARCH; // Continue searching handlers
    }
    EXCEPTION_CONTINUE_SEARCH
}
```

### 1.2 Hardware Breakpoint Detection (Debug Registers)

The system monitors CPU debug registers (Dr0-Dr7) through thread CONTEXT structures. These registers are used by debuggers to set hardware breakpoints that can track memory accesses or instruction execution.

**Detection Mechanism:**
```rust
// In anti_debug.rs: Hardware breakpoint detection logic
// Reads CONTEXT.Dr0 through Dr7 to detect set breakpoints
if context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 {
    add_suspicion(DetectionSeverity::Critical);
}
if context.Dr6 & 0x0F != 0 { // Check if any breakpoint was triggered
    add_suspicion(DetectionSeverity::High);
}
```

### 1.3 RDTSC Timing Anomalies

The system uses the RDTSC (Read Time-Stamp Counter) instruction to measure execution latency. Normal x86 instructions execute in predictable time windows, but when a debugger is stepping through code, execution times are dramatically extended.

**Calibration Process:**
The system performs 2000 calibration iterations during initialization to establish a baseline latency threshold. On real hardware, this typically ranges from 100-200 CPU cycles. On virtual machines or under debugging, times spike to 2000+ cycles.

```rust
// Pseudo-code for timing-based detection
let start = rdtsc();
cpuid(0);  // Serialize instruction stream
let end = rdtsc();
let delta = end - start;

// Adaptive threshold accounts for different hardware
if delta > CALIBRATED_THRESHOLD * 10 {
    add_suspicion(DetectionSeverity::High);
}
```

**Why This Works:**
- CPUID is a serializing instruction that flushes the CPU pipeline
- On native hardware: ~100-200 cycles
- On VM with debugging: 2000+ cycles (VM-Exit overhead)
- When single-stepping: Each instruction takes thousands of extra cycles

### 1.4 PEB Memory Integrity Checks

The Process Environment Block (PEB), located at `GS:[0x60]` on x86-64, contains critical process metadata including debug flags. fdebug periodically reads and validates:

- **PEB.BeingDebugged** (offset 0x02) - Set to 1 if a debugger is attached
- **PEB.NtGlobalFlag** (offset 0x68) - Contains debugging-related flags (e.g., 0x70)
- **Heap flags** - Debug heaps have specific flag patterns (0x02000004)

**Code Pattern Example:**
```rust
// Read PEB through virtualized bytecode
let peb = unsafe { 
    std::arch::asm!(
        "mov {peb}, gs:[0x60]",
        peb = out(reg) peb,
        options(nomem, nostack)
    );
    peb
};

let being_debugged = *(peb as *const u8).add(0x02);
if being_debugged != 0 {
    add_suspicion(DetectionSeverity::Critical);
}
```

### 1.5 Environment Detection

The system also checks for virtualization and cloud environments:

```rust
fn detect_virtual_environment() -> bool {
    // Check CPUID for VM vendor strings
    let (_, ebx, ecx, edx) = cpuid_helper(0);
    
    // Convert CPUID output to vendor string
    let vendor_string = format!("{:?}{:?}{:?}", ebx, ecx, edx).to_lowercase();
    
    vendor_string.contains("vmware") ||
    vendor_string.contains("virtualbox") ||
    vendor_string.contains("kvm") ||
    vendor_string.contains("xen")
}
```

---

## Architecture Layer 2: Polymorphic Virtual Execution (TinyVM)

TinyVM is a lightweight custom virtual machine that executes anti-debug bytecode using **Control Flow Flattening** obfuscation.

### 2.1 What is Control Flow Flattening?

Control Flow Flattening converts sequential code execution into a state machine. Instead of:
```rust
// Sequential code (easy to analyze)
let a = get_value();
let b = process(a);
let result = finalize(b);
return result;
```

The code becomes:
```rust
// Flattened (extremely hard to reverse-engineer)
loop {
    match state {
        STATE_INIT => { state = STATE_GET_VALUE; }
        STATE_GET_VALUE => { 
            a = get_value(); 
            state = STATE_PROCESS; 
        }
        STATE_PROCESS => { 
            b = process(a); 
            state = STATE_FINALIZE; 
        }
        STATE_FINALIZE => { 
            result = finalize(b); 
            state = STATE_EXIT; 
        }
        STATE_EXIT => { break; }
        _ => { state = STATE_GARBAGE; } // Anti-analysis trap
    }
}
return result;
```

**Why This is Effective:**
- IDA Pro's graph view becomes nearly unreadable
- Ghidra's decompiler produces garbage
- Manual analysis requires understanding the entire state machine
- Control flow is obscured by fake branches and garbage states

### 2.2 Polymorphic Opcodes

The opcodes defined in `VmOp` enum are not static. They're generated at compile time using the `auto_op!()` macro:

```rust
pub enum VmOp {
    OP_LOAD_IMM = auto_op!(0x1A),           // Load immediate value onto stack
    OP_READ_GS_OFFSET = auto_op!(0x2B),    // Read from GS segment (PEB access)
    OP_READ_MEM_U64 = auto_op!(0x2E),      // Read 8 bytes from memory
    OP_RDTSC = auto_op!(0x3C),             // Execute RDTSC instruction
    OP_CPUID = auto_op!(0x3D),             // Execute CPUID instruction
    OP_ADD = auto_op!(0x4D),               // Add top two stack values
    OP_XOR = auto_op!(0x6F),               // XOR top two stack values
    OP_CMP_EQ = auto_op!(0xB4),            // Compare equality
    OP_JZ = auto_op!(0xEE),                // Jump if zero
    // ... 30+ more opcodes
}
```

The `auto_op!()` macro generates unique values based on:
- `DYNAMIC_SEED` (changes every build, generated at compile-time)
- Build environment hash
- Line number and source location
- File path hash

**Result:** Each binary has completely different opcode values, preventing signature-based detection.

**Example Polymorphism:**
```
Build 1: OP_LOAD_IMM = 0xA3
Build 2: OP_LOAD_IMM = 0x2F
Build 3: OP_LOAD_IMM = 0x78

IDA Pro signature for opcode 0xA3 won't work on the other builds!
```

### 2.3 Example: Reading PEB via TinyVM

Instead of directly reading memory:
```rust
// Direct (vulnerable to breakpoints)
let peb = unsafe { 
    asm!("mov {peb}, gs:[0x60]", peb = out(reg) peb);
    peb 
};
```

fdebug uses TinyVM bytecode:
```rust
// Executed through virtualized bytecode (polymorph)
let mut vm = TinyVm::new(security_key);

// Bytecode: LOAD_IMM(0x60) -> READ_GS_OFFSET -> EXIT
let bytecode = vec![
    VmOp::OP_LOAD_IMM as u8, 0x60,
    VmOp::OP_READ_GS_OFFSET as u8,
    VmOp::OP_EXIT as u8,
];

vm_execute(&mut vm, &bytecode);
let peb = vm.pop(); // Result from VM execution
```

**Security Benefit:**
- Debugger breakpoints on `mov gs:[0x60]` instructions won't trigger (instruction doesn't exist in native code)
- The bytecode is polymorphic and changes every build
- Analyzing the bytecode requires understanding the complete VM state machine

### 2.4 VM Architecture and State Machine

```rust
pub struct TinyVm {
    pub vip: usize,           // Virtual Instruction Pointer
    pub v_stack: [u64; 32],   // Virtual Stack (fixed 32 u64 slots)
    pub sp: usize,            // Stack Pointer
    pub accumulator: u64,     // Accumulator register
    pub key: u64,             // Local key for this execution
}

// Stack-based operations
fn push(&mut self, val: u64) {
    if self.sp < 32 {
        self.v_stack[self.sp] = val;
        self.sp += 1;
    }
}

fn pop(&mut self) -> u64 {
    if self.sp > 0 {
        self.sp -= 1;
        self.v_stack[self.sp]
    } else {
        0
    }
}
```

The VM uses a stack-based architecture similar to JVM or .NET IL, which makes bytecode analysis more time-consuming.

### 2.5 VM Execution with Control Flow Flattening

```rust
fn vm_execute(mut vm: TinyVm, code: &[u8]) -> u64 {
    let mut state = STATE_FETCH;
    let mut opcode = 0u8;
    
    loop {
        match state {
            s if opaque_predicate_eq(s, STATE_FETCH) => {
                // Bounds check and fetch opcode
                if vm.vip < code.len() {
                    opcode = code[vm.vip];
                    vm.vip += 1;
                    state = STATE_DECODE;
                } else {
                    state = STATE_EXIT;
                }
            }
            
            s if opaque_predicate_eq(s, STATE_DECODE) => {
                // Match opcode and set next state
                if opcode == VmOp::OP_LOAD_IMM as u8 {
                    state = STATE_EXEC_LOAD_IMM;
                } else if opcode == VmOp::OP_RDTSC as u8 {
                    state = STATE_EXEC_RDTSC;
                } else if opcode == VmOp::OP_READ_GS_OFFSET as u8 {
                    state = STATE_EXEC_READ_GS;
                } else if opcode == VmOp::OP_EXIT as u8 {
                    state = STATE_EXIT;
                } else {
                    state = STATE_GARBAGE; // Invalid opcode
                }
            }
            
            s if opaque_predicate_eq(s, STATE_EXEC_LOAD_IMM) => {
                // Load immediate from next byte
                if vm.vip < code.len() {
                    let imm = code[vm.vip] as u64;
                    vm.vip += 1;
                    vm.push(imm);
                    state = STATE_FETCH;
                } else {
                    state = STATE_EXIT;
                }
            }
            
            s if opaque_predicate_eq(s, STATE_EXEC_RDTSC) => {
                // Execute RDTSC and push result
                let tsc = unsafe {
                    let low: u32;
                    let high: u32;
                    asm!("rdtsc", out("eax") low, out("edx") high);
                    ((high as u64) << 32) | (low as u64)
                };
                vm.push(tsc);
                state = STATE_FETCH;
            }
            
            s if opaque_predicate_eq(s, STATE_EXEC_READ_GS) => {
                // Pop offset from stack, read from GS segment
                let offset = vm.pop() as u16;
                let value = unsafe {
                    let result: u64;
                    asm!("mov {}, gs:[{:x}]", out(reg) result, in(reg) offset);
                    result
                };
                vm.push(value);
                state = STATE_FETCH;
            }
            
            s if opaque_predicate_eq(s, STATE_EXIT) => {
                break; // Exit the VM
            }
            
            s if opaque_predicate_eq(s, STATE_GARBAGE) => {
                // Dead end state for anti-analysis
                // Complex computation without effect
                let junk = vm.pop().wrapping_mul(0xDEADBEEFCAFEBABE);
                vm.push(junk ^ vm.key);
                state = STATE_FETCH; // Continue as if nothing happened
            }
            
            _ => {
                // Fallback for unknown states
                state = STATE_EXIT;
            }
        }
    }
    
    vm.pop()
}
```

---

## Architecture Layer 3: Distributed Suspicion Scoring & Integrity Monitoring

Rather than using a single boolean flag, fdebug maintains a **distributed, sharded threat score** that's nearly impossible to manipulate.

### 3.1 Sharded Threat Detection

The suspicion score is split across 16 independent `AtomicU32` shards (`SUSPICION_SHARDS`). Each detection event adds points to a different shard selected by a scatter algorithm:

```rust
pub static SUSPICION_SHARDS: [AtomicU32; 16] = [
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 0)),
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 1)),
    // ... 14 more
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 15)),
];

pub static SHARD_MASKS: [u32; 16] = [
    mix_seed(DYNAMIC_SEED, 0), mix_seed(DYNAMIC_SEED, 1), // ... etc
];
```

**Key Properties:**
- Each shard is initialized to its corresponding mask value (representing 0 score)
- The true score is: `score = (shard0 ^ mask0) + (shard1 ^ mask1) + ... + (shard15 ^ mask15)`
- If a cracker attempts to zero out memory, they'll instantly create an enormous score spike

**Score Reconstruction:**
```rust
pub fn reconstruct_threat_score() -> u32 {
    let mut score = 0u32;
    for i in 0..16 {
        let shard = SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        let mask = SHARD_MASKS[i];
        score = score.wrapping_add(shard ^ mask);
    }
    score
}
```

**Example Attack and Defense:**
```
Normal state: 
  shard[0] = 0x12345678
  mask[0] = 0x87654321
  Contribution: 0x12345678 ^ 0x87654321 = 0x95511559

Cracker zeros memory: 
  shard[0] = 0x00000000
  Contribution: 0x00000000 ^ 0x87654321 = 0x87654321 (HUGE!)
  Total score jumps dramatically
  Alarm triggered!
```

### 3.2 Detection Severity Levels

```rust
pub enum DetectionSeverity {
    Low = 10,        // Timing anomaly, minor VM artifact
    Medium = 30,     // PEB flags set, but could be legitimate
    High = 60,       // Hardware breakpoint, INT3, decoy tampering
    Critical = 100,  // Multiple simultaneous detections, TLS callback alerts
}

fn add_suspicion(severity: DetectionSeverity) {
    // Scatter the points across a random shard
    let shard_idx = (CALL_COUNT.fetch_add(1) % 16) as usize;
    let score = severity.score();
    
    let current = SUSPICION_SHARDS[shard_idx].load(Ordering::SeqCst);
    let mask = SHARD_MASKS[shard_idx];
    
    // XOR with mask to get current score, add new points, XOR with mask again
    let new_score = (current ^ mask).wrapping_add(score);
    let new_value = new_score ^ mask;
    
    SUSPICION_SHARDS[shard_idx].store(new_value, Ordering::SeqCst);
}
```

### 3.3 SipHash Integrity Verification

The system uses **SipHash** (with dynamic constants derived from `DYNAMIC_SEED`) to compute a global integrity hash across all protected state:

```rust
fn recalculate_global_integrity() {
    let combined = reconstruct_threat_score() 
        ^ GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
    
    // Dynamic SipHash constants based on DYNAMIC_SEED
    let base_v0 = 0x736f6d6570736575u64;
    let base_v1 = 0x646f72616e646f6du64;
    let base_v2 = 0x6c7967656e657261u64;
    let base_v3 = 0x7465646279746573u64;
    
    // Mix with DYNAMIC_SEED to create unique constants per build
    let mut v0 = base_v0 ^ (DYNAMIC_SEED as u64);
    let mut v1 = base_v1 ^ ((DYNAMIC_SEED as u64) << 8);
    let mut v2 = base_v2 ^ ((DYNAMIC_SEED as u64) << 16);
    let mut v3 = base_v3 ^ ((DYNAMIC_SEED as u64) << 24);
    
    // Mix in the protected data
    v2 ^= combined;
    
    // 4 rounds of SipHash compression
    for _ in 0..4 {
        // SipHash round:
        // v0 += v1; v2 += v3;
        // v1 = rotate_left(v1, 13); v3 = rotate_left(v3, 16);
        // v1 ^= v0; v3 ^= v2;
        // v0 = rotate_left(v0, 32); v2 = rotate_left(v2, 32);
        // ... (2 more sub-rounds per round)
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    
    let hash = v0 ^ v1 ^ v2 ^ v3;
    GLOBAL_INTEGRITY_HASH.store(hash, Ordering::SeqCst);
}
```

**Defense Mechanism:**
- Any tampering with `SUSPICION_SHARDS` that doesn't go through `add_suspicion()` will immediately corrupt the hash
- Crackers attempting to zero-out shards will increase the hash (making the discrepancy obvious)
- Periodic integrity checks catch modifications mid-execution

### 3.4 The Poison Seed Mechanism

When a debugger is detected early (via TLS callbacks or VEH), the `POISON_SEED` is corrupted:

```rust
pub static POISON_SEED: AtomicU64 = AtomicU64::new(0);

// When early-bird detection triggers
if detected_in_early_stage {
    POISON_SEED.store(random_garbage_value, Ordering::SeqCst);
}

// Later, in run_secure():
let mut transformation_key = (DYNAMIC_SEED as u64) ^ 0x61C8864680B583EB;

// Mathematical corruption through poison
transformation_key ^= POISON_SEED.load(Ordering::SeqCst);

// If poison was triggered, key becomes garbage
```

**Effect on Business Logic:**
```rust
// Any operation using the transformation key becomes corrupted
let actual_price = vault_price ^ (transformation_key as u32 % 0xFFFF);
// If key is garbage, price is garbage
```

---

## Architecture Layer 4: Decoy System (Honey Pot Pattern)

The **Decoy System** implements a honey pot pattern: obvious, easy-to-find security functions that attract reverse engineers.

### 4.1 Decoy Functions

The module provides three intentionally visible security functions in `decoy_system.rs`:

```rust
#[inline(never)]
#[no_mangle]
fn check_kernel_debugger() -> bool {
    unsafe {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    }
}

#[inline(never)]
#[no_mangle]
fn is_process_being_debugged() -> bool {
    unsafe {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    }
}

#[inline(never)]
#[no_mangle]
fn anti_tamper_validation() -> bool {
    let entropy = get_cpu_entropy();
    let threshold = 0x12345678u32;
    (entropy ^ threshold) != 0
}
```

**Attributes Used:**
- `#[inline(never)]` - Forces function to exist at a fixed address (easy to find)
- `#[no_mangle]` - Preserves function name in binary (visible in symbol table)

**Cracker's Expected Behavior:**
1. Open binary in IDA Pro or Ghidra
2. Search for strings "IsDebuggerPresent" or function names
3. Find these functions immediately (they stand out)
4. Assume one is the main detection mechanism
5. Patch function to always return `false` (common NOP+RET patch)
6. Test application, believe they've defeated protection

### 4.2 Watchdog Monitoring

While the cracker patches decoys, the `watchdog_check_decoys()` function monitors them continuously:

```rust
fn watchdog_check_decoys() {
    for (func_name, func_ptr) in [
        ("check_kernel_debugger", check_kernel_debugger as *const fn() -> bool as *const u8),
        ("is_process_being_debugged", is_process_being_debugged as *const fn() -> bool as *const u8),
        ("anti_tamper_validation", anti_tamper_validation as *const fn() -> bool as *const u8),
    ] {
        // Check for common patch patterns (RET instruction = 0xC3)
        let is_patched = is_function_patched(func_ptr);
        
        // Calculate checksum of function prologue
        let checksum = calculate_checksum(func_ptr, 16);
        let expected = match func_name {
            "check_kernel_debugger" => EXPECTED_KERNEL_DEBUGGER_HASH.load(Ordering::Relaxed),
            "is_process_being_debugged" => EXPECTED_PROCESS_DEBUGGED_HASH.load(Ordering::Relaxed),
            "anti_tamper_validation" => EXPECTED_ANTI_TAMPER_HASH.load(Ordering::Relaxed),
            _ => 0,
        };
        
        if is_patched || (expected != 0 && checksum != expected) {
            // Function has been modified!
            DECOY_TAMPERED.store(true, Ordering::SeqCst);
            add_suspicion(DetectionSeverity::Critical);
            break;
        }
    }
}
```

### 4.3 Patch Detection Logic

```rust
fn is_function_patched(func_ptr: *const u8) -> bool {
    unsafe {
        // Check for common patch patterns
        let ptr = func_ptr as *const u8;
        
        // Pattern 1: Immediate RET (0xC3)
        if *ptr == 0xC3 {
            return true;
        }
        
        // Pattern 2: RET with immediate (0xC2)
        if *ptr == 0xC2 {
            return true;
        }
        
        // Pattern 3: JMP to stub (0xEB or 0xE9)
        if *ptr == 0xEB || *ptr == 0xE9 {
            return true;
        }
        
        // Pattern 4: All NOPs (0x90 0x90 0x90...)
        if *ptr == 0x90 && *ptr.add(1) == 0x90 && *ptr.add(2) == 0x90 {
            return true;
        }
        
        false
    }
}

fn calculate_checksum(ptr: *const u8, len: usize) -> u32 {
    let mut checksum = 0u32;
    unsafe {
        for i in 0..len {
            let byte = std::ptr::read_volatile(ptr.add(i));
            checksum = checksum.wrapping_add(byte as u32)
                              .wrapping_mul(31)
                              .wrapping_add(1);
        }
    }
    checksum
}
```

### 4.4 Effect of Decoy Tampering

When tampering is detected, the `DECOY_TAMPERED` flag triggers silent corruption in business logic:

```rust
impl CoupledLogic<T> for Protector {
    fn run_coupled<F>(&self, operation: F) -> T 
    where
        F: FnOnce(u64) -> T,
    {
        // Check decoys and watchdog
        let _ = decoy_system::check_kernel_debugger();
        let _ = decoy_system::is_process_being_debugged();
        
        if get_cpu_entropy() % 2 == 0 {
            decoy_system::watchdog_check_decoys();
        }
        
        // Get security token
        let mut token = 0x12345678ABCDEF00u64;
        
        // If tampering detected, corrupt the token
        if decoy_system::DECOY_TAMPERED.load(Ordering::SeqCst) {
            token = token.wrapping_mul(0xDEADBEEFCAFEBABE);
        }
        
        // Execute business logic with (possibly corrupted) token
        let result = operation(token);
        
        // Silent corruption through token usage
        result.corrupt_if_needed(token)
    }
}
```

**The Perfect Trap:**
- Attacker patches decoy → Watchdog detects patch
- Attacker's app runs without crashing
- But all subsequent calculations use corrupted tokens
- Financial reports show wrong numbers
- Encryption produces garbage
- The attacker spends weeks debugging seemingly random corruption!

---

## Integration Patterns

### Pattern 1: Guarded Execution (run_secure)

Wraps sensitive operations with mandatory security tokens:

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    // Create a vault containing sensitive data
    let secret_price = SecureVault::new(999u32);
    
    // Access requires a valid security token
    let actual_price = protector.run_secure(&secret_price, |price, token| {
        // token is only valid if environment is clean
        // If debugged, token is garbage
        price ^ (token as u32 % 0xFFFF)
    });
    
    println!("Price: {}", actual_price);
    // If debugged: prints incorrect price
    // If clean: prints correct price
}
```

**Security Flow:**
```
1. run_secure() called
2. System performs heartbeat (anti-debug checks)
3. Derives transformation_key based on suspicion score
4. If suspicion > 0: key is mathematically corrupted
5. Passes key to closure
6. Closure produces result using key
7. If key was corrupted: result is garbage
```

### Pattern 2: Coupled Logic (run_coupled)

Integrates detection and business logic at the fundamental level, with automatic corruption:

```rust
use fdebug::protector::{Protector, CoupledLogic, Corruptible};

#[derive(Clone)]
struct FinancialData {
    revenue: f64,
    expenses: f64,
    is_valid: bool,
}

impl Corruptible for FinancialData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        // If token is corrupted (odd from garbage seed)
        if token % 7 == 0 {
            // Silently corrupt data
            self.revenue *= 0.5;
            self.expenses *= 2.0;
            self.is_valid = false;
        }
        self
    }
}

fn main() {
    let protector = Protector::new(12345);
    
    let report = protector.run_coupled(|token| {
        // token depends entirely on system cleanliness
        
        FinancialData {
            revenue: 1_000_000.0 + (token as f64 * 0.00001),
            expenses: 500_000.0,
            is_valid: (token % 11) != 0,
        }
    });
    
    println!("Revenue: ${:.2}", report.revenue);
    println!("Valid: {}", report.is_valid);
    
    // If debugged:
    //   Revenue: $500000.00
    //   Valid: false
    // 
    // If clean:
    //   Revenue: $1000000.00
    //   Valid: true
}
```

### Pattern 3: Macro-Based Enforcement (guarded_value!)

Inline enforcement for critical values:

```rust
use fdebug::protector::{Protector, guarded_value};

fn main() {
    let protector = Protector::new(0xACE);
    
    // Force inline security token integration
    let (license_key, security_token) = guarded_value!("LICENSE_ABC123", protector);
    
    // license_key is valid only if security_token is valid
    let is_valid_license = validate_license(license_key, security_token);
    
    if !is_valid_license {
        eprintln!("License validation failed");
        return;
    }
}

fn validate_license(key: &str, token: u64) -> bool {
    // Validation depends on security token
    key.len() == 13 && (token % 17) == 0
}
```

---

## Decay and Periodic Monitoring

The threat score doesn't accumulate indefinitely. The system implements decay logic to reduce false positives in legitimate debugged environments while still catching real attackers:

```rust
pub fn decay_threat_score() {
    let now = UNIX_EPOCH.elapsed().unwrap().as_millis() as u64;
    let last_decay = GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
    
    // Decay every 30 seconds
    if now - last_decay > 30000 {
        let mut score = reconstruct_threat_score();
        
        // Reduce score by 10% per decay period
        score = (score as f64 * 0.9) as u32;
        
        // Redistribute to shards
        for i in 0..16 {
            let mask = SHARD_MASKS[i];
            let shard_score = (score / 16) as u32;
            SUSPICION_SHARDS[i].store(shard_score ^ mask, Ordering::SeqCst);
        }
        
        GLOBAL_LAST_DECAY_TIME.store(now, Ordering::SeqCst);
    }
}
```

---

## Summary

fdebug provides **four concentric layers of protection**:

| Layer | Mechanism | Effect |
| --- | --- | --- |
| **Detection** | VEH, Hardware BP, RDTSC, PEB | Identify debugging attempts |
| **Obfuscation** | Polymorphic TinyVM, Control Flow Flattening | Hide security logic from analysis |
| **Integrity** | Distributed shards, SipHash, Poison Seeds | Prevent state manipulation |
| **Deception** | Decoy functions, Watchdog monitoring | Trap reverse engineers into trigger alarms |

The combination makes fdebug extremely resistant to both automated and manual reverse engineering, while maintaining the philosophy of **silent corruption** rather than obvious crashes. An attacker running the application under a debugger will experience subtle but pervasive data corruption that makes the application appear to function correctly while producing completely wrong results.

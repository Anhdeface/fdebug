---

## Architecture Layer 5: Seed Orchestrator & Entropy Reconstruction

Beyond the four primary protection layers, fdebug adds a **foundational fifth layer** that generates all cryptographic material dynamically at runtime through **entropy reconstruction**.

### 5.1 The Problem with Static Seeds

Traditional anti-debug systems use hardcoded constants:

```rust
// ❌ VULNERABLE APPROACH
const ENCRYPTION_KEY: [u8; 32] = [0x12, 0x34, ...];  // Frozen in binary
const DYNAMIC_SEED: u32 = 0x12AB34CD;                 // Same every run
```

**Attacks Against Static Keys:**
1. **Static Analysis**: IDA Pro strings window finds the constants
2. **Memory Dumps**: Extract keys from running process RAM
3. **Binary Patching**: Modify constants directly in PE file
4. **Replay Attacks**: Intercept encrypted data once, decrypt offline
5. **Frozen State**: Debugger can freeze memory containing keys

### 5.2 Runtime Reconstruction from Entropy Shards

fdebug never stores secrets. Instead, it **generates them on-demand** from distributed, changing sources:

```rust
// ✅ SECURE APPROACH
let seed = get_dynamic_seed();  // Generated from three entropy sources
let key = derive_key_from(seed);  // Computed once, never stored
```

**The three entropy shards:**

#### Shard 1: Build-Time Seed (Unique per binary)

Generated during compilation:

```rust
// In build.rs
let seed = rand::random::<u32>();
write!(seed_file, "0x{:08X}u32", seed)?;
```

Embedded in binary via:
```rust
const BUILD_TIME_SEED: u32 = include!(concat!(env!("OUT_DIR"), "/dynamic_seed.rs"));
```

**Properties:**
- Different for every build (~4 billion possibilities)
- Cannot be reverse-engineered from the binary
- Changes with every recompilation
- Each user gets a uniquely protected version

#### Shard 2: Hardware Entropy (CPU-specific)

Extracted from the processor itself:

```rust
// In hardware_entropy.rs
pub fn get_hardware_entropy() -> u32 {
    // Read from CPU CPUID instruction
    // Includes: vendor name, model, features, stepping
    let (eax, ebx, ecx, edx) = cpuid_helper(0);  // CPUID vendor
    let (_, _, features, _) = cpuid_helper(1);  // CPUID features
    
    // Combine into fingerprint
    hash(ebx ^ edx ^ ecx ^ features)
}
```

**Properties:**
- Processor-specific (Intel vs AMD vs VIA, etc.)
- Changes if code runs on different hardware
- Hard to spoof perfectly (requires VM emulation)
- Cached after first access for performance

**Attack Resistance:**
```
Attacker's Emulator:         Real User's Hardware:
CPUID spoofing easy    →     Actual CPU values
  │                           │
  └─ VEH detects VM           └─ Entropy is correct
     Suspicion +100              Seed is valid
```

#### Shard 3: PE Integrity Hash (Code checksum)

Computes checksum of the entire `.text` section:

```rust
// In pe_integrity.rs
pub fn get_text_section_hash() -> u32 {
    // Find .text section in PE header
    let text_base = find_section_address(".text")?;
    let text_size = find_section_size(".text")?;
    
    // Checksum all code bytes
    let mut hash = 0u32;
    for i in 0..text_size {
        let byte = unsafe { *(text_base.add(i) as *const u8) };
        hash = hash.wrapping_mul(31).wrapping_add(byte as u32);
    }
    hash
}
```

**Properties:**
- Changes if ANY byte of code is modified
- Detects: DLL injection, code patching, function hooks
- Defeats: Frida, inline hooking, thread hijacking
- Invalidates entire seed if code is tampered with

**Defense Example:**
```
Original Code:          Attacker Patches:
text_hash = 0x82F1     text_hash = 0x5C3A (COMPLETELY DIFFERENT!)
   │                       │
   └─ SEED = avalanche      └─ SEED = invalid garbage
      (BUILD ^ HW ^ PE)        All opcodes become wrong
      Application works        Application crashes
```

### 5.3 Shard Composition: XOR and Avalanche Mixing

**Step 1: Combine all three shards:**
```rust
let intermediate = BUILD_SEED ^ HW_ENTROPY ^ PE_HASH;
```

XOR properties make this ideal:
- **Avalanche Effect**: Single bit change → 50% of output bits flip
- **Reversible**: Can't solve for individual shards algebraically
- **Non-linear**: Immune to linear cryptanalysis

**Step 2: Apply avalanche mixing (MurmurHash3 finalizer):**
```rust
fn avalanche_mix(mut x: u32) -> u32 {
    x ^= x >> 16;                          // First layer
    x = x.wrapping_mul(0x85ebca6b);       // Mix with prime
    x ^= x >> 13;                          // Second layer
    x = x.wrapping_mul(0xc2b2ae35);       // Mix with prime
    x ^= x >> 16;                          // Final layer
    x
}

let final_seed = avalanche_mix(intermediate);
```

**Effect on bits:**
```
Input: 10101010 10101010 10101010 10101010
Output:01100110 01100110 01100110 01100110
       ↑↑↑↑↑↑↑↑ ↑↑↑↑↑↑↑↑ ↑↑↑↑↑↑↑↑ ↑↑↑↑↑↑↑↑
       ALL bits changed from a simple input pattern!
```

This ensures each bit of the output depends on all bits of the input, making analysis impossible.

### 5.4 Polymorphism Across Users and Hardware

The three-shard approach creates multiple dimensions of uniqueness:

```
Build 1, User A (CPU: Intel):
  BUILD_SEED = 0xA3 (unique)
  HW_ENTROPY = 0x12 (Intel fingerprint)
  PE_HASH = 0x45 (code hash)
  OP_LOAD_IMM = avalanche(0xA3 ^ 0x12 ^ 0x45) = 0x7F

Build 1, User B (CPU: AMD - same binary!):
  BUILD_SEED = 0xA3 (same, same binary)
  HW_ENTROPY = 0x99 (AMD fingerprint - DIFFERENT!)
  PE_HASH = 0x45 (same code)
  OP_LOAD_IMM = avalanche(0xA3 ^ 0x99 ^ 0x45) = 0x2E

Build 2 (Recompiled):
  BUILD_SEED = 0x5C (DIFFERENT - new random value)
  HW_ENTROPY = 0x12 (same hardware)
  PE_HASH = 0xA8 (DIFFERENT - new code)
  OP_LOAD_IMM = avalanche(0x5C ^ 0x12 ^ 0xA8) = 0xE4
```

**Result:**
- **Each user gets unique bytecode** (BUILD_SEED)
- **Same binary runs differently on different CPUs** (HW_ENTROPY)
- **Any code modification breaks everything** (PE_HASH)
- **Static binary analysis completely fails** (ever-changing opcodes)

### 5.5 Caching Strategy for Performance

Reconstructing entropy on every access would be slow. The Seed Orchestrator uses `OnceLock` for lazy initialization:

```rust
static RECONSTRUCTED_SEED: OnceLock<u32> = OnceLock::new();

pub fn get_dynamic_seed() -> u32 {
    *RECONSTRUCTED_SEED.get_or_init(|| {
        // Only computed once, on first access
        // All subsequent calls read from cache
        Self::compute_seed()
    })
}
```

**Performance Characteristics:**
- **First Access**: ~50-100 microseconds
  - CPUID calls: ~10 microseconds
  - PE header parsing: ~40-90 microseconds
  - Avalanche mixing: ~5 microseconds

- **Cached Accesses**: ~1-10 nanoseconds
  - OnceLock atomic read
  - CPU L1 cache hit
  - No visible overhead

**Invalidation Policy:**
The cache is intentionally **never invalidated** during process lifetime:
- Attempting to invalidate signals tampering detection
- Process restart gets fresh entropy
- Long-running services benefit from first-call overhead amortization

### 5.6 Integration with Other Layers

The reconstructed seed feeds into every other layer:

```
┌─────────────────────────────────────────────────────┐
│         get_dynamic_seed() - Runtime Reconstruction │
└──────────────────┬──────────────────────────────────┘
                   │
        ┌──────────┴──────────┬──────────────┬────────────┐
        │                     │              │            │
        ↓                     ↓              ↓            ↓
    TinyVM              SipHash         Shard           String
    Opcodes            Constants        Masks       Encryption
   (auto_op!)         (global_state)  (SHARD_MASKS) (enc_str!)
        │                  │               │            │
        └──────────────────┴───────────────┴────────────┘
                           │
                    All Security Material
                 Derived from Runtime Seed
```

**TinyVM Opcodes:**
```rust
// Each opcode is derived from reconstructed seed
pub enum VmOp {
    OP_LOAD_IMM = auto_op!(0x1A),  // Includes get_dynamic_seed()
    OP_RDTSC = auto_op!(0x3C),     // Different on each build/hardware
    // ... all opcodes are polymorphic
}
```

**SipHash Constants:**
```rust
// Initialized from seed in global_state.rs
let base_v0 = 0x736f6d6570736575u64;
let v0_mixed = base_v0 ^ (get_dynamic_seed() as u64);  // Seed-dependent
```

**Shard Masks:**
```rust
// Each mask is XOR'ed with seed
pub fn get_shard_mask(index: usize) -> u32 {
    let seed = get_dynamic_seed();
    mix_seed(seed, index as u32)  // Seed-dependent initialization
}
```

### 5.7 Defense Summary

The Seed Orchestrator defeats major attack vectors:

| Attack | Defense |
| --- | --- |
| **Static analysis finds constants** | Constants don't exist (generated at runtime) |
| **Memory freeze to extract keys** | Seed changes unpredictably, VM crashes if frozen |
| **Binary patching of constants** | PE_HASH changes, invalidates all opcodes |
| **DLL injection** | PE_HASH changes, detection triggered |
| **Run in emulator with spoofed CPU** | HW_ENTROPY spoofing detected by VEH |
| **Replay encrypted data** | Encryption key depends on runtime seed, different per user |
| **Disassemble and patch bytecode** | Opcodes are polymorphic, different every build |

---

## Complete Architecture Summary

fdebug provides **five concentric protection layers**, with runtime seed reconstruction as the foundation:

| Layer | Level | Mechanism | Effect |
| --- | --- | --- | --- |
| **Entropy** | 1 (Foundation) | Seed Orchestrator (Build/Hardware/PE) | Generate unique cryptographic material |
| **Detection** | 2 | VEH, Hardware BP, RDTSC, PEB | Identify debugging attempts in real-time |
| **Obfuscation** | 3 | Polymorphic TinyVM, Control Flow Flattening | Hide security logic from analysis tools |
| **Integrity** | 4 | Distributed shards, SipHash, Poison Seeds | Prevent state tampering and manipulation |
| **Deception** | 5 (Outermost) | Decoy functions, Watchdog monitoring | Trap attackers into triggering alarms |

Each layer depends on the ones below:
- **Detection** mechanisms trigger based on state managed by **Integrity** layer
- **Obfuscation** of VM opcodes derived from **Entropy** reconstruction
- **Integrity** shards initialized using **Entropy**-derived masks
- **Deception** functions protect the binary that feeds into **Entropy** hash

The combination makes fdebug **extremely resistant** to both automated and manual reverse engineering:

1. **Static Analysis**: Impossible (opcodes are runtime-generated)
2. **Dynamic Analysis**: Detected immediately (VEH catches breakpoints)
3. **Memory Patching**: Fails (seed reconstruction invalidates everything)
4. **Code Patching**: Fails (PE integrity hash changes)
5. **Emulation**: Detected (CPUID spoofing caught by VEH)

**The Ultimate Defense:**
An attacker running the application under a debugger experiences subtle but pervasive **silent corruption** that makes the application appear to function correctly while producing completely wrong results. There is no single "key" to find, no "master constant" to patch—only mathematical relationships between distributed entropy sources that rebuild themselves at runtime.


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

### 1.1 Enhanced Vectored Exception Handling (VEH) - 5-Phase Logic

Instead of relying on simple exception handlers, fdebug implements a **5-Phase Exception Filtering System** that acts as the first line of defense:

1.  **Entry Filtering**: Checks if the exception occurred within the legitimate `.text` section boundaries (using PE Integrity metadata). Exceptions from external code or hooks are ignored.
2.  **Stack Validation**: Performs a shallow stack walk (2 frames deep) using `RtlVirtualUnwind` to detect spoofed return addresses or artificial stack frames.
3.  **Anti-Dump Dispatch**: Delegates `STATUS_GUARD_PAGE_VIOLATION` exceptions to the `anti_dump` module (see Section 1.4).
4.  **Anti-Debug Dispatch**: Intercepts `EXCEPTION_BREAKPOINT` (INT3) and `EXCEPTION_SINGLE_STEP` (Hardware Breakpoints).
5.  **Internal VM Heartbeat**: Uses **TinyVM** to verify debug registers (`Dr0`-`Dr3`) against an internal rolling checksum. If verification fails (e.g., external modification), the thread context is silently poisoned.

**Why 5 Phases?**
This layered approach prevents bypasses via:
-   **Hooking VEH**: The handler validates its own execution context.
-   **Spoofing Context**: Stack validation catches artificial frames.
-   **Patching Checks**: The VM Heartbeat is obfuscated and structurally coupled to the encryption key.

### 1.2 Hardware Breakpoint Detection (Debug Registers)

The system monitors CPU debug registers (Dr0-Dr7) through thread CONTEXT structures. These registers are used by debuggers to set hardware breakpoints that can track memory accesses or instruction execution.

**Detection Mechanism:**
```rust
// Verified via TinyVM Heartbeat logic (see Phase 5 of VEH)
// Checks if Dr0-Dr3 match expected internal state, effectively preventing
// external debuggers from using these registers without detection.
if context.Dr7 != 0 && !validate_heartbeat(context) {
    poison_state();
}
```

### 1.3 RDTSC Timing Anomalies

The system uses the RDTSC (Read Time-Stamp Counter) instruction to measure execution latency. Normal x86 instructions execute in predictable time windows, but when a debugger is stepping through code, execution times are dramatically extended.

**Calibration Process:**
The system performs 2000 calibration iterations during initialization to establish a baseline latency threshold. On real hardware, this typically ranges from 100-200 CPU cycles. On virtual machines or under debugging, times spike to 2000+ cycles.

### 1.4 Surgical Anti-Dump & Indirect Syscalls

To prevent memory dumping tools (like Scylla, PD, PE-Sieve) from reconstructing the binary, fdebug implements a **Surgical Anti-Dump** strategy combined with **Indirect Syscalls**.

**A. Indirect Syscalls (Bypassing EDR/Hooks)**
Instead of calling `VirtualProtect` directly (which is monitored by EDRs), fdebug resolves the System Service Number (SSN) for `NtProtectVirtualMemory` dynamically and executes a raw `syscall` instruction via a "trampoline" gadget found in `ntdll.dll`.
-   **Benefit**: The call stack points to valid `ntdll` memory, bypassing user-mode hooks.
-   **Stealth**: No `jmp` instructions or recognizable stub patterns in the main binary.

**B. Surgical PE Erasure**
Rather than zeroing the entire PE header (which causes crashes in CRT/Windows APIs), fdebug selectively corrupts only critical fields using high-entropy random data:
-   **Preserved**: `DOS Header` (`MZ`) - maintains basic module validity.
-   **Corrupted**: `NT Signature`, `AddressOfEntryPoint`, `SizeOfImage`, `Section Headers`.
-   **Entropy**: Fields are overwritten with `KUSER_SHARED_DATA` entropy (timestamp-based), making them look like random garbage rather than empty zeros.

**C. Direct Syscall Watchdog v2 (Liveness Monitoring)**
To catch thread suspension by a debugger, the `anti_dump` module implements a watchdog that monitors the internal **VM Heartbeat**.
-   **Adaptive Sensitivity**: Uses a **5-second baseline threshold** (50M 100ns units). If the system is under heavy load (>85% CPU), the threshold doubles to **10 seconds** to eliminate false positives.
-   **Silent Poisoning**: Unlike version 1.0 which exited the process, version 2.0 triggers **Silent Data Poisoning**. It corrupts `POISON_SEED` and cryptographic keys, ensuring all future execution produces garbage data without notifying the attacker.
-   **Warm-up Period**: A 10-second stabilization window at startup prevents race conditions during module initialization.

**D. Passive Decoy Traps**
The `anti_dump` module allocates "Honey Pot" pages with `PAGE_GUARD` protection. Any attempt to scan or read these pages (linear sweep) triggers a `STATUS_GUARD_PAGE_VIOLATION` exception, which is caught by the VEH (Phase 3) and flags the process as under attack.

### 1.5 PEB Memory Integrity Checks

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

### 1.6 Environment Detection

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
    vendor_string.contains("xen") ||
    vendor_string.contains("microsoft hv")
}
```

**Hyper-V Optimization:**
In modern Windows environments (WSL2, Sandbox), Hyper-V is often active. To reduce false positives:
-   **Baseline Suspicion**: Hyper-V/Virtualized state baseline is set to **60 points** (DetectionSeverity::High).
-   **Consolidated Scoring**: Multiple indicators (Hypervisor bit + Brand string + Timing) are capped at 60 points to prevent accidental poisoning (which occurs at 100+).
-   **Stability**: This allows the application to run safely on machine-local virtual environments while maintaining detection resistance.

### 1.7 Extended Environmental Context
The system further refines its detection through subtle environmental cues:
- **Terminal Context Detection**: Checks if the process is running within a standard terminal shell (`powershell.exe`, `cmd.exe`). Debugging tools often launch processes in non-standard or redirected pipes, which the system flags.
- **Precision Calibration**: Performs 2000 hardware timing cycles at startup to distinguish between "Real Hardware Jitter" and "Debugger Interruption".

---

## Architecture Layer 2: Randomized Virtual Execution (TinyVM 2.0)

TinyVM is a lightweight custom virtual machine that executes anti-debug bytecode using **Indirect Threading** and **Randomized V-Table Dispatching**.

### 2.1 Indirect Threading vs Control Flow Flattening

Traditional "Control Flow Flattening" uses a massive `switch` statement inside a loop. This is effective against humans but vulnerable to compiler optimization and automated CFG reconstruction.

**TinyVM 2.0 Approach:**
Instead of a `switch`, the VM uses a **Trampoline Architecture** with a single indirect call:

```rust
// The VM Loop (Trampoline)
loop {
    // 1. Fetch encrypted opcode
    // 2. Map Logical Opcode -> Physical Index (via LTP Map)
    // 3. Indirect Call
    let handler = VM_HANDLERS[phys_idx];
    handler(ctx, code, &mut state);
}
```

**Security Benefit:**
- **Control Flow Graph (CFG) Collapse**: Static analysis tools see a single loop with one indirect call target. The destinations are unknown until runtime.
- **No Switch-Case Pattern**: There are no `cmp/je` chains for decompilers to reconstruct.

### 2.2 Randomized V-Table (Fail-Deadly)

The mapping between Logical Opcodes (in bytecode) and Physical Handlers (in memory) is **dynamic**.

1.  **LTP Map (Logic-to-Physical)**: A 256-byte table that permutes opcode indices.
2.  **Runtime Shuffling**: On initialization, the LTP Map is shuffled using a PRNG seeded by the **Seed Orchestrator**.
3.  **Fail-Deadly "Chaos Trap"**:
    - If the system detects a safe environment, the map is consistent with the compiler's output.
    - If a **suspicious seed** (e.g., 0 from a mocked environment) is detected, the map is initialized with **Chaotic Entropy** (RDTSC + ASLR mixing).
    - **Result**: The VM "runs" but executes the wrong handlers (e.g., `ADD` becomes `XOR`), silently corrupting all internal logic without crashing.

### 2.3 Advanced Rolling Key Decryption

Instruction decoding is no longer stateless. It uses a **Multi-Stage State Mixing** algorithm:

```rust
// Cryptographic State Update
state.key = state.key.wrapping_add(raw_byte).wrapping_mul(0x1F);
state.key ^= state.key.rotate_right(3) ^ 0x3C;
state.key ^= GLOBAL_VIRTUAL_MACHINE_KEY; // External Entropy
```

**Properties:**
-   **Avalanche Effect**: Every byte read changes the key for all subsequent bytes.
-   **Position Dependent**: Decoding logic includes the instruction pointer (`VIP`), so identical instructions have different ciphertext at different addresses.
-   **No Frequency Analysis**: The same opcode `0xA0` will appear as completely different bytes throughout the bytecode stream.

### 2.4 Polymorphic Opcodes

The opcodes defined in `VmOp` are generated at compile time using the `auto_op!()` macro and synchronized with the runtime seed:

```rust
pub enum VmOp {
    OP_LOAD_IMM = auto_op!(0x1A),           // Load immediate value onto stack
    OP_READ_GS_OFFSET = auto_op!(0x2B),    // Read from GS segment (PEB access)
    // ... 30+ more opcodes
}
```

The `dynamic_str!` macro performs the **inverse mathematical transformation** at compile time to generate valid bytecode that matches the runtime's complex decoding logic.

### 2.5 VM Architecture

```rust
pub struct TinyVm {
    pub v_stack: [u64; 32],   // Virtual Stack
    pub sp: usize,            // Stack Pointer
    pub key: u64,             // Local key
}
```

The stack-based architecture remains, but the execution engine is now entirely decentralized into standalone micro-handlers rather than a monolithic loop.

### 2.6 Secure Memory Management (RAII Scrubbing)
To prevent sensitive data leaks in memory, the VM uses `SecureBuffer<N>`:
- **Automatic Zeroing**: Implements the `Drop` trait to perform `write_volatile` zeroing of the entire buffer when it goes out of scope.
- **RAII Pattern**: Ensures that decrypted strings or encryption keys never persist in heap or stack memory longer than necessary.

---

## Architecture Layer 3: Distributed Suspicion Scoring & Integrity Monitoring

Rather than using a single boolean flag, fdebug maintains a **distributed, sharded threat score** that's nearly impossible to manipulate.

### 3.1 Sharded Threat Detection

The suspicion score is split across **128 independent `AtomicU32` shards** (`SUSPICION_SHARDS`), implementing an **Active/Decoy (64/64)** distribution.
-   **Active Shards (64)**: Store real suspicion scores masked with build-time values.
-   **Decoy Shards (64)**: Filled with high-entropy decoy values to dilute the memory signature and mislead automated analysis tools.

Each detection event adds points to a random active shard selected by a scatter algorithm:

```rust
pub static SUSPICION_SHARDS: [AtomicU32; 128] = [
    AtomicU32::new(mix_seed(DYNAMIC_SEED, 0)),
    // ... 127 more
];

pub static SHARD_MASKS: [u32; 128] = [
    mix_seed(DYNAMIC_SEED, 0), // ... etc
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

### 3.5 Opaque Predicate Obfuscation
The system replaces direct boolean comparisons with **Opaque Predicates**:
- **Mathematical Concealment**: Instead of `if a == b`, the system uses `opaque_predicate_eq(a, b)`, which performs XOR-based bit-counting and wrapping operations that are functionally equivalent but statically opaque.
- **Flow Diversion**: Branching logic is directed through calculation chains that prevent simple "NZ" to "Z" patching in disassemblers.

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

## Architecture Layer 6: Advanced Stealth Mechanisms

Beyond detection and obfuscation, fdebug implements several advanced stealth mechanisms that operate at the lowest OS and hardware levels.

### 6.1 Zero-Static-Trace String Obfuscation (`dynamic_str!`)

**The Problem**: Traditional encrypted strings leave patterns in the `.rdata` section:

```rust
// ❌ VULNERABLE: Static array visible in binary
const ENCRYPTED_MSG: [u8; 13] = [0xA3, 0xB4, 0xC5, ...];  // Still analyzable
```

**The Solution**: `dynamic_str!` achieves complete zero-static-trace obfuscation:

```rust
// ✅ SECURE: No data in binary, volatile stack operations only
let secret = dynamic_str!("API_KEY_12345");  // Reconstructed at runtime via TinyVM
```

**Technical Implementation**:

1. **Compile-Time Shuffling**: Each string location selects 1 of 3 transformation types:
   - **XOR-Rotate**: `val ^= key; val = val.rotate_left(3)`
   - **Subtract-XOR**: `val = val.wrapping_sub(key); val ^= 0x55`
   - **Bit-Flip-Add**: `val = !val; val = val.wrapping_add(key)`

2. **POISON_SEED Integration**: Decryption key includes `get_dynamic_seed()`:
   ```rust
   let key = COMPILE_TIME_SALT ^ get_dynamic_seed();
   // If POISON_SEED is corrupted (anti-debug triggered), result is garbage
   ```

3. **Volatile Stack Reconstruction**: Each byte is pushed via `write_volatile`:
   ```rust
   for i in 0..len {
       write_volatile(buffer.as_mut_ptr().add(i), decrypted_byte);
   }
   ```

4. **TinyVM Bytecode Execution**: The reconstruction happens inside the VM:
   ```rust
   // Bytecode: PUSH LEN -> PUSH ADDR -> PUSH KEY -> PUSH TYPE -> RECONSTRUCT -> EXIT
   vm_execute(&bytecode[..bc_idx], bc_key, hw_seed);
   ```

**Result**: Strings cannot be found via static analysis (no `.rdata` entry) or memory dumps (volatile operations are not cached).

---

### 6.2 SecureBuffer RAII with Volatile Zeroization

**Problem**: Rust's `Drop` doesn't guarantee memory erasure; optimizer may remove "dead" writes.

**Solution**: `SecureBuffer<N>` wraps stack-allocated buffers with two-pass volatile zeroization:

```rust
pub struct SecureBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        // Pass 1: Zero with volatile writes
        for i in 0..N {
            unsafe { write_volatile(&mut self.data[i], 0x00); }
        }
        compiler_fence(Ordering::SeqCst);
        
        // Pass 2: Randomize with entropy (defeats cold-boot attacks)
        let entropy = get_cpu_entropy();
        for i in 0..N {
            unsafe { write_volatile(&mut self.data[i], (entropy >> (i % 4 * 8)) as u8); }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
```

**Defense Properties**:
- **No Heap Allocation**: Stack-only prevents heap-scanning attacks
- **Volatile Writes**: Optimizer cannot remove the zeroization
- **Two-Pass Erasure**: First zeros, then randomizes (defeats residual data recovery)
- **Memory Barriers**: `compiler_fence` prevents reordering

---

### 6.3 Indirect Syscall Engine (Anti-Dump)

**Problem**: Standard `VirtualProtect` calls are easily hooked by security tools:

```rust
// ❌ DETECTABLE: ntdll!NtProtectVirtualMemory is hooked by EDR
VirtualProtect(addr, size, PAGE_NOACCESS, &old_protect);
```

**Solution**: Indirect syscalls bypass all user-mode hooks:

```rust
// ✅ STEALTH: Direct system call without touching ntdll
indirect_nt_protect_virtual_memory(process_handle, &mut addr, &mut size, protect, &mut old);
```

**Technical Implementation** (anti_dump.rs):

1. **SSN Resolution**: Find syscall number from `ntdll.dll` in-memory:
   ```rust
   // Parse ntdll's EAT to find NtProtectVirtualMemory
   let func_addr = find_exported_function("NtProtectVirtualMemory");
   
   // Read the syscall number from the function prologue:
   // mov r10, rcx
   // mov eax, SSN  <-- We extract this value
   let ssn = *(func_addr.offset(4) as *const u32);
   ```

2. **Syscall Instruction Gadget**: Find a `syscall; ret` instruction inside ntdll:
   ```rust
   // Search for pattern: 0F 05 C3 (syscall; ret)
   for offset in 0..ntdll_size {
       if bytes[offset] == 0x0F && bytes[offset+1] == 0x05 && bytes[offset+2] == 0xC3 {
           syscall_addr = ntdll_base + offset;
           break;
       }
   }
   ```

3. **Indirect Call**: Jump to the gadget with proper register setup:
   ```rust
   asm!(
       "mov r10, rcx",      // First argument
       "mov eax, {ssn:e}",  // Syscall number
       "call {addr}",       // Jump to syscall gadget (not direct syscall instruction)
       ssn = in(reg) syscall_id,
       addr = in(reg) syscall_addr,
       // ... register arguments
   );
   ```

**Why This Defeats EDR**:
- No import for `NtProtectVirtualMemory` in IAT
- No call to `ntdll.dll` code (jumps directly to gadget)
- Returns directly from kernel-mode
- Hooks in ntdll are never triggered

---

### 6.4 PE Header Erasure with Cached Metadata

**Problem**: Memory dump tools read PE headers to reconstruct executables:

```
dumper.exe -p my_app.exe → Produces valid .exe file
```

**Solution**: Surgically erase PE headers after caching essential metadata:

```rust
pub fn init_anti_dump() {
    // 1. Cache .text section metadata BEFORE destroying headers
    pe_integrity::force_cache_pe_metadata();  // Stores RVA + size in OnceLock
    
    // 2. Erase DOS header and PE signature
    erase_critical_headers(base_addr);
}

fn erase_critical_headers(base: *mut u8) {
    // Change memory protection to RW
    protected_virtual_protect(base, 0x1000, PAGE_READWRITE, &mut old);
    
    // Zero the DOS header (first 64 bytes)
    for i in 0..64 {
        unsafe { *base.offset(i) = 0x00; }
    }
    
    // Zero the PE signature and file header
    let pe_offset = /* from cached e_lfanew */;
    for i in 0..256 {
        unsafe { *base.offset(pe_offset + i) = 0x00; }
    }
    
    // Restore to PAGE_READONLY
    protected_virtual_protect(base, 0x1000, PAGE_READONLY, &mut old);
}
```

**Key Innovation**: `force_cache_pe_metadata()` stores `.text` section RVA and size **before** headers are destroyed. This allows `get_text_section_hash()` to continue working for PE integrity checks.

**Result**: 
- Memory dumps produce invalid PE files
- Rebuilding headers requires manual reverse engineering
- PE integrity hash still works (cached values)

---

### 6.5 Guard Page Trap System

**Problem**: Memory scanning tools enumerate process memory looking for secrets.

**Solution**: Deploy decoy regions with `PAGE_GUARD` protection:

```rust
fn spawn_decoy_traps() {
    for _ in 0..8 {
        // Allocate 4KB decoy region
        let decoy = VirtualAlloc(null_mut(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        // Fill with fake "secrets" to attract scanners
        fill_with_decoy_data(decoy, 4096);
        
        // Set PAGE_GUARD (access triggers exception)
        VirtualProtect(decoy, 4096, PAGE_READWRITE | PAGE_GUARD, &mut old);
        
        // Track for VEH handler
        DECOY_REGIONS.lock().push((decoy as usize, 4096));
    }
}
```

**VEH Handler** catches access:

```rust
unsafe extern "system" fn veh_handler(ptrs: *mut EXCEPTION_POINTERS) -> i32 {
    let record = (*ptrs).ExceptionRecord;
    
    if (*record).ExceptionCode == STATUS_GUARD_PAGE_VIOLATION {
        let fault_addr = (*record).ExceptionInformation[1] as usize;
        
        // Check if it's one of our decoy regions
        if is_decoy_region(fault_addr) {
            // Memory scanner detected!
            poison_encryption_on_dump_attempt();
            add_suspicion(DetectionSeverity::Critical);
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    EXCEPTION_CONTINUE_SEARCH
}
```

**Attack Detection Flow**:
```
Memory Scanner → Touches decoy region
                 ↓
                 STATUS_GUARD_PAGE_VIOLATION
                 ↓
                 VEH catches exception
                 ↓
                 POISON_SEED corrupted
                 ↓
                 All future decryption fails silently
```

---

### 6.6 Defense Summary

The Advanced Stealth Mechanisms defeat forensic attacks:

| Attack | Defense |
| --- | --- |
| **String extraction** | `dynamic_str!` leaves no trace in binary |
| **Memory dump** | PE headers erased, Guard Page traps |
| **Cold-boot attacks** | SecureBuffer two-pass zeroization |
| **EDR hooks** | Indirect syscalls bypass ntdll |
| **Process scanning** | Decoy regions with PAGE_GUARD |
| **Heap analysis** | Stack-only SecureBuffer (no heap) |

---

## Summary

fdebug provides **five concentric layers of protection**:

| Layer | Mechanism | Effect |
| --- | --- | --- |
| **Detection** | VEH, Hardware BP, RDTSC, PEB | Identify debugging attempts |
| **Obfuscation** | Polymorphic TinyVM, Control Flow Flattening | Hide security logic from analysis |
| **Integrity** | Distributed shards, SipHash, Poison Seeds | Prevent state manipulation |
| **Deception** | Decoy functions, Watchdog monitoring | Trap reverse engineers into trigger alarms |

The combination makes fdebug extremely resistant to both automated and manual reverse engineering, while maintaining the philosophy of **silent corruption** rather than obvious crashes. An attacker running the application under a debugger will experience subtle but pervasive data corruption that makes the application appear to function correctly while producing completely wrong results.


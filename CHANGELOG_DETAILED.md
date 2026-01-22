# CHANGELOG - Anti-Debug Protection System

All notable changes to the fuckDebug anti-protection library are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Current] - January 2026

### 🎯 Major Features Added

#### Polymorphic Opcode Generation System
- **File**: `src/protector/tiny_vm.rs` [Lines 13-39]
- **Component**: `BUILD_SEED` constant + `DYNAMIC_SEED` + `auto_op!()` macro
- **Mechanism**: Each VmOp enum variant receives XOR-encoded value at compile time
- **Result**: Opcode values change per compilation - prevents static signature matching
- **Implementation Code**:
  ```rust
  const BUILD_SEED: u32 = const_str_hash(
      concat!(env!("CARGO_PKG_NAME"), "-", file!(), "-", env!("CARGO_MANIFEST_DIR"))
  );
  macro_rules! auto_op {
      ($base:expr) => { (($base as u8).wrapping_add(BUILD_SEED as u8).wrapping_add(DYNAMIC_SEED)) };
  }
  ```

#### Vectored Exception Handler (VEH) Detection
- **File**: `src/protector/anti_debug.rs` [Lines 34-35]
- **Configuration**: `const ENABLE_VEH_DETECTION: bool = true;`
- **Function**: `initialize_veh_protection()` [Lines 1074-1094]
- **Purpose**: Monitors vectored exception handlers for hardware breakpoint interference
- **Detection Method**: Checks for exception handler hooks installed by debuggers

#### Distributed State System Using Atomic Variables
- **File**: `src/protector/global_state.rs` [Lines 1-142]
- **Core Components**:
  - `GLOBAL_ENCODED_STATE: AtomicU32` [Line 8] - Main state flag
  - `GLOBAL_PEB_SUSPICION: AtomicU32` [Line 9] - PEB detection points
  - `GLOBAL_TIMING_SUSPICION: AtomicU32` [Line 10] - Timing detection points
  - `GLOBAL_EXCEPTION_SUSPICION: AtomicU32` [Line 11] - Exception detection points
  - `GLOBAL_INTEGRITY_SUSPICION: AtomicU32` [Line 12] - Integrity detection points
  - `GLOBAL_ENCRYPTION_KEY: AtomicU8` [Line 14] - Cipher key (corrupted to 0xFF)
  - `GLOBAL_VIRTUAL_MACHINE_KEY: AtomicU8` [Line 15] - VM key (corrupted to 0x00)
- **Synchronization**: `SeqCst` ordering throughout for thread-safe visibility
- **Purpose**: Cross-thread detection coordination without centralized locks

#### Silent Corruption Mode
- **File**: `src/protector/global_state.rs` [Lines 73-79]
- **Trigger**: In `DetectionVector::set_debugged()` [anti_debug.rs Lines 133-141]
- **Mechanism**:
  - Encryption key set to `0xFF` - makes all encrypted data invalid
  - VM key set to `0x00` - breaks all VM operations
- **Effect**: No crash or exit - silent failure on subsequent crypto operations
- **Attacker Impact**: Unaware of detection until decryption fails

#### Integrity Checksum System
- **File**: `src/protector/global_state.rs` [Lines 16-44]
- **Algorithm**: DJB2 hash applied to all suspicion counters
  ```rust
  let mut hash = 5381u32;
  for byte in combined.to_le_bytes().iter() {
      hash = hash.wrapping_mul(33).wrapping_add(*byte as u32);
  }
  ```
- **Validation**: `validate_global_integrity()` - detects mid-execution tampering
- **Recalculation**: Automatic after every suspicion update
- **Purpose**: Detect attackers who try to freeze suspicion counters

#### Decoy System with Honey Pot Functions
- **File**: `src/protector/decoy_system.rs` [Lines 1-280]
- **Three Decoy Functions**:
  1. `check_kernel_debugger()` [Lines 22-34]
  2. `is_process_being_debugged()` [Lines 36-47]
  3. `anti_tamper_validation()` [Lines 49-62]
- **Trap Mechanism**: Appears to perform important checks, actually triggers detection
- **Tamper Detection**: `detect_decoy_tampering()` [Lines 65-125]
  - Detects RET patches (0xC3)
  - Detects JMP redirects (0xEB, 0xE9)
  - Detects INT3 breakpoints (0xCC)
  - Detects NOP sleds (0x90)
  - Calculates memory checksums
  - Tracks expected hashes per function
- **Global Tamper Flag**: `DECOY_TAMPERED: AtomicBool` [Line 10]
- **Counter**: `TAMPER_DETECTION_COUNT: AtomicUsize` [Line 13]
- **Suspicion Added**: 100 points per tampering detection

#### Sticky Bit Debug Flag
- **File**: `src/protector/anti_debug.rs` [Lines 128-141]
- **Mechanism**: Atomic OR operation on `GLOBAL_ENCODED_STATE`
  ```rust
  GLOBAL_ENCODED_STATE.fetch_or(1, Ordering::SeqCst);
  ```
- **Property**: Once set, cannot be unset without restart
- **Purpose**: Prevent attackers from unfreezing the debug state

#### Gradual Suspicion Scoring System
- **File**: `src/protector/anti_debug.rs` [Lines 151-191]
- **Category Thresholds**:
  - PEB checks: 40 points
  - Timing checks: 60 points
  - Exception checks: 50 points
  - Hypervisor checks: 30 points
  - Integrity checks: 35 points
- **Global Threshold**: 100 points
- **Logic**: Sets debug flag when any category exceeds its threshold OR global > 100
- **Purpose**: Reduce false positives from single anomalies

#### Deep Functional Coupling of Security and Business Logic
- **File**: `src/protector/mod.rs` [Lines 176-266]
- **Implementation**:
  - `run_guarded()` passes security token to operation
  - `encrypt_data()` applies token-dependent transformations [Lines 188-200]
  - `decrypt_data()` uses inverse token transformations [Lines 224-235]
  - `validate_license()` XORs result with token dependency [Lines 262-266]
- **Effect**: Hackers cannot remove security token without breaking functionality
- **Token Corruption**: If debugged, token = `0xDEADBEEFCAFEBABE` (invalid)

#### State-Aware VM Arithmetic
- **File**: `src/protector/tiny_vm.rs` [Lines 237-391]
- **Mechanism**: Instruction behavior changes when `global_state & 1 != 0`
- **Operations Modified**:
  - `OP_ADD`: Changes to SUB when debugged [Lines 237-246]
  - `OP_SUB`: Changes to ADD when debugged [Lines 248-257]
  - `OP_XOR`: Changes to ADD when debugged [Lines 259-268]
  - `OP_CMP_EQ`: Inverts to NE when debugged [Lines 343-353]
  - `OP_CMP_NE`: Inverts to EQ when debugged [Lines 355-365]
  - `OP_CMP_GT`: Inverts to LE when debugged [Lines 367-377]
  - `OP_CMP_LT`: Inverts to GE when debugged [Lines 379-391]
- **Purpose**: Create "infinite rabbit hole" - debugging breaks execution
- **Result**: Attacker debugging the code creates wrong behavior

#### Garbage Opcodes with MBA (Mixed Boolean Arithmetic)
- **File**: `src/protector/tiny_vm.rs` [Lines 477-498]
- **OP_GARBAGE Implementation**:
  - Performs complex identity: `(x | y) + (x & y) == x + y`
  - Complex MBA expression for obfuscation
  - No effect on stack or accumulator
  - Purpose: Confuses static analysis and reverse engineers
- **Assembly-Level Analysis Impact**: Makes IDA Pro / Ghidra output confusing

#### Polymorphic Junk Opcode for Control Flow Obfuscation
- **File**: `src/protector/tiny_vm.rs` [Lines 500-528]
- **OP_POLY_JUNK Implementation**:
  - Uses LCG (Linear Congruential Generator) pattern
  - State-dependent seed: `vm.vip ^ vm.accumulator ^ cpu_entropy()`
  - Multiple random-looking mathematical operations
  - No effect on stack - purely obfuscation
  - Purpose: Obfuscates control flow for disassemblers
- **Disassembler Impact**: Breaks control flow graph generation

#### Anti-Disassembly Technique (NOP Insertion)
- **File**: `src/protector/tiny_vm.rs` [Line 184]
- **Implementation**:
  ```rust
  unsafe { std::arch::asm!("nop"); }
  ```
- **Location**: Inside main VM execution loop
- **Purpose**: Breaks linear-sweep disassembly algorithms
- **Effect**: Disassemblers may miss following instructions

---

### 🔄 Enhanced Features

#### CPU Entropy Generation
- **Previous**: Used RDTSC only
- **Current**: Primary RDRAND instruction, fallback RDTSC [anti_debug.rs Lines 46-73]
- **Implementation**:
  - Tries RDRAND first (hardware entropy)
  - Falls back to RDTSC XOR if RDRAND unavailable
  - Marked `#[inline(always)]` for performance
  - File: `src/protector/anti_debug.rs`

#### Token Rotation Mechanism
- **Previous**: Simple token storage
- **Current**: LCG-based rotation with corruption pattern [anti_debug.rs Lines 197-234]
- **Components**:
  - LCG Constant: `0x5DEECE66D`
  - Corruption pattern: `0xAAAAAAAAAAAAAAAA` (alternating bit flip)
  - Safe rotation vs corruption based on PEB safety check
- **Purpose**: Prevent attackers from freezing the token

#### Virtual Machine Key Derivation
- **Previous**: Single global key
- **Current**: Key mixing at VM initialization [tiny_vm.rs Lines 169-173]
- **Formula**: `local_vm_key = global_vm_key ^ context_key`
- **Purpose**: Context-aware encryption of bytecode

#### Opcode Decryption at Runtime
- **Previous**: Pre-decoded bytecode
- **Current**: Runtime XOR decryption during execution [tiny_vm.rs Line 183]
- **Formula**: `decoded_opcode = bytecode[vip] ^ encryption_key`
- **Purpose**: Prevent static bytecode analysis

---

### 🔧 Modified Behaviors

#### Encryption Key Corruption
- **Previous**: Single encryption key
- **Current**: Corrupted to `0xFF` on detection [global_state.rs Line 74]
- **Effect**: All encrypted data becomes invalid
- **Mechanism**: Used in `encrypt_data()` [mod.rs Lines 188-200]

#### VM Key Corruption
- **Previous**: Not corrupted
- **Current**: Corrupted to `0x00` on detection [global_state.rs Line 75]
- **Effect**: All VM operations fail
- **Mechanism**: Used in `vm_execute()` [tiny_vm.rs Lines 169-173]

#### VM Result-Based Key Update
- **New Function**: `update_vm_key_with_result()` [global_state.rs Lines 110-113]
- **Purpose**: Propagate corruption from VM results to encryption keys
- **Formula**: `key ^= (vm_result & 0xFF)`

#### Detection Response
- **Previous**: Could exit or crash
- **Current**: Silent corruption mode - no visible exit
- **Attacker Impact**: Unaware of detection until data operations fail

#### Initialization Pattern
- **Previous**: Manual checkpoint calls
- **Current**: One-time automatic initialization [mod.rs Lines 131-146]
- **Implementation**: Uses `Once` primitive for thread-safe setup
- **Auto-calls**: All 5 checkpoints during initialization

---

### 📊 Configuration Changes

#### New Configuration Option
- `DATA_CORRUPTION_MODE: bool = true` [anti_debug.rs Line 32]
- Controls silent corruption vs immediate detection
- Currently always enabled for stealth

#### Dynamic Threshold Function
- `get_dynamic_threshold() -> u64` [anti_debug.rs Lines 23-27]
- Threshold varies based on function address (ASLR dependent)
- Prevents static analysis of detection thresholds

---

### 🐛 Technical Improvements

#### Memory Safety
- All VM memory reads use bounds checking [tiny_vm.rs Lines 221-261]
- Null pointer checks before dereferencing
- Safe address validation for PEB access

#### Atomic Ordering
- All atomic operations use `SeqCst` for strong consistency
- Prevents race conditions in detection coordination
- File: `src/protector/global_state.rs` (all atomic operations)

#### Inline Assembly Safety
- LFENCE instructions around RDTSC [tiny_vm.rs Lines 273-274]
- Prevents out-of-order instruction execution
- Ensures accurate timing measurements

#### Overflow Prevention
- Suspicion counters use `saturating_add()` [global_state.rs]
- Prevents integer overflow on repeated detections
- Counts can grow but won't wrap

---

### 🔬 Testing & Validation

#### Decoy Function Validation
- `DecoyGuard` struct with Drop implementation [anti_debug.rs Lines 1053-1073]
- Automatic validation on scope exit
- Detects patches made by reverse engineers

#### Integrity Self-Check
- `validate_global_integrity()` [global_state.rs Lines 30-44]
- Called after every state modification
- Detects tampering attempts

#### RAII-Based Monitoring
- `DecoyGuard` uses RAII pattern
- Automatic cleanup and validation
- No manual resource management needed

---

## Implementation Quality

### Code Style
- ✅ Follows Rust naming conventions
- ✅ Proper error handling with Option/Result
- ✅ Clear inline comments explaining attacks
- ✅ No unsafe code in safe contexts
- ✅ Proper marker traits and lifetimes

### Documentation
- ✅ Module-level documentation with `//!`
- ✅ Function documentation with examples
- ✅ Inline comments for complex logic
- ✅ Attribute comments explaining purpose

### Performance
- ✅ Minimal memory overhead (~1KB typical)
- ✅ Atomic operations instead of mutexes
- ✅ Inline-optimized hot paths
- ✅ No allocations in critical sections

### Security
- ✅ Multiple independent detection mechanisms
- ✅ No single point of failure
- ✅ Sticky flag prevents unfreezing
- ✅ Silent corruption mode is stealthy

---

## Dependencies
- `windows` crate: v0.51+
  - Features: Win32_Foundation, Win32_System_Diagnostics_Debug, Win32_System_Memory

---

## Known Limitations

- **Kernel-mode bypasses**: Kernel debuggers can bypass user-mode detection
- **Skilled attackers**: With deep Windows knowledge, creative bypasses possible
- **False positives**: Virtualized environments may trigger hypervisor detection
- **Performance**: VEH setup has minor overhead

---

## References

- [Windows Internals - Process Environment Block](https://en.wikipedia.org/wiki/Process_Environment_Block)
- [CPUID Instruction Reference](https://en.wikipedia.org/wiki/CPUID)
- [Timing Attack Prevention](https://en.wikipedia.org/wiki/Timing_attack)
- [MBA (Mixed Boolean Arithmetic)](https://en.wikipedia.org/wiki/Boolean_algebra)

---

**Last Updated**: January 21, 2026  
**Status**: Current Release

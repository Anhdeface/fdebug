# Technical Architecture Guide — fuckDebug Anti-Debug Protection System

> **Comprehensive Architectural Deep-Dive into the `fuckDebug` Engine**  
> *Five-Layer Concentric Defense Model on Windows x86_64*

---

## Executive Overview

`fuckDebug` is an advanced anti-reverse engineering and anti-debugging protection system engineered specifically for Rust applications running on Windows x86-64.

The engine operates on three foundational principles:

1. **Silent Corruption over Hard Crashes**: Rather than terminating with an exception or message box upon debugger detection (which presents an immediate crash anchor to reverse engineers), the system quietly mutates internal cryptographic keys, execution tokens, and algorithm states. The protected application continues running, but produces subtly and plausibly corrupted results.
2. **Decentralized 128-Shard State Management**: Detection scores are partitioned across **128 independent atomic shards** (64 Active and 64 Decoy), utilizing XOR masking and rotation. Attempting to freeze or zero out memory arrays creates an immediate, massive threat score spike.
3. **Hardware & Algorithmic Coupling**: Security tokens are derived dynamically from compile-time seeds, processor CPUID fingerprints, and PE `.text` section checksums. Business logic is cryptographically coupled to these tokens, forcing attackers to solve multiple non-linear equations simultaneously.

---

## The Five-Layer Concentric Defense Model

```
+-----------------------------------------------------------------------------------+
| Layer 5: Decentralized State & Silent Corruption                                  |
|   `global_state.rs` — 128 Shards (64 Active/64 Decoy), Dynamic SipHash-2-4,       |
|   Murmur3 Diffusion, Soft Backoff Latency, Token Mutation                         |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 4: Polymorphic Virtual Execution (TinyVM 2.0)                               |
|   `tiny_vm.rs` — 256-Entry Indirect V-Table, Randomized LTP Permutation,         |
|   Rolling Key Cipher, RIP Entanglement, Cycle Heartbeat (2M threshold)            |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 3: Memory Stealth & Anti-Dump                                               |
|   `anti_dump.rs`, `enhanced_veh.rs`, `decoy_system.rs` — 5-Phase Master VEH,      |
|   Synthetic x64 Call Frames, Surgical Header Erasure, 56-Byte Syscalls, Decoys    |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 2: Seed Orchestration & Key Derivation                                      |
|   `seed_orchestrator.rs` — Dynamic Seed Reconstruction, MurmurHash3 Finalizer,    |
|   Golden Ratio Modular Inverse Invariant, OnceLock Caching                        |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 1: Detection & Hardware/PE Entanglement                                     |
|   `hardware_entropy.rs`, `pe_integrity.rs`, `anti_debug.rs` — CPUID Fingerprint,  |
|   PE .text Checksum, PEB Dereference, DR0-DR7 Registers, RDTSC Baseline, TLS     |
+-----------------------------------------------------------------------------------+
```

---

## Architecture Layer 1: Detection & Hardware/PE Entanglement

Layer 1 anchors the protection engine directly into the CPU architecture and the physical disk/memory layout of the PE binary.

### 1.1 Hardware Entropy Fingerprinting (`hardware_entropy.rs`)

Layer 1 queries the underlying microprocessor using the x86 `CPUID` instruction to extract physical hardware entropy:
- `CPUID(0)`: Extracts vendor identification string (e.g., `GenuineIntel`, `AuthenticAMD`).
- `CPUID(1)`: Reads model, family, stepping, and CPU feature flags.
- `CPUID(0x80000000..=0x80000004)`: Reads extended processor brand string.

These inputs are mixed using a 32-bit FNV-1a hash. If the CPUID instruction returns all zeros (common in poorly configured virtual machine sandboxes or emulation emulators), Layer 1 falls back to `fallback_entropy()`, mixing serialized RDTSC with the current stack pointer address (`&stack_var as *const _ as usize`).

### 1.2 PE Code Section Integrity Checksum (`pe_integrity.rs`)

The `.text` section contains all executable machine instructions. Layer 1 verifies that no software breakpoints (`0xCC` / `INT3`), inline hooks (`JMP` / `CALL`), or binary patches have been applied:
1. Dynamically locates the image base in memory via `GetModuleHandleW(std::ptr::null())`.
2. Parses DOS and NT headers to identify the `.text` section virtual address and raw size.
3. Partitions the `.text` section into 1KB shards and calculates an FNV-1a rolling hash across all shards.
4. Generates the runtime `INTEGRITY_TOKEN`.

If any byte in `.text` is modified, the computed checksum immediately diverges, injecting `0xBAD_FAA_11` into `POISON_SEED` and setting `INTEGRITY_TOKEN` to `0xDEAD_DEAD_DEAD_DEAD`.

### 1.3 Multi-Vector Dynamic Detection (`anti_debug.rs`)

Layer 1 operates continuous checkpoints across critical Windows operating system artifacts:

1. **PEB Inspection**:
   Inspects `BeingDebugged` and `NtGlobalFlag` from the Process Environment Block. On Windows x86_64, `GS:[0x60]` contains the linear pointer to the PEB. The implementation loads the pointer into a scratch 64-bit register before reading `[peb + 0x02]` and `[peb + 0xBC]`:
   ```rust
   let peb: u64;
   let being_debugged: u8;
   let nt_global_flag: u32;
   unsafe {
       std::arch::asm!(
           "mov {}, gs:[0x60]",
           "movzx {}, byte ptr [{}+0x02]",
           "mov {}, dword ptr [{}+0xBC]",
           out(reg) peb,
           out(reg) being_debugged,
           in(reg) peb,
           out(reg) nt_global_flag,
           in(reg) peb,
       );
   }
   ```
2. **Hardware Debug Registers (`Dr0`–`Dr7`)**:
   Accesses thread context structures to inspect debug registers `Dr0`, `Dr1`, `Dr2`, and `Dr3`. Any non-zero address indicates an active hardware breakpoint and increments suspicion by 60 (`DetectionSeverity::High`).
3. **RDTSC Timing Anomaly Calibration**:
   Calibrates a baseline CPU cycle latency across 2,000 iterations using serialized `lfence; rdtsc` execution. If subsequent checkpoint blocks observe execution cycle deltas exceeding the baseline by more than 250 cycles, single-stepping or hypervisor VM-exit interception is detected.
4. **Hypervisor & Cloud Optimization**:
   Inspects CPUID leaf 1 ECX bit 31 and parses processor brand strings. Decodes the hypervisor brand string `b"Microsoft Hv"` dynamically. Standard Windows Hyper-V, Virtualization-Based Security (VBS), and WSL2 environments are recognized and permitted without false-positive poisoning.
5. **Driver & Kernel Hook Blacklisting**:
   Enumerates active system drivers using `EnumDeviceDrivers`. Buffer slice indexing is strictly clamped via `(len as usize).min(buffer.len())` to prevent buffer overflow panics. Matches base driver names against known analysis tools (`x64dbg`, `vbox`, `vmware`, `wireshark`).
6. **Early-Bird TLS Callback (`.CRT$XLB`)**:
   Registered to execute during `DLL_PROCESS_ATTACH` before `main` entry. Inspects PEB flags before the attacker can place initial user-space breakpoints.

---

## Architecture Layer 2: Seed Orchestration & MurmurHash3 Key Derivation

Layer 2 resolves the fundamental flaw of static cryptographic constants. In `fuckDebug`, all cryptographic keys, opcode maps, and buffer encryption masks are derived dynamically at runtime.

### 2.1 Three-Shard Entropy Recomposition

The **Seed Orchestrator** (`seed_orchestrator.rs`) reconstructs the 32-bit dynamic seed by mixing three independent entropy shards:

```
+-----------------------------------------------------------+
| Shard 1: Build-Time Seed (Unique per compiled binary)    |
|   Generated by build.rs into OUT_DIR/dynamic_seed.rs      |
+-----------------------------------------------------------+
                             XOR
+-----------------------------------------------------------+
| Shard 2: Hardware Entropy Fingerprint                    |
|   Generated by hardware_entropy.rs from CPUID             |
+-----------------------------------------------------------+
                             XOR
+-----------------------------------------------------------+
| Shard 3: PE Integrity Hash                               |
|   Generated by pe_integrity.rs from .text section bytes   |
+-----------------------------------------------------------+
                             │
                             ▼
              MurmurHash3 Avalanche Mixing
                             │
                             ▼
                    FINAL_DYNAMIC_SEED
```

### 2.2 MurmurHash3 Avalanche Finalizer

To ensure complete non-linear diffusion, Layer 2 executes the MurmurHash3 32-bit integer finalizer:

```rust
fn avalanche_mix(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(0x85EBCA6B);
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2AE35);
    x ^= x >> 16;
    x
}
```

**Cryptographic Properties**:
- **Strict Avalanche Criterion (SAC)**: Flipping a single bit in any of the three inputs flips ~50% of the output bits.
- **Bijectivity**: The function is a mathematical bijection on $\mathbb{Z}_{2^{32}}$ (zero maps to zero, every input maps to a unique output), formally proven by Verus theorem `theorem_math_murmur3_invertible`.
- **High Performance**: Evaluates in 5–10 CPU cycles.

### 2.3 Caching & Golden Ratio Invariance

- **OnceLock Initialization**: Wrapped in `static RECONSTRUCTED_SEED: OnceLock<u32> = OnceLock::new()`. The first call incurs ~50–100μs overhead; all subsequent reads complete in 1–10ns without locking overhead.
- **Golden Ratio Automorphism**: Dynamic key transformations utilize the golden ratio constant $M = 0x9E3779B97F4A7C15$ and its modular inverse $M^{-1} = 0x61C8864680B583EB$, satisfying:

$$M \times M^{-1} \equiv 1 \pmod{2^{64}}$$

This guarantees that uncorrupted keys can be cleanly inverted, while any suspicion added to the key produces permanent irreversible dispersion.

---

## Architecture Layer 3: Memory Stealth & Anti-Dump

Layer 3 defeats memory dumping utilities, debugging hooks, and process inspection tools.

### 3.1 Five-Phase Master Vectored Exception Handler (`enhanced_veh.rs`)

`enhanced_veh.rs` implements a master exception filter pre-empting standard Structured Exception Handling (SEH):

```
Exception Occurs
       │
       ▼
[Phase 1: Entry Filtering]
       │ ── Is ExceptionAddress in .text OR is code STATUS_GUARD_PAGE_VIOLATION?
       │    NO  → Return EXCEPTION_CONTINUE_SEARCH
       │    YES → Intercept
       ▼
[Phase 2: Shallow Stack Unwinding]
       │ ── Walk 2 frames via RtlVirtualUnwind
       │    Invalid frames or RIP=0 → Poison context & redirect
       ▼
[Phase 3: Anti-Dump Trap Dispatch]
       │ ── STATUS_GUARD_PAGE_VIOLATION caught?
       │    YES → Poison encryption keys & trip blind diagnostic mode
       ▼
[Phase 4: Anti-Debug Breakpoint Dispatch]
       │ ── EXCEPTION_BREAKPOINT (INT3) or SINGLE_STEP (Drx)?
       │    YES → Increment suspicion & construct redirection frame
       ▼
[Phase 5: TinyVM Debug Register Verification]
       │ ── Verify Dr0-Dr3 against rolling checksum
       │    Corrupted → Synthesize call frame to safe_exit_stub
       ▼
Return EXCEPTION_CONTINUE_EXECUTION
```

### 3.2 Windows x64 ABI-Compliant Call Frame Synthesis

When redirecting execution to a decoy handler or safe termination stub, simply altering `context.Rip` violates the Windows x64 calling convention, causing crash dialogs when the function attempts to execute `ret`.

Layer 3 synthesizes an authentic 64-bit call frame:
1. Aligns `context.Rsp` to 16 bytes minus 8: `(context.Rsp & !0xFu64).wrapping_sub(0x28)`.
2. Writes the return address of `safe_exit_stub` (which calls `ExitThread(0)`) at `[Rsp]`.
3. Reserves 32 bytes of shadow space at `[Rsp + 8 .. Rsp + 32]`.
4. Updates `context.Rip` to the decoy function entry point.

### 3.3 Surgical PE Header Obfuscation (`anti_dump.rs`)

Dump tools rely on valid PE headers to reconstruct executables. Naive anti-dump implementations zero the entire DOS header (`MZ`), which causes crashes in system DLLs.

Layer 3 performs **surgical corruption**:
- **Preserved**: DOS header (`MZ` signature) and PE section headers, maintaining OS and CRT loader stability.
- **Erased**: `AddressOfEntryPoint`, NT signature (`0x00004550`), export tables, and debug directories are overwritten with pseudo-random entropy derived from `KUSER_SHARED_DATA`. Memory dumpers fail to identify section alignments or entry points.

### 3.4 Indirect Syscall Engine (`anti_dump.rs`)

To bypass EDR API hooks on `VirtualProtect` or `NtProtectVirtualMemory`:
1. Resolves the System Service Number (SSN) dynamically from `ntdll.dll` export tables.
2. Locates a `syscall; ret` instruction gadget inside `ntdll.dll`.
3. Executes the system call via inline assembly with **56 reserved stack bytes** (`sub rsp, 0x38` / `add rsp, 0x38`), ensuring the 5th argument at `[rsp + 0x28]` is stored safely within the allocated frame.

### 3.5 Guard Page Honeytraps & Watchdog v2

- **Guard Page Honeytraps**: Commits 4 decoy memory pages allocated with `PAGE_GUARD`. If a memory scanner attempts a linear memory read, a `STATUS_GUARD_PAGE_VIOLATION` is triggered and intercepted by the Master VEH, tripping silent poisoning.
- **KUSER Watchdog v2**: Reads `InterruptTime` from `0x7FFE0014` using paired aligned 32-bit reads. If execution latency exceeds 5 seconds (indicating thread suspension in a debugger), silent poisoning activates. Under heavy CPU load (>85%), timeout adaptively doubles to 10 seconds. Includes a 10-second startup warm-up period.

### 3.6 Decoy Honey Pot Functions (`decoy_system.rs`)

Visible dummy functions (`check_kernel_debugger`, `is_process_being_debugged`) are exported to attract attackers. An eager watchdog verifies the first 16 bytes of each decoy function at startup (`init_decoy_system()`) and during heartbeats (`watchdog_check_decoys()`). If an attacker patches a prologue with `RET` (`0xC3`), `NOP+RET` (`[0x90, 0xC3]`), or `JMP` (`0xEB`, `0xE9`), the watchdog immediately flags `DECOY_TAMPERED` and adds 60 suspicion points.

---

## Architecture Layer 4: Polymorphic Virtual Execution (TinyVM 2.0)

Layer 4 virtualizes critical operations and sensitive string decoding through an indirect-threaded bytecode virtual machine.

### 4.1 Indirect Threading V-Table Dispatch

TinyVM 2.0 replaces monolithic `match` or `switch` dispatch loops with an indirect function pointer dispatch table:

```rust
pub type VmInstruction = unsafe fn(
    bytecode: &[u8],
    vm: &mut TinyVm,
    state: &mut VmExecutionState,
    encryption_key: u8,
);
```

The runtime initializes a 256-entry table (`[VmInstruction; 256]`). Unused opcode slots default to `op_trap`.

### 4.2 Randomized Logic-to-Physical Permutation (`LTP_MAP`)

Opcodes are not mapped to fixed indices. Instead, a 256-byte Logic-to-Physical (`LTP_MAP`) array is generated at runtime via an `Xorshift32` PRNG seeded by the reconstructed dynamic seed:

$$\text{PhysicalHandler} = \text{TABLE}[\text{LTP\_MAP}[\text{LogicalOpcode}]]$$

- Every compiled binary and target machine executes opcodes through a unique permutation.
- Reverse engineers cannot reuse static disassembly signatures or opcode maps across targets.

### 4.3 The Chaos Trap

If an attacker passes a fake, zeroed, or static seed (such as `0x00000000` or `0xDEADBEEF`), the mapping logic activates the **Chaos Trap**:
- Mixes the seed with RDTSC and ASLR stack address entropy.
- Produces a scrambled LTP map where arithmetic opcodes execute jumps, loads execute traps, and calculations produce unpredictable garbage without crashing.

### 4.4 Rolling Key Cipher & Entangled Execution

Bytecode is encrypted with a rolling key cipher. During instruction fetch:

```rust
let decrypted = ciphertext ^ key ^ ((vip as u8).wrapping_mul(0x5D));
key = key.rotate_left(3).wrapping_add(decrypted);
```

- **RIP Entanglement**: The decryption key is XORed with the upper 16 bits of the physical instruction pointer (`get_rip_marker`). If the binary code is relocated or hooked via dynamic binary instrumentation (DBI) engines (such as Frida or DynamoRIO), the key desynchronizes.
- **Thread Cycle Heartbeat**: Measures `QueryThreadCycleTime` across instructions. If the cycle delta exceeds `ANTI_TRACE_CYCLE_THRESHOLD` (2,000,000 cycles), tracing is detected and the key is corrupted.

### 4.5 Zero-Static-Trace `dynamic_str!` & `SecureBuffer<N>`

String literals wrapped in `dynamic_str!("secret")` are compiled into encrypted bytecode sequences. At runtime:
1. Decrypted in volatile stack memory via TinyVM.
2. Returned inside a `SecureBuffer<const N: usize>` implementing `Deref<Target = [u8]>`.
3. When dropped, scrubs memory via a 2-pass volatile drop (Pass 1: dynamic seed scramble, Pass 2: volatile zeros, compiler fences, and x86 asm memory barrier).

---

## Architecture Layer 5: Decentralized State, 128-Shard Scoring & Silent Corruption

Layer 5 eliminates the traditional centralized boolean `is_debugged` flag, distributing threat state across a decentralized state machine.

### 5.1 128-Shard Active/Decoy State Machine (`global_state.rs`)

The threat score is maintained across `SUSPICION_SHARDS: [AtomicU32; 128]`:
- **64 Active Shards**: Contain genuine suspicion points.
- **64 Decoy Shards**: Contain high-entropy decoy noise mimicking real detections.

```
Pair Index:       0       1       2       3      ...     63
Shards:        [0, 1]  [2, 3]  [4, 5]  [6, 7]   ...  [126, 127]
Pair Map Bit:    0       1       0       1      ...      0
Role:         [A, D]  [D, A]  [A, D]  [D, A]   ...    [A, D]

(A = Active Shard, D = Decoy Shard)
```

The partition is governed by `pair_map: u64` derived via `mix_seed_to_u64(seed)`. For pair $i$, if bit $i$ is 0, shard $2i$ is Active; if bit $i$ is 1, shard $2i + 1$ is Active.

### 5.2 XOR Masking & Zero-Freeze Trap

Each shard stores an encoded value:

$$\text{Encoded}_i = (\text{Value}_i \lll (i \bmod 32)) \oplus \text{Mask}_i$$

where $\text{Mask}_i$ is derived from `mix_seed(seed, i)`.

**Defense Against Memory Freezing / Zeroing**:
If an attacker freezes memory or writes `0x00` across the entire array, the decoded value becomes:

$$\text{Decoded}_i = (0 \oplus \text{Mask}_i) \ggg (i \bmod 32) = \text{Mask}_i \ggg (i \bmod 32)$$

Summing across all 64 active shards results in a massive pseudo-random score exceeding 500 points, immediately tripping the honeytrap and returning `0xFFFFFFFF`.

### 5.3 Dispersed Scattering Algorithm

When suspicion is added (`add_suspicion(severity)`):
1. The total points are split into 3 random positive values ($p_1 + p_2 + p_3 = \text{amount}$).
2. $p_1, p_2, p_3$ are added to 3 randomly selected Active shards using atomic compare-exchange loops.
3. Simultaneously, 3 pseudo-random noise values are written to 3 randomly selected Decoy shards using the identical rotation and mask encoding.

An attacker monitoring memory writes cannot distinguish between authentic detections and decoy camouflage.

### 5.4 Dynamic SipHash-2-4 Integrity Hash

To prevent offline tampering with global memory:
- `recalculate_global_integrity()` computes a 64-bit SipHash-2-4 over the reconstructed threat score and decay timestamp.
- The SipHash initialization vectors (`GLOBAL_SIPHASH_V0..V3`) are dynamically randomized at startup using the runtime seed.
- If memory is edited without updating the SipHash digest, `validate_global_integrity()` returns `false`, tripping immediate key poisoning.

### 5.5 Saturated Score Decay

To prevent temporary environmental hiccups from permanently impairing execution:
- Every 300 seconds, `apply_decay()` reduces suspicion by 5 points.
- Decays both Active shards (reducing genuine score) and Decoy shards (mimicking decay patterns).
- The score decays saturating at baseline 0 and never drops below legitimate detection minimums.

### 5.6 Soft Corruption vs Hard Corruption

`fuckDebug` enforces a two-tier response to accumulated suspicion:

1. **Soft Corruption (Exponential Latency Backoff)**:
   For scores between 50 and 100:
   $$\text{Delay} = (\text{Score} - 50)^2 \text{ ms}$$
   On the main thread, the delay is capped at 50ms (~20 FPS) to avoid Windows ANR hangs while introducing system lag that severely disrupts automated fuzzing.
2. **Hard Corruption (Data & Token Poisoning)**:
   For scores > 100 or when `POISON_SEED` is contaminated:
   - `SecureVault::unlock` rotates the transformation key by `(score % 61)` and multiplies by `0x9E3779B97F4A7C15`.
   - `CoupledLogic` and `Corruptible` silently mutate application data (e.g., bit flips, numeric scaling, inverted booleans).
   - `trigger_silent_poisoning()` corrupts `POISON_SEED`, `GLOBAL_ENCRYPTION_KEY`, and `GLOBAL_VIRTUAL_MACHINE_KEY`.

---

## Complete API Reference

### Core Public APIs

```rust
// Initialization Macro
let protector = setup_anti_debug!(get_dynamic_seed());

// Dynamic Seed Accessors
pub fn get_dynamic_seed() -> u32;
pub fn get_dynamic_seed_u8() -> u8;

// Suspicion Management
pub fn get_suspicion_score() -> u32;
pub fn get_combined_score() -> u64;
pub fn add_suspicion(severity: DetectionSeverity);
pub fn add_suspicion_at(severity: DetectionSeverity, checkpoint_id: u8);
pub fn trigger_silent_poisoning();

// Memory Scrubbing Buffer
pub struct SecureBuffer<const N: usize>;
impl<const N: usize> std::ops::Deref for SecureBuffer<N> {
    type Target = [u8];
}
```

### Internal Engine Primitives (Not for Direct Public Use)

- `opaque_predicate_eq(u32, u32) -> bool`: Internal obfuscation primitive in `mod.rs`.
- `opaque_predicate_branch(bool) -> bool`: Internal obfuscation primitive in `mod.rs`.
- `pe_integrity::heartbeat_check(0)`: Internal shard table caching and PE verification.

---

## Architectural Comparison & Summary Table

| Defense Layer | Primary Modules | Key Mechanisms | Defeated Vectors |
|---|---|---|---|
| **Layer 1: Foundational Entropy & Detection** | `hardware_entropy.rs`, `pe_integrity.rs`, `anti_debug.rs` | CPUID fingerprinting, PE `.text` FNV-1a checksum, PEB scratch dereference, DRx checks, RDTSC calibration, TLS callback | Static key extraction, inline patches, INT3 hooks, hardware breakpoints, debuggers |
| **Layer 2: Seed Orchestration** | `seed_orchestrator.rs` | 3-shard entropy mixing, MurmurHash3 avalanche finalizer, OnceLock caching, golden ratio automorphism | Replay attacks, cross-device binary copying, static analysis of constants |
| **Layer 3: Memory Stealth & Anti-Dump** | `anti_dump.rs`, `enhanced_veh.rs`, `decoy_system.rs` | 5-phase master VEH, synthetic x64 ABI frames, surgical PE NT header erasure, 56-byte indirect syscalls, decoy honey pots | Memory dumpers (Scylla, ProcDump), guard page scanners, prologue patchers, EDR hooks |
| **Layer 4: Polymorphic Virtual Execution** | `tiny_vm.rs` | 256-entry indirect v-table, randomized `LTP_MAP` permutation, rolling key cipher, RIP entanglement, cycle heartbeat | Disassemblers (IDA, Ghidra), DBI engines (Frida, DynamoRIO), instruction tracing |
| **Layer 5: Decentralized State & Silent Corruption** | `global_state.rs` | 128 atomic shards (64 Active / 64 Decoy), pair-based partition, XOR masking, 3-shard scatter, dynamic SipHash, soft backoff | Memory search/freeze tools (Cheat Engine), data breakpoints, static decompilation |

---

*fuckDebug Architecture Guide — Formally Verified & Synchronized — 2026*

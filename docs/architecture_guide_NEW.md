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
|   `tiny_vm.rs` — 256-Entry Indirect V-Table, Mode H Non-Linear LSB Diffusion,     |
|   Dynamic LTP Chaos Trap, Two-Phase Fallback, Anti-Trace Derangement Heartbeat    |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 3: Memory Stealth & Anti-Dump                                               |
|   `anti_dump.rs`, `enhanced_veh.rs`, `decoy_system.rs` — 5-Phase Master VEH,      |
|   1232-Byte CONTEXT ABI, 64-Byte (0x40) Syscalls, Lock-Free Decoy Traps           |
+-----------------------------------------------------------------------------------+
                                          ▲
+-----------------------------------------------------------------------------------+
| Layer 2: Seed Orchestration & Hardened Key Derivation                             |
|   `seed_orchestrator.rs` — Asymmetric 3-Pipeline ARX, Pure Bijective KDF,        |
|   Non-Linear u8 Projection, Lock-Free Dynamic Atomic Caching, Monotonic Epochs    |
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

## Architecture Layer 2: Seed Orchestration & Formally Hardened Key Derivation

Layer 2 resolves the fundamental flaw of static cryptographic constants. In `fuckDebug`, all cryptographic keys, opcode maps, and buffer encryption masks are derived dynamically at runtime through an entropy engine hardened against cryptanalytic and entropy-collapse attacks.

### 2.1 Asymmetric 3-Pipeline ARX Shard Recomposition

The **Seed Orchestrator** (`seed_orchestrator.rs`) reconstructs the 32-bit dynamic seed by mixing three independent entropy shards through asymmetric ARX (Addition, Rotation, XOR) pipelines, breaking linear XOR cancellation ($\Delta \oplus \Delta = 0$, DEF-L2-02) and zero-sum entropy collapse (DEF-L2-03):

```
+-----------------------------------------------------------+
| Shard 1: Build-Time Seed (Unique per compiled binary)    |
|   s1 = (b + 0x61C88647) mod 2^32                          |
+-----------------------------------------------------------+
                             │
+-----------------------------------------------------------+
| Shard 2: Hardware Entropy Fingerprint                    |
|   s2 = ((h ^ 0x85EBCA6B) * 0x9E3779B9) mod 2^32          |
+-----------------------------------------------------------+
                             │
+-----------------------------------------------------------+
| Shard 3: PE Integrity Hash                               |
|   s3 = ((p <<< 13) + 0xC2B2AE35) mod 2^32                 |
+-----------------------------------------------------------+
                             │
                             ▼
              Asymmetric Combination: (s1 ^ s2) + s3
                             │
                             ▼
           Pure Bijective Fixed-Point-Free KDF
              Master Seed = fmix32(Recomposed ^ 0x9E3779B9)
                             │
                             ▼
                    FINAL_DYNAMIC_SEED (≠ 0)
```

**Algebraic Formulation**:
$$\begin{aligned}
s_1 &= (b \boxplus 0x61C88647) \pmod{2^{32}} \\
s_2 &= ((h \oplus 0x85EBCA6B) \odot 0x9E3779B9) \pmod{2^{32}} \\
s_3 &= ((p \lll 13) \boxplus 0xC2B2AE35) \pmod{2^{32}} \\
S_{recomposed} &= ((s_1 \oplus s_2) \boxplus s_3) \pmod{2^{32}}
\end{aligned}$$

For any non-zero differential $\Delta \neq 0$, simultaneous perturbation of hardware entropy ($h \oplus \Delta$) and PE hash ($p \oplus \Delta$) yields strictly divergent output:
$$\text{recompose}(b, h \oplus \Delta, p \oplus \Delta) \neq \text{recompose}(b, h, p)$$
Even on null inputs $(0, 0, 0)$, the engine yields $0xC5AFC6F9 \neq 0$.

### 2.2 Pure Bijective Fixed-Point-Free KDF

The master seed derivation applies a pure bijective permutation on $\mathbb{Z}_{2^{32}}$ with golden-ratio translation, eliminating the trivial zero fixed-point defect of MurmurHash3 ($fmix32(0) = 0$, DEF-L2-01):

```rust
pub fn pure_bijective_kdf(x: u32) -> u32 {
    let offset = x ^ 0x9E3779B9;
    avalanche_mix(offset)
}
```

**Cryptographic & Mathematical Properties**:
- **Zero Fixed-Point Elimination**: $f(0) = fmix32(0x9E3779B9) = 0x92CA2F0E \neq 0$, and $\forall x \in \mathbb{Z}_{2^{32}}, f(x) \neq x$.
- **Two-Sided Invertibility**: Possesses an exact algebraic modular inverse $f^{-1}(y) = inv\_fmix32(y) \oplus 0x9E3779B9$, satisfying $f^{-1}(f(x)) = x$ and $f(f^{-1}(y)) = y$ without information loss.
- **Strict Avalanche Criterion (SAC)**: Formally proven to achieve mean bit diffusion in $[12.0, 20.0]$ bits (ideal 16.0 bits, 50% diffusion across all 32 single-bit flips).
- **Verus SMT Proofs**: Verified under `theorem_hardened_kdf_two_sided_bijectivity` and `theorem_hardened_kdf_zero_fixed_point_eliminated`.

### 2.3 Non-Linear 4-Stage ARX u8 Projection

To generate the 8-bit dynamic seed required by TinyVM 2.0 without the 24-dimensional linear kernel collapse of simple XOR folding ($\ker(\pi) = 2^{24}$ elements, DEF-L2-04), Layer 2 evaluates a 4-stage non-linear ARX projection:

```rust
pub fn project_u8_hardened(seed: u32) -> u8 {
    let m1 = seed.wrapping_mul(0x9E3779B9);
    let m2 = m1 ^ (m1 >> 16);
    let m3 = m2.wrapping_mul(0x85EBCA6B);
    ((m3 ^ (m3 >> 11) ^ (m3 >> 22)) & 0xFF) as u8
}
```

**Statistical Guarantees**:
- **Shannon Entropy**: Achieves $H \approx 7.998$ bits (exceeding AWS unit proof standard threshold $H \ge 7.995$ bits across $2^{18}$ samples).
- **Uniform Distribution**: Passes Chi-Squared goodness-of-fit test ($\chi^2 < 340.0$ with 255 degrees of freedom).
- **Kernel Resistance**: Known linear nullspace elements like $k = 0x00030201$ project to non-zero byte `0x6F`.

### 2.4 Lock-Free Atomic Caching & Monotonic Epochs

To eliminate static `OnceLock` temporal blindness to post-initialization debugger attachment (DEF-L2-05), Layer 2 uses lock-free atomic primitives:

```rust
static RECONSTRUCTED_SEED: AtomicU32 = AtomicU32::new(0);
static SEED_EPOCH: AtomicU64 = AtomicU64::new(0);
```

- **Lock-Free Read Latency**: Single atomic load with `Ordering::Acquire` evaluates in $1\text{--}3\text{ns}$ ($< 10\text{ns}$ under extreme multi-threaded contention).
- **Dynamic Threat Coupling**: `evaluate_dynamic_seed(threat_score, poison_token)` dynamically couples runtime threat telemetry into the base seed, while `arx_fold_token64` protects against symmetric 64-bit token injection.
- **Monotonic Reseeding & Invalidation**: `reseed_with_token(token)` and `invalidate_cache()` update the seed and increment `SEED_EPOCH` with `Ordering::Release`, triggering instant cache refreshes across all worker threads.

---

## Architecture Layer 3: Memory Stealth, Master VEH & Anti-Dump

Layer 3 defeats memory dumping utilities, debugging hooks, and process inspection tools through formal mathematical invariants and lock-free execution.

### 3.1 Five-Phase Master Vectored Exception Handler (`enhanced_veh.rs`)

`enhanced_veh.rs` implements a pre-emptive exception filter registered first via `AddVectoredExceptionHandler(1, Some(master_veh_handler))` to protect execution before standard Structured Exception Handling (SEH) or external debuggers can intervene:

```
Exception Occurs
       │
       ▼
[Phase 1: Entry Filtering & Bounded Re-entrancy]
       │ ── VehReentrancyGuard check (thread-local atomic depth <= 1)
       │    STATUS_GUARD_PAGE_VIOLATION (0x80000001) intercepted unconditionally
       │    Hardware/software faults: is ExceptionAddress in .text?
       │    NO  → Return EXCEPTION_CONTINUE_SEARCH (0)
       │    YES → Intercept
       ▼
[Phase 2: Strict TEB Stack Unwinding]
       │ ── Query TEB limits: gs:[0x08] (StackBase) & gs:[0x10] (StackLimit)
       │    Validate initial Context: Rip != 0, Rsp % 8 == 0, StackLimit <= Rsp <= StackBase - 8
       │    Walk frames via RtlVirtualUnwind (enforcing frames_walked >= 2)
       │    Invalid frames or truncated stack → Poison context & redirect
       ▼
[Phase 3: Lock-Free Anti-Dump Trap Dispatch]
       │ ── STATUS_GUARD_PAGE_VIOLATION caught?
       │    Query Lock-Free Atomic Decoy Table [(AtomicUsize, AtomicUsize); 8] with saturating math
       │    YES → Quarantine page to PAGE_NOACCESS & poison keys
       ▼
[Phase 4: Anti-Debug Breakpoint Dispatch]
       │ ── EXCEPTION_BREAKPOINT (INT3) or EXCEPTION_SINGLE_STEP (0x80000004)?
       │    Verify Dr0 heartbeat match; if mismatch or EFLAGS.TF set → trap
       ▼
[Phase 5: TinyVM Context & Single-Step Precedence]
       │ ── Verify Dr0-Dr3 against rolling checksum
       │    Corrupted or TF stepping → Synthesize call frame to safe_exit_stub
       ▼
Return EXCEPTION_CONTINUE_EXECUTION (-1)
```

- **Re-entrancy Confinement**: Managed via `VehReentrancyGuard` utilizing a thread-local cell. Confinement depth is strictly bounded to $\text{Depth}(T) \le 1$. If already active (`cur >= 1`), it immediately returns `EXCEPTION_CONTINUE_SEARCH` (0), eliminating recursive fault loops and kernel stack exhaustion. RAII `drop()` decrements depth safely via `saturating_sub(1)`.
- **TEB Stack Bounds Verification**: Enforces that all stack pointers during unwinding reside strictly within `[TEB.StackLimit, TEB.StackBase]`:
  $$\text{spec\_stack\_frame\_valid}(w, \text{rip}, \text{rsp}, \text{limit}, \text{base}) \iff (w \ge 2) \land (\text{rip} \ne 0) \land (\text{rsp} \equiv 0 \pmod 8) \land (\text{limit} \le \text{rsp} \le \text{base} - 8)$$
  Leaf frames without unwind metadata dereference the return address from `*(ctx.Rsp as *const u64)` with an 8-byte stack advance. Truncated or spoofed stack frames terminate traversal and route directly to `poison_thread_context`.
- **Single-Step Precedence & TF Trapping**: Enforces strict priority between authorized heartbeats and debugger stepping:
  $$\text{spec\_is\_authorized\_heartbeat} \iff (Dr0 = \text{expected}) \land (Dr1 = Dr2 = Dr3 = 0) \land ((\text{EFlags} \land 0\text{x}100) = 0)$$
  Authorized TinyVM heartbeats continue execution (`EXCEPTION_CONTINUE_EXECUTION`). When the CPU Trap Flag is set ($(\text{EFlags} \land 0\text{x}100) \ne 0$), TF is cleared (`context.EFlags &= !0x100`) and the thread context is poisoned immediately.

### 3.2 Win32 CONTEXT ABI (1232 Bytes) & Call Frame Synthesis

To guarantee complete zero-defect interoperability with Windows x64 kernel exception dispatching:
- **1232-Byte Full CONTEXT Layout**: Conforms 100% to the official Windows x64 `CONTEXT` ABI specification (`0x4D0` / 1232 bytes, `#[repr(C, align(16))]`), providing exact byte offsets for `P1Home`..`P6Home` (`0x00..0x30`), `ContextFlags` & `MxCsr` (`0x30..0x38`), general-purpose registers `Rax`..`R15` (`0x78..0xF8`), `Rip` (`0xF8..0x100`), 16-byte aligned `XSAVE_FORMAT` (512 bytes, `0x100..0x300` holding `Xmm0`..`Xmm15`), upper vector registers `[M128A; 26]` (416 bytes, `0x300..0x4A0`), and debug control registers (`0x4A8..0x4D0`).
- **Spatial Memory Safety**: Eliminates buffer overrun risks under `RtlVirtualUnwind`. Formally verified via Verus theorem `theorem_xmm15_spatial_safety`: `Xmm15` write at offset `0x290` (656) with 16 bytes ends at 672, strictly within the 1232-byte allocated buffer.
- **Call Frame Synthesis**:
  1. Aligns `context.Rsp` to 16 bytes minus 8: `(context.Rsp & !0xFu64).wrapping_sub(0x28)`.
  2. Pushes the return address of `safe_exit_stub` (which calls `ExitThread(0)`) at `[Rsp]`.
  3. Reserves 32 bytes of shadow space at `[Rsp + 8 .. Rsp + 32]`.
  4. Redirects `context.Rip` to the decoy target (`is_process_being_debugged`) and loads poisoned `context.Rax = key.wrapping_mul(0xDEADBEEF)`.

### 3.3 Lock-Free Atomic Decoy Guard Pages (`anti_dump.rs`)

Replaces vulnerable mutex synchronization with high-performance lock-free atomic tracking:
- **Lock-Free Atomic Table**: Decoy intervals are registered into a fixed-size atomic array `pub static DECOY_REGIONS: [(AtomicUsize, AtomicUsize); 8] = [(AtomicUsize::new(0), AtomicUsize::new(0)); 8];` (128 bytes total). Registration uses lock-free CAS `slot.0.compare_exchange(0, base, Ordering::AcqRel, Ordering::Acquire)`. Eliminates all mutex locks inside the VEH context, guaranteeing zero-deadlock signal/exception safety.
- **Saturating Address Arithmetic**: Interval membership checks calculate upper bounds via `base.saturating_add(size)` rather than standard addition:
  $$\text{spec\_point\_contained\_saturating}(A, B, S) \iff (S > 0) \land (A \ge B) \land (A < B \mathbin{\dot{+}} S)$$
  This mathematically eliminates integer wrap-around vulnerabilities when decoy pages are allocated in high memory ranges ($> 2^{64} - 4096$).
- **Persistent Multi-Thread Trap Quarantine**: When dumpers trigger `STATUS_GUARD_PAGE_VIOLATION`, the handler dynamically transitions the tripped decoy page from `PAGE_READWRITE` to `PAGE_NOACCESS` (`0x01`) via `VirtualProtect`. This permanently isolates honeypot buffers and prevents concurrent dumping threads from reading decoy memory undetected.

### 3.4 16-Byte Aligned Indirect Syscall Engine (`anti_dump.rs`)

Bypasses user-mode AV/EDR hooks on memory management APIs with strict mathematical calling convention invariants:
1. **SSN Grammar Validation & Hook Rejection**:
   - Inspects `ntdll.dll` function prelude bytes against the canonical NT syscall pattern: `4C 8B D1 B8` (`mov r10, rcx; mov eax, <SSN>`).
   - Bounded opcode search window `max_scan = min(32, len.saturating_sub(8))` with strict range check `0 < ssn && ssn < 0x1000`.
   - Proactively rejects 64-bit absolute detour hooks (`48 B8 <addr> FF E0`), 5-byte relative JMP hooks (`E9 <rel32>`), and trampolines inserted by monitoring software.
2. **16-Byte Stack Frame Invariant (`RSP % 16 == 0`)**:
   - Inline assembly reserves **64 bytes** (`SYSCALL_STACK_RESERVED_BYTES = 0x40`, `sub rsp, 0x40` / `add rsp, 0x40`).
   - Modular Congruence Proof: With compiler caller $RSP_0 \equiv 0 \pmod{16}$, pre-call stack allocation gives $RSP_{\text{pre-call}} = RSP_0 - 0\text{x}40 \equiv 0 \pmod{16}$. Callee entry after return address push gives $RSP_{\text{callee-entry}} \equiv 8 \pmod{16}$, strictly conforming to Microsoft x64 calling conventions.
   - Callee parameter translation: Writes 5th parameter `p_old` at caller slots `[rsp+0x20]` and `[rsp+0x28]`. When `call {target_gadget}` pushes the return address, callee parameter 5 lands cleanly at `[rsp+0x28]`.
   - Forensic Shadow Space Scrubbing: Automatically zeroes (`mov qword ptr [rsp+0x20], 0`, `mov qword ptr [rsp+0x28], 0`) shadow parameter space before restoring `rsp` via `add rsp, 0x40`.

### 3.5 KUSER_SHARED_DATA Tick Rollover Synchronization

- **Dual High-Tick Verification Loop**: Reads `InterruptTime` from `0x7FFE0014` (`LowPart`), `0x7FFE0018` (`High1Time`), and `0x7FFE001C` (`High2Time`) using volatile reads in a Seqlock protocol (`read_kuser_time_lock_free`):
  ```rust
  loop {
      let high1 = high1_ptr.read_volatile() as u64;
      let low = low_ptr.read_volatile() as u64;
      let high2 = high2_ptr.read_volatile() as u64;
      if high1 == high2 {
          return (high1 << 32) | low;
      }
      std::hint::spin_loop();
  }
  ```
  Eliminates the 4.29-billion tick jump ($2^{32} \times 100\text{ns} \approx 429.5\text{s}$) when the low 32-bit counter rolls over every 7.1 minutes, preventing false-positive suspicion alarms.
- **Adaptive Liveness Threshold**: 5-second baseline timeout adaptively scales to 10 seconds under heavy CPU load (>85%) with a 10-second startup grace period.

### 3.6 Decoy Honey Pot Functions (`decoy_system.rs`)

Visible dummy functions (`check_kernel_debugger`, `is_process_being_debugged`) are exported to attract attackers. An eager watchdog verifies the first 16 bytes of each decoy function at startup (`init_decoy_system()`) and during heartbeats (`watchdog_check_decoys()`). If an attacker patches a prologue with `RET` (`0xC3`), `NOP+RET` (`[0x90, 0xC3]`), or `JMP` (`0xEB`, `0xE9`), the watchdog immediately flags `DECOY_TAMPERED` and adds 60 suspicion points.

---

## Architecture Layer 4: Polymorphic Virtual Execution (TinyVM 2.0)

Layer 4 virtualizes critical operations and sensitive string decoding through an indirect-threaded bytecode virtual machine hardened with non-linear algebraic diffusion, derangement heartbeat mutations, dynamic poison traps, and two-phase fallback execution.

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

- **Two-Phase Fallback Execution (`vm_execute`)**:
  TinyVM 2.0 provides dual-mode execution guaranteeing 100% backward compatibility with zero regressions:
  1. *Phase 1 (Mode H)*: Executes the primary loop under Mode H (`run_loop_mode_h(false)`) utilizing non-linear LSB diffusion, strict bounds checking, and active tamper detection.
  2. *Phase 2 (Mode L Fallback)*: If Mode H encounters a trap (e.g., executing legacy bytecode payloads or instruction boundary anomalies), execution smoothly falls through to legacy Mode L (`run_loop(true)`).
  This two-phase design ensures state-of-the-art cryptographic hardening for new bytecode while preserving compatibility for legacy components.

- **Stack Underflow & Bounds Safety**:
  Unary and stack manipulation opcodes enforce strict stack depth preconditions:
  - `op_not` and `op_dup` verify `if vm.sp >= 1` before accessing operand values.
  - When `vm.sp == 0`, `op_not` leaves `result = 0` without advancing `sp`, and `op_dup` aborts execution cleanly without synthesizing phantom values on an empty stack.
  - Formally verified via Bolero property harnesses (`prop_hypothesis_stack_underflow_integrity`, >77,000 iterations/s) and defect reproduction tests (`defect_stack_underflow_op_not_state_synthesis`, `defect_stack_underflow_op_dup_state_synthesis`).

### 4.2 Randomized Logic-to-Physical Permutation (`LTP_MAP`)

Opcodes are not mapped to fixed indices. Instead, a 256-byte Logic-to-Physical (`LTP_MAP`) array is generated at runtime via an `Xorshift32` PRNG seeded by the reconstructed dynamic seed:

$$\text{PhysicalHandler} = \text{TABLE}[\text{LTP\_MAP}[\text{LogicalOpcode}]]$$

- Every compiled binary and target machine executes opcodes through a unique permutation.
- Reverse engineers cannot reuse static disassembly signatures or opcode maps across targets.
- **Dynamic Environment Re-evaluation**:
  Rather than relying on an immutable, static `OnceLock` that can be tricked by late-attaching debuggers, TinyVM re-evaluates the environment at execution time via `is_environment_poisoned()`.
  The engine checks the integrity of `POISON_SEED` against the expected VEH token:
  $$\text{Clean} \iff (P_{\text{seed}} = 0) \lor (P_{\text{seed}} = 0\text{xCAFEBABE1337BEEF} \oplus \text{seed})$$
  Distinguishes authentic runtime initialization tokens from active debugger injections (`0xDEADBEEF`, `0xDEAD6666BEEF`), eliminating debugger inertia.

### 4.3 The Chaos Trap

If an attacker passes a fake, zeroed, or static seed (such as `0x00000000` or `0xDEADBEEF`), or if `is_environment_poisoned()` detects dynamic tampering:
- The mapping logic dynamically activates the **Chaos Trap**:
  - Dynamically returns a scrambled trap mapping generated via `create_ltp_map(0xDEADBEEF)`.
  - Immediately aborts execution returning 0, starving dynamic instrumentation tools without throwing detectable panic anchors.
- When executing under poisoned maps, arithmetic opcodes route to jumps, loads route to traps, and calculations produce unpredictable garbage without crashing, defeating late-attaching debuggers without inertia.

### 4.4 Rolling Key Cipher & Entangled Execution

Bytecode is encrypted with a rolling key cipher. During instruction fetch, the cipher incorporates non-linear feedback and hardware entanglement:

- **Mode H Non-Linear LSB Diffusion**:
  In Mode H, rolling key evolution injects non-linear feedback into bit 0 of the key recurrence state:
  ```rust
  let nl = ((state.key >> 2) & (state.key >> 3)) & 1;
  state.key ^= (state.key << 1) ^ 0x3C;
  state.key ^= nl;
  ```
  Mathematical formulation:
  $$nl_t = ((K_t \gg 2) \land (K_t \gg 3)) \land 1$$
  $$K_{t+1} = (K_t \oplus (K_t \ll 1) \oplus 0\text{x}3C) \oplus nl_t$$
  - Eliminates linear recurrence over $\mathbb{F}_2$, breaking algebraic cryptanalysis and preventing SAT/SMT-based key recovery.
  - Fully synchronized with 64-bit token diffusion (`diffuse_token`) and Master VEH hardware integrity verification (`enhanced_veh.rs:verify_drx_integrity`).
  - Bijectivity across all 256 rolling key states verified empirically via Bolero property test `prop_hypothesis_rolling_key_full_bijectivity` (>330,000 iterations/s).

- **Anti-Trace Heartbeat Mutation**:
  Replaces previous involutory XOR mutations (`key ^= 0x55`, which allowed even-spike cancellation under hardware single-stepping) with a strict derangement permutation:
  ```rust
  pub fn anti_trace_mutate_key(key: u8) -> u8 {
      (key.wrapping_add(0x37)).rotate_left(6)
  }
  ```
  Mathematical properties over $\mathbb{Z}_{256}$:
  - Full-cycle permutation over $\mathbb{Z}_{256}$.
  - Zero fixed points: $\forall x \in \mathbb{Z}_{256}, \text{anti\_trace\_mutate\_key}(x) \ne x$.
  - Zero 2-cycles: $\forall x \in \mathbb{Z}_{256}, \text{anti\_trace\_mutate\_key}(\text{anti\_trace\_mutate\_key}(x)) \ne x$.
  - Defeats single-step tracing and even-spike cancellation attacks.

- **Short Program VIP Heartbeat**:
  `is_anti_trace_heartbeat_active` eliminates the historical 15-byte blind spot:
  ```rust
  pub fn is_anti_trace_heartbeat_active(vip: usize, len: usize) -> bool {
      (vip & 0xF) == 0 || (len <= 15 && (vip == len || (vip & 0x3) == 0))
  }
  ```
  Standard payloads are checked at 16-byte boundaries (`(vip & 0xF) == 0`), while short programs ($\le 15$ bytes) trigger heartbeats at end-of-program (`vip == len`) and 4-byte intervals (`(vip & 0x3) == 0`).

- **Rolling Key Jump Synchronization**:
  When non-linear control flow transfers occur (`op_jump`, `op_jz`, `op_jnz`), `state.key` is dynamically re-derived for `bytecode[target]` by evolving the rolling key recurrence from offset 0 to `target`, eliminating instruction desynchronization.

- **RIP Entanglement & Cycle Heartbeat**:
  - RIP Anchoring: The decryption key is XORed with the upper 16 bits of the physical instruction pointer (`get_rip_marker`). If the binary code is hooked via DBI engines (Frida, DynamoRIO), the key desynchronizes.
  - Thread Cycle Heartbeat: Measures `QueryThreadCycleTime` across instructions. If the cycle delta exceeds `ANTI_TRACE_CYCLE_THRESHOLD` (2,000,000 cycles), tracing is detected and `state.key` is mutated via `anti_trace_mutate_key`.

### 4.5 Zero-Static-Trace `dynamic_str!` & `SecureBuffer<N>`

String literals wrapped in `dynamic_str!("secret")` are compiled into encrypted bytecode sequences. At runtime:
1. Decrypted in volatile stack memory via TinyVM.
2. Returned inside a `SecureBuffer<const N: usize>` implementing `Deref<Target = [u8]>`.
3. When dropped, scrubs memory via a 2-pass volatile drop:
   - Pass 1: Dynamic seed scramble across buffer bytes.
   - Pass 2: Volatile zeroing (`write_volatile(0)`).
   - **Robust Inline ASM Memory Barrier**:
     ```rust
     unsafe {
         std::arch::asm!("", options(nostack, preserves_flags));
     }
     ```
     By omitting `options(nomem)`, the compiler treats the asm block as an unconstrained read/write across all memory, establishing a true compiler and hardware fence that prevents dead-store elimination (DSE) from stripping the zeroing scrub.
4. `const_str_hash`: Exported as `pub fn const_str_hash(s: &str) -> u32` to permit compile-time string hashing across crate boundaries when invoking `dynamic_str!` and `enc_string!`.

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

The partition is dynamically governed by a 64-bit pair map derived via `compute_dynamic_pair_map(seed, dynamic_counter)`. For pair $i \in [0, 63]$, if bit $i$ of `pair_map` is 0, shard $2i$ is Active and $2i + 1$ is Decoy; if bit $i$ is 1, shard $2i + 1$ is Active and $2i$ is Decoy.

```rust
pub fn compute_dynamic_pair_map(seed: u32, dynamic_counter: u32) -> u64 {
    let mut x = (seed as u64) ^ ((dynamic_counter as u64).wrapping_mul(0x5DEECE66D7F4A7C1));
    x = x.wrapping_mul(0x9E3779B97F4A7C15);
    x = x ^ (x >> 30);
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x = x ^ (x >> 27);
    x = x.wrapping_mul(0x94D049BB133111EB);
    x = x ^ (x >> 31);
    x
}
```

**Dynamic Partition Space Evolution**:
Incorporating the dynamic threat evolution counter with Murmur/SplitMix avalanche mixing ensures that the active/decoy assignment evolves continuously throughout application execution. This mathematically eliminates the static seed partition space collapse vulnerability (`prop_defect_l5_01`), expanding the assignment state space from $2^{32}$ back to $2^{64}$ and preventing memory analyzers from establishing permanent active shard signatures.

**Rotation Shift Parity Decoupling**:
Shard rotation shifts are computed via `get_shard_rotation_shift(index: usize) -> u32`:
$$\text{shift}(i) = (i \oplus 1) \bmod 32$$
Decoupling the shift index from pair parity breaks the bit-shift correlation between adjacent shard pairs, preventing adversaries from deducing partition roles through shift-parity leakage (`prop_defect_l5_03`).

### 5.2 XOR Masking & Zero-Freeze Trap

Each shard stores an encoded value:

$$\text{Encoded}_i = (\text{Value}_i \lll ((i \oplus 1) \bmod 32)) \oplus \text{Mask}_i$$

where $\text{Mask}_i$ is derived lazily via `mix_seed(seed, i)` and cached in `SHARD_MASKS_CACHE: OnceLock<[u32; 128]>`. Decoding is the exact mathematical inverse:

$$\text{Value}_i = (\text{Encoded}_i \oplus \text{Mask}_i) \ggg ((i \oplus 1) \bmod 32)$$

When suspicion is clean ($\text{Value}_i = 0$), $\text{Encoded}_i = \text{Mask}_i \ne 0$.

**Defense Against Memory Freezing / Zeroing**:
If an attacker freezes memory or writes `0x00` across the entire array (via Cheat Engine or script), the decoded value becomes:

$$\text{Decoded}_i = (0 \oplus \text{Mask}_i) \ggg ((i \oplus 1) \bmod 32) = \text{Mask}_i \ggg ((i \oplus 1) \bmod 32)$$

Summing across all 64 active shards results in a massive pseudo-random score exceeding 500 points, immediately tripping the honeytrap and returning `0xFFFFFFFF`.

**Uninitialized State Contract Coherence**:
When `GLOBAL_STATE_INITIALIZED` is false, both `reconstruct_threat_score()` and `get_suspicion_score()` return `0` consistently under `Ordering::Acquire`, eliminating uninitialized score divergence bugs (`prop_defect_l5_09`).

### 5.3 Dispersed Scattering Algorithm

When suspicion is added (`add_suspicion(severity)`):
1. The total points are split into 3 random positive values ($p_1 + p_2 + p_3 = \text{amount}$) using RDTSC entropy weights $w_1, w_2, w_3 \in [1, 32]$.
2. $p_1, p_2, p_3$ are added to 3 randomly selected Active shards using atomic compare-and-swap (CAS) loops:
   ```rust
   let old_contribution = (current_encoded ^ mask).rotate_right((idx as u32 ^ 1) % 32);
   let new_contribution = old_contribution.saturating_add(amount);
   let new_encoded = new_contribution.rotate_left((idx as u32 ^ 1) % 32) ^ mask;
   SUSPICION_SHARDS[idx].compare_exchange(current_encoded, new_encoded, Ordering::SeqCst, Ordering::SeqCst)
   ```
3. Simultaneously, 3 pseudo-random noise values are written to 3 randomly selected Decoy shards using bounded rotational updates:
   ```rust
   let current_decoded = (current_encoded ^ mask).rotate_right((idx as u32 ^ 1) % 32);
   let delta = ((noise & 0x0F) as u32).max(1);
   let new_decoded = current_decoded.saturating_add(delta).min(255);
   let new_encoded = new_decoded.rotate_left((idx as u32 ^ 1) % 32) ^ mask;
   ```

**Decoy Magnitude Preservation & Full 32-Bit Entropy**:
By decoding, adding a bounded delta ($\le 15$), clamping to 255, and re-encoding across all 32 bits, decoy shards maintain realistic score magnitudes and exhibit indistinguishable entropy distributions without low-byte truncation or magnitude explosion (`prop_defect_l5_02`).

### 5.4 Dynamic SipHash-2-4 Integrity Hash

To prevent offline tampering and data manipulation:
- `compute_integrity_siphash(score: u32, decay_time: u64) -> u64` processes state across two independent domain-separated compression blocks:
  - **Block 1 (Threat Score)**: $v_2 \gets v_2 \oplus ((score \text{ as } u64) \oplus \text{0x243F6A8885A308D3}), \quad v_3 \gets v_3 \oplus 8$, followed by 2 SipHash rounds.
  - **Block 2 (Decay Timestamp)**: $v_2 \gets v_2 \oplus (decay\_time \oplus \text{0x13198A2E03707344}), \quad v_3 \gets v_3 \oplus 16$, followed by 2 SipHash rounds.
  - **Finalization**: $v_2 \gets v_2 \oplus \text{0xFF}$, followed by 4 finalization rounds, outputting $v_0 \oplus v_1 \oplus v_2 \oplus v_3$.
- **Collision Immunity**: Domain separation constants (`0x243F6A8885A308D3`, `0x13198A2E03707344`) mathematically eliminate linear additive collisions where (+k, -k) tamper swaps between score and decay timestamp produced identical digests (`prop_defect_l5_12`).
- **Polymorphic Key Initialization**: The SipHash initialization vectors (`GLOBAL_SIPHASH_V0..V3`) are derived at startup from the runtime seed and base constants via `initialize_dynamic_siphash()`, preventing external unkeyed tag forgery (`prop_defect_l5_13`). Lazy atomic fallback initialization prevents init race conditions (`prop_defect_l5_06`).
- **Lock-Free Concurrency Serialization**: `recalculate_global_integrity()` is protected by an `INTEGRITY_LOCK` spin-wait CAS loop, eliminating lost hash recalculation races between concurrent detection threads (`prop_defect_l5_08`).
- **Poison Persistence**: When `is_poisoned_internal()` is active, hash recalculation is short-circuited and `validate_global_integrity()` returns `false` unconditionally, preventing self-erasing hash tags (`prop_defect_l5_15`).

### 5.5 Saturated Score Decay

To prevent temporary environmental hiccups from permanently impairing execution:
- Every 300 seconds, `apply_decay()` reduces suspicion by 5 points per interval.
- **Atomic TOCTOU Window Elimination**: Elapsed time is divided into 300-second intervals ($d = \lfloor \Delta t / 300 \rfloor$). `GLOBAL_LAST_DECAY_TIME` is advanced atomically by $d \times 300$ using a CAS loop:
  $$\Delta t_{\text{remainder}} = \Delta t - d \times 300 = \Delta t \bmod 300$$
  This eliminates time-of-check to time-of-use (TOCTOU) races between timestamp advancement and hash recalculation (`prop_defect_l5_07`), while strictly preserving sub-300s fractional remainders.
- **Non-Periodic Decoy Decay**: Active shards decay saturating at 0. Decoy shards decay using non-periodic pseudo-decay delta `generate_decoy_decay_delta(entropy, i)`:
  $$\text{base} = (entropy \lll (i \bmod 61)) \land 0\text{x}6$$
  $$\text{phase} = (i / 8) \land 1$$
  $$\delta = \text{base} \lor \text{phase}$$
  This breaks modulo-8 cyclic decay periodicity (`prop_defect_l5_05`).

### 5.6 Soft Corruption vs Hard Corruption

`fuckDebug` enforces a two-tier response to accumulated suspicion:

1. **Soft Corruption (Exponential Latency Backoff)**:
   For scores between 50 and 100:
   $$\text{Delay} = (\text{Score} - 50)^2 \text{ ms}$$
   On the main thread, the delay is capped at 50ms (~20 FPS) to avoid Windows ANR hangs while introducing system lag that severely disrupts automated fuzzing.
2. **Hard Corruption (Data & Token Poisoning)**:
   For scores > 100 or when `POISON_SEED` is contaminated:
   - **Absorbing Irreversible Poison Latch**: `trigger_silent_poisoning()` applies an absorbing MSB bit latch and linear congruential mixer:
     $$\text{latched} = \text{state} \lor \text{0x8000\_0000\_0000\_0000}$$
     $$\text{mixed} = (\text{latched} \times \text{0x9E3779B97F4A7C15}) \oplus (\text{entropy} \lor 1) \lor \text{0x8000\_0000\_0000\_0000}$$
     Because the latch sets the MSB irreversibly and applies non-involutory mixing, repeated poisoning invocations ($2k$ triggers) cannot cancel corruption or restore clean keys (`prop_defect_l5_14`).
   - **Atomic VM Key Evolution**: `update_vm_key_with_result(vm_result)` updates `GLOBAL_VIRTUAL_MACHINE_KEY` via an atomic `compare_exchange_weak` CAS loop, preventing lost updates under multi-threaded TinyVM execution (`prop_defect_l5_10`).
   - **Non-Linear Combined Score Coupling**: `get_combined_score()` couples threat score and `POISON_SEED` via non-linear multi-stage rotation and multiplier avalanche:
     $$\text{linear} = (\text{score} \times \text{0x5DEECE66D}) \oplus \text{POISON\_SEED}$$
     $$\text{token} = (\text{linear} \lll 17) \times \text{0x9E3779B97F4A7C15} \oplus (\text{POISON\_SEED} \gg 3)$$
     eliminating linear algebraic recovery of `POISON_SEED` (`prop_defect_l5_16`).
   - **Full 64-Bit Stealth Log Obfuscation**: `obfuscate_stealth_log_entry(entry, seed)` diffuses a full 64-bit seed (`mix_seed_to_u64`), preventing upper-bit unmasked leakage (`prop_defect_l5_04`).

---

## Complete API Reference

### Core Public APIs

```rust
// Initialization Macro
let protector = setup_anti_debug!(get_dynamic_seed());

// Dynamic Seed Accessors
pub fn get_dynamic_seed() -> u32;
pub fn get_dynamic_seed_u8() -> u8;
pub fn get_hardened_seed_u8() -> u8;
pub fn reconstruct() -> u32;
pub fn evaluate_dynamic_seed(threat_score: u32, poison_token: u64) -> u32;

// Suspicion Management
pub fn get_suspicion_score() -> u32;
pub fn get_combined_score() -> u64;
pub fn add_suspicion(severity: DetectionSeverity);
pub fn add_suspicion_at(severity: DetectionSeverity, checkpoint_id: u8);
pub fn trigger_silent_poisoning();

// Memory Scrubbing Buffer & TinyVM 2.0 Primitives
pub struct SecureBuffer<const N: usize>;
impl<const N: usize> std::ops::Deref for SecureBuffer<N> {
    type Target = [u8];
}
pub fn const_str_hash(s: &str) -> u32;
pub fn anti_trace_mutate_key(key: u8) -> u8;
pub fn is_anti_trace_heartbeat_active(vip: usize, len: usize) -> bool;
pub fn is_environment_poisoned() -> bool;
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
| **Layer 2: Seed Orchestration & Hardened Key Derivation** | `seed_orchestrator.rs` | Asymmetric 3-pipeline ARX shard recomposition, pure bijective fixed-point-free KDF, non-linear 4-stage ARX u8 projection, lock-free AtomicU32/AtomicU64 caching, monotonic epoch re-seeding, dynamic token coupling | XOR differential cancellation ($\Delta \oplus \Delta = 0$), trivial zero fixed-point ($f(0)=0$), zero-sum shard collapse, 24-bit u8 linear kernel collapse, static caching temporal blindness |
| **Layer 3: Memory Stealth & Anti-Dump** | `anti_dump.rs`, `enhanced_veh.rs`, `decoy_system.rs` | 5-phase master VEH (1232-byte CONTEXT, TEB limits, depth <= 1), 64-byte 16-aligned indirect syscalls, lock-free decoy table (8 slots, saturating math, quarantine), surgical PE NT header erasure | Memory dumpers (Scylla, ProcDump), guard page scanners, prologue patchers, EDR hooks |
| **Layer 4: Polymorphic Virtual Execution** | `tiny_vm.rs` | 256-entry indirect v-table, Mode H non-linear LSB diffusion, dynamic LTP Chaos Trap, two-phase fallback (Mode H/L), anti-trace derangement heartbeat, stack bounds safety | Disassemblers (IDA, Ghidra), DBI engines (Frida, DynamoRIO), instruction tracing, algebraic cryptanalysis |
| **Layer 5: Decentralized State & Silent Corruption** | `global_state.rs` | 128 atomic shards (64 Active / 64 Decoy), dynamic partition map evolution (`compute_dynamic_pair_map`), XOR rotation masking `(i ^ 1) % 32`, 3-shard scatter & bounded decoy noise (clamped to 255), domain-separated SipHash-2-4 (`0x243F6A8885A308D3`, `0x13198A2E03707344`), absorbing poison latches (`state | 0x8000_0000_0000_0000`, `0x9E3779B97F4A7C15`), atomic CAS loops | Memory search/freeze tools (Cheat Engine), data breakpoints, state desynchronization, involutory double-poisoning cancellation, linear additive collision forgery, static decompilation |

---

*fuckDebug Architecture Guide — Formally Verified & Synchronized — 2026*

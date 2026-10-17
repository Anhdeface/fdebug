![img](https://i.pinimg.com/originals/c9/16/d9/c916d9fc9dd8b168666baea645f54234.gif)
# fuckDebug — Advanced Anti-Debug & Integrity Protection System

[![Version](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2FAnhdeface%2Ffdebug%2Fmain%2FCargo.toml&query=%24.package.version&label=version&color=blue&prefix=v)](Cargo.toml)
[![Crates.io](https://img.shields.io/crates/v/fuckDebug.svg)](https://crates.io/crates/fuckDebug)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A sophisticated, multi-layered anti-debugging, memory stealth, and polymorphic execution protection engine for Rust applications on Windows x86-64. `fuckDebug` detects debugging and analysis attempts and silently poisons sensitive cryptographic computations, making reverse engineering economically intractable.

---

## Core Philosophy

Rather than halting with a crash or exception when a debugger is detected (which provides attackers an immediate, reproducible patch anchor), **`fuckDebug` silently corrupts internal transformation keys and global state**. The protected application continues executing normally, but produces subtly and plausibly incorrect results — turning dynamic analysis into an endless search for phantom bugs with no visible root cause.

```
Traditional Anti-Debug:   Debugger detected → Crash / ExitProcess → Trivial NOP/JMP patch
                        
fuckDebug Architecture:   Debugger detected → Silent Key Poisoning → 
                          Calculations produce plausible phantom outputs → 
                          Reverse engineering costs become economically prohibitive
```

### [UPDATE] Latest Architecture & Hardening
- **Silent Poisoning (Watchdog v2)**: Process termination is replaced with silent data poisoning. If thread suspension is detected (via a debugger pause), the system corrupts internal cryptographic keys and poison seeds instead of killing the process.
- **Adaptive Sensitivity & Hypervisor Tolerance**: 5-second baseline threshold with heavy-load awareness (doubles timeout to 10s during high CPU usage). Hyper-V, VBS, and WSL2 environments are recognized via dynamic `"Microsoft Hv"` decoding and given a stable 60 suspicion score (well below the 100-point poisoning threshold).
- **Entangled Execution (Anti-DBI / Anti-Trace)**: The TinyVM 2.0 execution loop is entangled with code location (RIP marker) and thread execution timing (`QueryThreadCycleTime` with a 2,000,000 cycle preemption threshold), silently corrupting state if code is relocated or single-stepped.
- **Surgical Anti-Dump**: PE NT headers (`AddressOfEntryPoint`, NT signature, debug directories) are erased with `KUSER_SHARED_DATA` random entropy while DOS and section headers are preserved for OS and CRT loader stability.
- **Formally Verified**: Backed by **30 Verus deductive mathematical theorems** (Z3 SMT solver) and **47 Bolero property-based fuzzing harnesses** with 100% verification pass rate across 125 tests.

---

## Key Features

| Feature | Implementation | Security Effect |
|---|---|---|
| **Multi-Vector Detection** | PEB dereference, RDTSC timing baseline, DR0–DR7 checks, driver blacklists | Detects debugging attempts across multiple hardware and OS vectors simultaneously |
| **Watchdog v2 (Liveness)** | KUSER_SHARED_DATA InterruptTime + Adaptive Thresholding | Detects thread suspension; triggers **Silent Poisoning** instead of exit |
| **Entangled Execution** | RIP Anchoring + Thread Cycle Heartbeat (2M threshold) | Binds VM decryption key to physical code location and timing; defeats DBI and tracing |
| **Randomized TinyVM 2.0** | 256-Entry Indirect V-Table + Randomized LTP Permutation | No switch/match statements; opcode handler addresses shuffled at runtime via Xorshift32 |
| **128-Shard Suspicion State** | Distributed Atomic State (64 Active / 64 Decoy) | Defeats memory freezing and data breakpoints; zeroing memory causes immediate score spike |
| **Silent Key Poisoning** | Token-based non-linear key poisoning | No crashes; execution continues with poisoned cryptographic material |
| **Surgical Anti-Dump** | Selective NT Header Obfuscation + 56-Byte Indirect Syscalls | Wipes NT signatures to defeat dumpers while maintaining OS/CRT loader stability |
| **Master VEH 5-Phase Dispatch** | Preemptive Vectored Exception Handler with Call Frame Synthesis | Catches INT3, single-step, and guard page traps; redirects execution via valid x64 ABI frames |
| **Formal Mathematical Proofs** | 30 Verus SMT theorems + 47 Bolero property-based harnesses | Formally proves memory safety, stack bounds, and golden ratio key bijection |

---

## Quick Start

### Installation

The canonical Cargo package and library name is **`fuckDebug`**:

```toml
# Cargo.toml
[dependencies]
fuckDebug = { path = "./fuckDebug" }
```

> **Package Aliasing Note**: If your codebase prefers referencing the crate as `fdebug`, Cargo supports first-class package aliasing:
> ```toml
> [dependencies]
> fdebug = { package = "fuckDebug", path = "./fuckDebug" }
> ```

### Basic Usage

The standard way to initialize the protection engine is via the `setup_anti_debug!` macro paired with `get_dynamic_seed()`:

```rust
use fuckDebug::protector::{setup_anti_debug, get_dynamic_seed, SecureVault, ShieldedExecution};

fn main() {
    // 1. Reconstruct dynamic seed from hardware and PE state, then initialize
    let seed = get_dynamic_seed();
    let protector = setup_anti_debug!(seed);
    println!("[+] fuckDebug protection initialized. Seed: 0x{:08X}", seed);
    
    // 2. Protect sensitive credentials in a SecureVault
    let api_key = SecureVault::new("sk_live_secret_production_token".to_string());
    
    // 3. Access vaulted data through shielded execution
    let is_valid = protector.run_secure(&api_key, |key, token| {
        // 'token' is valid ONLY in an uncorrupted, debugger-free environment
        key.len() > 10 && (token % 7) == 0
    });
    
    if is_valid {
        println!("[+] Protected operation executed cleanly");
    } else {
        eprintln!("[-] Running under debugger or modified environment - data poisoned");
    }
}
```

### Coupled Business Logic Pattern

```rust
use fuckDebug::protector::{setup_anti_debug, get_dynamic_seed, CoupledLogic, Corruptible};

#[derive(Clone, Debug)]
struct PaymentData {
    amount: f64,
    valid: bool,
}

impl Corruptible for PaymentData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        if token == 0 || token.count_ones() > 16 {
            self.amount = 0.0;
            self.valid = false;
        }
        self
    }
}

fn process_payment() -> PaymentData {
    let protector = setup_anti_debug!(get_dynamic_seed());
    
    protector.run_coupled(|token| {
        PaymentData {
            amount: 1000.0 + (token as f64 * 0.001),
            valid: token != 0,
        }
    })
}

// In clean environment: amount ≈ 1000.0, valid = true
// Under debugger: amount = 0.0, valid = false (silent corruption)
```

---

## Documentation Index

Authoritative, detailed documentation is located in the [`docs/`](docs/) directory:

- 📖 **[Master Guide — Complete Integration Manual](docs/FDEBUG_COMPLETE_GUIDE.md)**: Exhaustive manual detailing all architecture layers, complete API signatures, design patterns, verification guides, and the defect remediation ledger. **Start here.**
- 📐 **[Technical Architecture Guide](docs/architecture_guide_NEW.md)**: Deep technical analysis of the Five-Layer Concentric Defense Model, 128-shard active/decoy partition, and TinyVM 2.0 indirect threading.
- ⚙️ **[API Reference Guide](docs/reference_guide_NEW.md)**: Full API documentation, function signatures, `SecureBuffer<N>` methods, and severity levels.
- 🛠️ **[Implementation & Design Patterns Guide](docs/implementation_guide_NEW.md)**: Production implementation patterns (Shield, Sentinel, Checksum) and real-world licensing/credential use cases.
- 🏗️ **[Build System & Entropy Customization Guide](docs/BUILD_GUIDE.md)**: Detailed analysis of `build.rs` compile-time seed generation and customization patterns.
- 🔒 **[Seed Orchestrator Specification](docs/ARCHITECTURE_LAYER5.md)**: Technical specification of the three-shard runtime entropy reconstruction and MurmurHash3 finalizer.
- 📝 **[Updates & Technical Changelog](docs/UPDATES.md)**: Chronological record of architectural enhancements, Watchdog v2, and the 17 remediated security defects.

---

## Five-Layer Concentric Architecture

```
Application Layer
    │ (uses run_secure, run_coupled, SecureVault, dynamic_str!)
    ▼
Protection Engine
    ├─→ Layer 5: Decentralized State & Silent Corruption
    │     128 Atomic Shards (64 Active / 64 Decoy), Dynamic SipHash-2-4,
    │     Dispersed Scattering, Soft Backoff Latency, Token Key Mutation
    │
    ├─→ Layer 4: Polymorphic Virtual Execution (TinyVM 2.0)
    │     256-Entry Indirect V-Table, Randomized LTP Permutation Map,
    │     Rolling Key Cipher, RIP Entanglement, Cycle Heartbeat (2M threshold)
    │
    ├─→ Layer 3: Memory Stealth, Master VEH & Anti-Dump
    │     5-Phase Master Vectored Exception Handler, Synthetic x64 ABI Frames,
    │     Surgical NT Header Erasure, 56-Byte Indirect Syscalls, Guard Page Traps
    │
    ├─→ Layer 2: Seed Orchestration & MurmurHash3 Key Derivation
    │     Dynamic Seed Reconstruction: Avalanche(BUILD ^ HW ^ PE),
    │     Thread-Safe OnceLock Caching, Golden Ratio Modular Inverse Invariance
    │
    └─→ Layer 1: Foundational Entropy & Detection Entanglement
          Shard 1 (Build Seed), Shard 2 (CPUID Fingerprint), Shard 3 (PE Checksum),
          PEB Dereference, Hardware Debug Registers (Dr0-Dr7), RDTSC Baseline, TLS
```

### 128-Shard Active/Decoy State (`global_state.rs`)
Rather than relying on a centralized boolean flag (which can be easily modified with a single debugger breakpoint or memory write), suspicion is distributed across **128 atomic shards** (`AtomicU32`):
- **64 Active Shards**: Contain real suspicion scores.
- **64 Decoy Shards**: Contain high-entropy decoy noise mimicking real detections.
- **Pair-Based Partitioning**: Shards are partitioned into 64 pairs `(2*i, 2*i+1)`. A 64-bit pair map derived from the dynamic seed designates which shard in each pair is Active.
- **XOR Masking**: Each shard stores `(Score.rotate_left(i % 32)) ^ Mask_i`. Zeroing memory results in `0 ^ Mask = Mask`, generating an immediate score spike exceeding 500 points that trips the `0xFFFFFFFF` honeytrap.
- **Dispersed Scattering**: Detections split suspicion points across 3 random active shards (`p1 + p2 + p3 = amount`) while injecting noise into 3 random decoy shards.

---

## Formal Verification & Testing Suite

`fuckDebug` incorporates a comprehensive formal verification suite located in `verification_suite/` combining deductive SMT proofs and property-based fuzzing.

### Verification Scorecard

| Suite / Harness Category | Total Tests | Pass Rate | Status |
|---|---|---|---|
| **Total Automated Tests** | **125** | **100% (125/125 Passed)** | **CLEAN** |
| **Library & Bolero Property Harnesses** | 74 | 100% Passed | **CLEAN** |
| **M1 Mathematical Invariant Challenges** | 17 | 100% Passed | **CLEAN** |
| **M2 Empirical Challenge Harnesses** | 27 | 100% Passed | **CLEAN** |
| **Module Concurrency & Shim Stress Tests** | 7 | 100% Passed | **CLEAN** |
| **Defect Proofs Suite (`defect_proofs.rs`)** | 16 | 100% Passed | **CLEAN** |
| **Verus Deductive SMT Theorems** | **30 + 2** | **100% (0 Admits)** | **DISCHARGED** |

### Running the Verification Suite

#### Via PowerShell (Authoritative Runner):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "verification_suite\run_verification.ps1"
```

#### Via Windows Batch File:
```cmd
verification_suite\run_verification.bat
```

#### Via Cargo Directly:
```cmd
# Run all 125 verification tests:
cargo test --manifest-path verification_suite/Cargo.toml -- --nocapture

# Run the 16 defect proofs:
cargo test --manifest-path verification_suite/Cargo.toml --test defect_proofs -- --nocapture

# Run crate unit tests:
cargo test --lib
```

---

## Security Audit & Remediated Defects Ledger

During the Milestone 1 audit and Milestone 2 remediation phases, 17 cataloged architectural, memory-safety, and logic defects (`FLAW-01` through `FLAW-17`) were proven via formal Verus/Bolero defect tests and genuinely remediated:

- **FLAW-01 (TEB/PEB Dereference)**: Fixed inline assembly immediate folding `gs:[0x60 + 0x02]` to two-stage dereference loading `gs:[0x60]` into scratch register before reading `BeingDebugged` and `NtGlobalFlag`.
- **FLAW-02 (DJB2/SipHash Divergence)**: Replaced mismatched 64-bit SipHash constant with `GOLDEN_MARKER_HASH` baseline, eliminating 100% false-positive tampering alarms.
- **FLAW-03 (Environment Variable Bypass)**: Removed environment variable inspections (`RUSTUP_HOME`, `CARGO_MANIFEST_DIR`); check strictly governed by `cfg!(debug_assertions)`.
- **FLAW-04 (Master VEH Guard Page Intercept)**: Updated VEH Phase 1 entry filter to intercept `STATUS_GUARD_PAGE_VIOLATION` regardless of address, routing heap guard page honeytraps.
- **FLAW-05 (KUSER Watchdog Timestamp)**: Harmonized KUSER time source and implemented paired aligned 32-bit reads to eliminate unaligned 64-bit pointer panics.
- **FLAW-06 (TinyVM Rolling Key Desynchronization)**: Removed mid-stream token mutation at `vip == 3`, preserving mathematical rolling key synchronization.
- **FLAW-07 (Decoy Lazy Registration)**: Added eager `init_decoy_system()` during startup to reject pre-patched function hooks.
- **FLAW-08 (Anti-Dump / PE Initialization Order)**: Preserved NT signature in header erasure and added eager `init_shard_table()` in `init_anti_dump()`.
- **FLAW-09 (Indirect Syscall Stack Frame)**: Increased stack frame allocation to 56 bytes (`sub rsp, 0x38`), proven by Verus theorem `theorem_flaw09_syscall_stack_safety`.
- **FLAW-10 (VEH Redirection Call Stack ABI)**: Synthesized authentic Windows x64 call frames (16-byte minus 8 RSP alignment, `safe_exit_stub` return address, 32-byte shadow space).
- **FLAW-11 (Driver Buffer Slice Clamping)**: Clamped slice bounds with `(len as usize).min(buffer.len())` to prevent buffer overflow panics.
- **FLAW-12 (Kernel Snapshot Handle Leak)**: Wrapped process snapshot handle in `CloseHandle(snapshot)` across all return paths in `is_terminal_context`.
- **FLAW-13 (TinyVM Anti-Trace Preemption)**: Raised cycle threshold to `ANTI_TRACE_CYCLE_THRESHOLD = 2_000_000` to accommodate legitimate OS thread context switches.
- **FLAW-14 (Dynamic SipHash Globals)**: Converted dead constants to `AtomicU64` and integrated dynamically into `recalculate_global_integrity`.
- **FLAW-15 (Hypervisor Brand String Decoding)**: Corrected `MS_HV_ENCODED` to cleanly decode to `b"Microsoft Hv"`, exempting Windows VBS and WSL2 hosts.
- **FLAW-16 (TinyVM Arithmetic Inversion)**: Resolved upstream false-positive score accumulation causes, verifying authentic arithmetic on clean systems.
- **FLAW-17 (VEH Dead Code Cleanup)**: Removed developer conversational prompt comments and duplicate dead functions.

---

## Module Structure

```
fuckDebug/
├── Cargo.toml                    # Crate definition (name = "fuckDebug")
├── build.rs                      # Build-time random seed generator (Shard 1)
├── src/
│   ├── lib.rs                    # Library root export (pub mod protector)
│   ├── main.rs                   # Entry point demonstration binary
│   └── protector/
│       ├── mod.rs                # Core Protector, SecureVault, CoupledLogic (802 lines)
│       ├── seed_orchestrator.rs  # 3-shard dynamic seed reconstruction (263 lines)
│       ├── hardware_entropy.rs   # CPUID processor fingerprinting (150 lines)
│       ├── pe_integrity.rs       # PE section sharded checksumming (310 lines)
│       ├── anti_debug.rs         # Multi-vector detection sensors (2170 lines)
│       ├── anti_dump.rs          # Surgical header obfuscation & indirect syscalls (450 lines)
│       ├── enhanced_veh.rs       # 5-phase master Vectored Exception Handler (280 lines)
│       ├── global_state.rs       # 128-shard active/decoy state machine (972 lines)
│       ├── tiny_vm.rs            # Indirect-threaded virtual machine 2.0 (1394 lines)
│       └── decoy_system.rs       # Honey pot functions & watchdog prologue scanner (190 lines)
├── verification_suite/           # Standalone Formal Verification Harness
│   ├── Cargo.toml                # Verification crate dependencies (Bolero, Verus)
│   ├── run_verification.ps1      # Authoritative PowerShell verification runner
│   ├── run_verification.bat      # Windows CMD verification wrapper
│   ├── src/
│   │   ├── verus_proofs/         # 30 Verus deductive SMT theorems (Z3 solver)
│   │   ├── bolero_harnesses/     # 47 Bolero property-based fuzzing harnesses
│   │   └── shims/                # Test shims for internal component verification
│   └── tests/
│       ├── defect_proofs.rs      # 16 formal defect proofs for FLAW-01..16
│       ├── m1_math_challenge.rs  # Mathematical boundary challenges
│       ├── m2_bolero_challenge.rs# Empirical fuzzing challenges
│       └── shim_stress.rs        # Multithreaded concurrency stress tests
├── docs/                         # Comprehensive Technical Documentation
│   ├── FDEBUG_COMPLETE_GUIDE.md  # Master integration & verification manual
│   ├── architecture_guide_NEW.md # 5-layer architecture deep dive
│   ├── reference_guide_NEW.md    # Complete API reference guide
│   ├── implementation_guide_NEW.md# Design patterns & use cases
│   ├── BUILD_GUIDE.md            # Build script customization guide
│   ├── ARCHITECTURE_LAYER5.md    # Seed Orchestrator technical specification
│   ├── UPDATES.md                # Technical changelog & remediation ledger
│   └── README_UPDATES.md         # Documentation update summary
└── examples/                     # Working code examples
    ├── basic_protection.rs       # API key protection
    ├── guarded_logic.rs          # Token-based financial calculations
    ├── custom_vm_op.rs           # VM opcode extension guide
    └── stealth_system.rs         # Memory stealth demonstration
```

---

## Threat Model

### Defends Against
- Software debuggers (WinDbg, x64dbg, Visual Studio Debugger, IDA Pro Debugger).
- Automated disassemblers & decompilers (IDA Pro, Ghidra, Binary Ninja).
- Binary patch attacks (modifying `.text` bytes triggers PE checksum invalidation).
- Dynamic binary instrumentation (DBI) frameworks (Frida, DynamoRIO via RIP and cycle entanglement).
- Memory dumpers (Scylla, ProcDump, Dump-It via surgical NT header erasure).
- In-memory state freezing and zeroing (128-shard active/decoy XOR mask trap).
- Single-stepping and timing inspection attacks.
- DLL injection attempts.

### Limitations & Out of Scope
- Kernel-mode debuggers with hardware hypervisor hooks (Ring -1 / Ring 0).
- Physical hardware attacks (Direct Memory Access / DMA hardware sniffers, side-channel analysis).

---

## Quick Navigation

| I want to... | Go to |
|---|---|
| **Read the complete master guide** | [Master Guide](docs/FDEBUG_COMPLETE_GUIDE.md) |
| **Understand the 5-layer architecture** | [Architecture Guide](docs/architecture_guide_NEW.md) |
| **Inspect all API functions & types** | [API Reference Guide](docs/reference_guide_NEW.md) |
| **Implement design patterns & licensing** | [Implementation Guide](docs/implementation_guide_NEW.md) |
| **Customize compile-time build entropy** | [Build Guide](docs/BUILD_GUIDE.md) |
| **Understand dynamic seed reconstruction** | [Seed Orchestrator Spec](docs/ARCHITECTURE_LAYER5.md) |
| **Inspect the 17 remediated flaw proofs** | [Remediation Ledger](docs/UPDATES.md) |
| **Run the formal verification suite** | `verification_suite\run_verification.bat` |
| **See working code examples** | [`examples/`](examples/) directory |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Created by anhdeface aka Julian Kmut. Formally verified & synchronized 2026.

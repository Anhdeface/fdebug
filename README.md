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

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Created by anhdeface aka Julian Kmut. Formally verified & synchronized 2026.

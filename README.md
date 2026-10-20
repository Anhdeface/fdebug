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

---

## Key Features

| Feature | Implementation | Security Effect |
|---|---|---|
| **Multi-Vector Detection** | PEB dereference, RDTSC timing baseline, DR0–DR7 checks, driver blacklists | Detects debugging attempts across multiple hardware and OS vectors simultaneously |
| **Watchdog v2 (Liveness)** | KUSER_SHARED_DATA InterruptTime + Adaptive Thresholding | Detects thread suspension; triggers **Silent Poisoning** instead of exit |
| **Entangled Execution** | RIP Anchoring + Anti-Trace Derangement Heartbeat | Derangement permutation over $\mathbb{Z}_{256}$ eliminates even-spike cancellation; short program VIP heartbeat |
| **Randomized TinyVM 2.0** | 256-Entry Indirect V-Table + Mode H LSB Diffusion + Dynamic LTP Map | No switch/match statements; non-linear $\mathbb{F}_2$ diffusion, two-phase fallback (Mode H/L), and poison-reactive Chaos Trap |
| **128-Shard Suspicion State** | Distributed Atomic State (64 Active / 64 Decoy) | Defeats memory freezing and data breakpoints; zeroing memory causes immediate score spike |
| **Silent Key Poisoning** | Token-based non-linear key poisoning | No crashes; execution continues with poisoned cryptographic material |
| **Surgical Anti-Dump & Memory Stealth** | Lock-Free Decoy Traps (8 Atomic Slots) + 64-Byte 16-Aligned Syscalls | Defeats memory dumpers via CAS registration, PAGE_NOACCESS quarantine, saturating math, and SSN grammar validation |
| **Master VEH 5-Phase Dispatch** | 1232-Byte Win32 CONTEXT ABI + TEB Stack Bounds (gs:[0x08]/0x10) | Enforces frames_walked >= 2, bounded re-entrancy depth <= 1, TF precedence over Dr0 heartbeats, and call frame synthesis |
| **Formal Mathematical Proofs** | 35 Verus SMT theorems + 85 Bolero property harnesses (355+ tests) | 355+ tests workspace-wide across root crate and 25 verification suite test binaries, 100% pass rate |

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
    │     256-Entry Indirect V-Table, Mode H Non-Linear LSB Diffusion, Dynamic LTP Chaos Trap,
    │     Two-Phase Fallback (Mode H/L), Anti-Trace Derangement Heartbeat, Stack Bounds Safety
    │
    ├─→ Layer 3: Memory Stealth, Master VEH & Anti-Dump
    │     5-Phase Master VEH (1232-Byte CONTEXT, TEB Bounds, Re-entrancy <= 1),
    │     Lock-Free Decoy Guard Pages (Saturating Math), 64-Byte 16-Aligned Syscalls
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
│       ├── anti_dump.rs          # Lock-free decoy traps & 16-aligned indirect syscalls (549 lines)
│       ├── enhanced_veh.rs       # 5-phase master VEH with Win32 CONTEXT & re-entrancy bounds (459 lines)
│       ├── global_state.rs       # 128-shard active/decoy state machine (1101 lines)
│       ├── tiny_vm.rs            # Hardened indirect-threaded virtual machine 2.0 (1660 lines)
│       └── decoy_system.rs       # Honey pot functions & watchdog prologue scanner (190 lines)
├── verification_suite/           # Standalone Formal Verification Harness
│   ├── Cargo.toml                # Verification crate dependencies (Bolero, Verus)
│   ├── run_verification.ps1      # Authoritative PowerShell verification runner
│   ├── run_verification.bat      # Windows CMD verification wrapper
│   ├── src/
│   │   ├── verus_proofs/         # 35 Verus deductive SMT theorems (Z3 solver)
│   │   ├── bolero_harnesses/     # 85 Bolero property-based fuzzing harnesses
│   │   └── shims/                # Test shims for internal component verification
│   └── tests/                    # 25 integration test binaries (339+ tests)
│       ├── hypothesis_*.rs       # Layer 3 & 4 hypothesis formal verification suites (5 binaries)
│       ├── defect_layer4_tinyvm.rs# Layer 4 TinyVM 2.0 formal defect verification suite (D1..D7)
│       ├── adversarial_*.rs      # Adversarial challenge suites for Layer 3 invariants (10 binaries)
│       ├── challenger_*.rs       # Layer 1 & 2 adversarial stress challenges (2 binaries)
│       ├── defect_proofs.rs      # Formal defect proofs for historical flaws (FLAW-01..16)
│       ├── m1_math_challenge.rs  # Golden ratio modular inverse & Murmur3 bijectivity
│       ├── m2_bolero_challenge.rs# Empirical fuzzing challenges across all layers
│       ├── repro_defects.rs      # Verified defect reproduction & regression guards
│       └── shim_stress.rs        # Multithreaded concurrency stress & PE integrity
├── docs/                         # Comprehensive Technical Documentation
│   ├── FDEBUG_COMPLETE_GUIDE.md  # Master integration & verification manual
│   ├── architecture_guide_NEW.md # 5-layer architecture deep dive
│   ├── reference_guide_NEW.md    # Complete API reference guide
│   ├── implementation_guide_NEW.md# Design patterns & use cases
│   ├── BUILD_GUIDE.md            # Build script customization guide
│   ├── ARCHITECTURE_LAYER5.md    # Seed Orchestrator technical specification
│   ├── UPDATES.md                # Technical changelog & remediation ledger
│   ├── DOCUMENTATION_UPDATE_SUMMARY.md # Milestone audit & resolution summary
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
- Virtual execution manipulation (algebraic cryptanalysis, VIP tracing, empty stack state synthesis).

### Limitations & Out of Scope
- Kernel-mode debuggers with hardware hypervisor hooks (Ring -1 / Ring 0).
- Physical hardware attacks (Direct Memory Access / DMA hardware sniffers, side-channel analysis).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Created by anhdeface aka Julian Kmut. Formally verified & synchronized 2026.

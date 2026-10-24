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
| **128-Shard Suspicion State** | Distributed Atomic State (64 Active / 64 Decoy) + SipHash-2-4 | Defeats memory freezing and data breakpoints; zeroing memory causes >500 score spike; dynamic partition map & absorbing poison latch |
| **Silent Key Poisoning** | Token-based non-linear key poisoning + Absorbing Poison Latch | No crashes; execution continues with poisoned cryptographic material; irreversible MSB latch prevents cancellation |
| **Surgical Anti-Dump & Memory Stealth** | Lock-Free Decoy Traps (8 Atomic Slots) + 64-Byte 16-Aligned Syscalls | Defeats memory dumpers via CAS registration, PAGE_NOACCESS quarantine, saturating math, and SSN grammar validation |
| **Master VEH 5-Phase Dispatch** | 1232-Byte Win32 CONTEXT ABI + TEB Stack Bounds (gs:[0x08]/0x10) | Enforces frames_walked >= 2, bounded re-entrancy depth <= 1, TF precedence over Dr0 heartbeats, and call frame synthesis |
| **Hardened Key Derivation (Layer 2)** | Asymmetric 3-Pipeline ARX + Pure Bijective KDF + u8 ARX Projection | Breaks linear XOR cancellation ($\Delta \oplus \Delta = 0$), eliminates zero fixed-point ($f(0) \neq 0$), Shannon entropy $H \approx 7.998$ bits, lock-free dynamic atomic caching |
| **Formal Mathematical Proofs** | 50+ Verus SMT theorems + 101 Bolero property harnesses (376 tests) | 376 tests workspace-wide across root crate and 27 verification suite test binaries, 100% pass rate |

---

## Five-Layer Concentric Architecture

```
Application Layer
    │ (uses run_secure, run_coupled, SecureVault, dynamic_str!)
    ▼
Protection Engine
    ├─→ Layer 5: Decentralized State & Silent Corruption
    │     128 Atomic Shards (64 Active / 64 Decoy), Domain-Separated SipHash-2-4,
    │     Dynamic Partition Map, Absorbing Poison Latch, Dispersed Scattering
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
    │     Asymmetric 3-Pipeline ARX Shard Recomposition (breaks Δ ⊕ Δ = 0),
    │     Pure Bijective Fixed-Point-Free KDF (f(0) != 0, Two-Sided Invertibility),
    │     Non-Linear 4-Stage ARX u8 Projection (H ≈ 7.998 bits), Lock-Free Dynamic Atomic Caching
    │
    └─→ Layer 1: Foundational Entropy & Detection Entanglement
          Shard 1 (Build Seed), Shard 2 (CPUID Fingerprint), Shard 3 (PE Checksum),
          PEB Dereference, Hardware Debug Registers (Dr0-Dr7), RDTSC Baseline, TLS
```

### 128-Shard Active/Decoy State (`global_state.rs`)
Rather than relying on a centralized boolean flag (which can be easily modified with a single debugger breakpoint or memory write), suspicion is distributed across **128 atomic shards** (`AtomicU32`):
- **64 Active Shards**: Contain real suspicion scores.
- **64 Decoy Shards**: Contain high-entropy decoy noise mimicking real detections.
- **Dynamic Partition Map Evolution**: Shards are partitioned into 64 adjacent pairs `(2*i, 2*i+1)`. A 64-bit pair map is dynamically derived via `compute_dynamic_pair_map(seed, dynamic_counter)` combining runtime seed with threat evolution counter, eliminating static partition space collapse.
- **XOR Masking & Decoupled Rotation**: Each shard stores `(Score.rotate_left((i ^ 1) % 32)) ^ Mask_i` with rotation shift decoupled from pair parity. Zeroing memory results in `0 ^ Mask = Mask`, generating an immediate score spike exceeding 500 points that trips the `0xFFFFFFFF` honeytrap.
- **Dispersed Scattering & Bounded Decoy Noise**: Detections split suspicion points across 3 random active shards (`p1 + p2 + p3 = amount`) via atomic CAS loops (`add_to_shard`), while injecting bounded noise into 3 random decoy shards with full 32-bit rotational encoding clamped to 255.
- **Domain-Separated Dynamic SipHash-2-4**: State integrity is cryptographically validated across two independent compression blocks using domain separation constants `0x243F6A8885A308D3` (score) and `0x13198A2E03707344` (decay timestamp), serialized via `INTEGRITY_LOCK` spin-wait CAS loop.
- **Absorbing Irreversible Poison Latch**: Irreversible MSB latch (`state | 0x8000_0000_0000_0000`) and linear congruential mixing (`0x9E3779B97F4A7C15`) prevent involutory cancellation under repeated triggers, short-circuiting recalculation and permanently invalidating integrity tags.
- **Formal Verification**: 16 formal proofs (Verus SMT deductive theorems & Bolero property fuzzing in `defect_layer5_proofs.rs`) verifying AWS unit proof invariants across partition spaces, concurrency races, and poison lifecycles.

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
│       ├── seed_orchestrator.rs  # Hardened 3-pipeline ARX & pure bijective KDF (350+ lines)
│       ├── hardware_entropy.rs   # CPUID processor fingerprinting (150 lines)
│       ├── pe_integrity.rs       # PE section sharded checksumming (310 lines)
│       ├── anti_debug.rs         # Multi-vector detection sensors (2170 lines)
│       ├── anti_dump.rs          # Lock-free decoy traps & 16-aligned indirect syscalls (549 lines)
│       ├── enhanced_veh.rs       # 5-phase master VEH with Win32 CONTEXT & re-entrancy bounds (459 lines)
│       ├── global_state.rs       # 128-shard active/decoy state machine (1173 lines)
│       ├── tiny_vm.rs            # Hardened indirect-threaded virtual machine 2.0 (1660 lines)
│       └── decoy_system.rs       # Honey pot functions & watchdog prologue scanner (190 lines)
├── verification_suite/           # Standalone Formal Verification Harness
│   ├── Cargo.toml                # Verification crate dependencies (Bolero, Verus)
│   ├── run_verification.ps1      # Authoritative PowerShell verification runner
│   ├── run_verification.bat      # Windows CMD verification wrapper
│   ├── src/
│   │   ├── verus_proofs/         # Verus deductive SMT theorems (Z3 solver, DEF-L2-01..05)
│   │   ├── bolero_harnesses/     # Bolero property-based fuzzing harnesses (SAC, bijectivity)
│   │   └── shims/                # Test shims for internal component verification
│   └── tests/                    # Integration test binaries (355+ tests)
│       ├── defect_layer2_proofs.rs# Layer 2 formal defect reproduction suite (DEF-L2-01..05)
│       ├── e2e_layer2_test_suite.rs# Layer 2 4-tier requirement & integration suite
│       ├── hypothesis_*.rs       # Layer 3 & 4 hypothesis formal verification suites (5 binaries)
│       ├── defect_layer4_tinyvm.rs# Layer 4 TinyVM 2.0 formal defect verification suite (D1..D7)
│       ├── defect_layer5_proofs.rs# Layer 5 mathematical hardening & formal defect suite (16 proofs)
│       ├── adversarial_*.rs      # Adversarial challenge suites for Layer 3 invariants (10 binaries)
│       ├── challenger_*.rs       # Layer 1 & 2 adversarial stress challenges (2 binaries)
│       ├── defect_proofs.rs      # Formal defect proofs for historical flaws (FLAW-01..16)
│       ├── m1_math_challenge.rs  # Golden ratio modular inverse & Murmur3 bijectivity
│       ├── m2_bolero_challenge.rs# Empirical fuzzing challenges across all layers
│       ├── repro_defects.rs      # Verified defect reproduction & regression guards
│       └── shim_stress.rs        # Multithreaded concurrency stress & PE integrity
├── docs/                         # Comprehensive Technical Documentation
│   ├── LAYER2_FORMAL_HARDENING.md# Master Layer 2 cryptographic & formal specification
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
- Linear shard XOR cancellation attacks & simultaneous environment spoofing ($\Delta \oplus \Delta = 0$).
- Degenerate zero fixed-point ($f(0)=0$) & zero-sum entropy collapse ($h = b \oplus p$).
- TinyVM keyspace collapse via 24-bit linear u8 projection kernel.
- Static caching temporal blindness via lock-free atomic caching and dynamic token coupling.

### Limitations & Out of Scope
- Kernel-mode debuggers with hardware hypervisor hooks (Ring -1 / Ring 0).
- Physical hardware attacks (Direct Memory Access / DMA hardware sniffers, side-channel analysis).

---

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Created by anhdeface aka Julian Kmut. Formally verified & synchronized 2026.

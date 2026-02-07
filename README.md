![img](https://i.pinimg.com/originals/c9/16/d9/c916d9fc9dd8b168666baea645f54234.gif)
# FDebug - Advanced Anti-Debug Protection System

A sophisticated, multi-layered anti-debugging protection system for Rust applications on Windows x86-64. FDebug detects debugging attempts and silently corrupts sensitive computations when tampering is detected, making reverse engineering economically unfeasible.

## Core Philosophy

Rather than crashing when a debugger is detected (which provides attackers an easy anchor point), **fdebug** silently corrupts the transformation keys and internal state. The protected application continues running but produces subtly incorrect results - making debugging an endless nightmare of phantom bugs with no root cause.

```
Traditional Anti-Debug:  Debugger detected → Crash → Attacker patches
                        
FDebug Protection:      Debugger detected → Silent Corruption → 
                        All calculations wrong → Attacker spends weeks 
                        debugging non-existent bugs → Attacker gives up
```

### [UPDATE] Latest Update: Watchdog v2 & Stability Refinement

The system has been hardened with **Watchdog v2** and environment-adaptive scoring:

-   **Silent Poisoning (Watchdog v2)**: Replaced process termination with **Silent Data Poisoning**. If thread suspension is detected (via a debugger), the system corrupts internal cryptographic keys and suspicious seeds instead of killing the process.
-   **Adaptive Sensitivity**: Implemented a 5-second baseline threshold with **Heavy-Load Awareness** (doubles timeout to 10s during high CPU usage) to virtually eliminate false positives in laggy or virtualized environments.
-   **Hypervisor Optimization**: Refined CPUID and timing detection logic. The system now reports a stable **60 suspicion score** on Hyper-V environments, allowing the app to run safely while remaining vigilant.
-   **Entangled Execution (Anti-DBI/Anti-Trace)**: Integrated internal anchors into the VM execution loop. The decryption key is now mathematically bound to the code's memory location (RIP) and execution timing (Thread Cycles), silently corrupting the execution state if relocation or tracing is detected.
-   **Precision Anti-Dump**: Fixed stealth state verification to specifically monitor **NT Signature erasure**, ensuring protection even when DOS headers are preserved for stability.

## Key Features

| Feature | Implementation | Effect |
| --- | --- | --- |
| **Multi-Vector Detection** | VEH hooks, RDTSC timing, Hardware BP, PEB checks | Catches debugging from multiple angles simultaneously |
| **Watchdog v2 (Liveness)** | Direct Syscall + Adaptive Thresholding | Detects suspension; triggers **Silent Poisoning** instead of exit [+] |
| **Entangled Execution** | RIP Anchoring + Thread Cycle Heartbeat | Binds VM key to code location and timing; anti-DBI/anti-trace [+] |
| **Randomized TinyVM** | Indirect Threading + Randomized V-Table | No switch/match; Helper addresses shuffled at runtime |
| **Distributed Scoring** | 128-shard atomic scoring (Active/Decoy) | Memory manipulation is self-detecting; massive entropy dilution |
| **Silent Corruption** | Token-based key poisoning | No crashes; just silently wrong results |
| **Continuous Sharding** | sharded integrity + VM entanglement | PE modifications naturally break VM execution loop [+] |
| **Surgical Anti-Dump** | Selective PE Header Corruption | Bypasses EDR hooks; wipes NT headers but keeps DOS for stability |

## Quick Start

### Installation

```rust
// Cargo.toml
[dependencies]
fdebug = { path = "./fdebug" }

// main.rs
use fdebug::protector::{Protector, get_dynamic_seed};

fn main() {
    let seed = get_dynamic_seed();  // Runtime-reconstructed from three sources
    let protector = Protector::new(seed);
    println!("[+] Anti-debug protection initialized");
}
```

### Basic Usage

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution, get_dynamic_seed};

fn main() {
    let seed = get_dynamic_seed();
    let protector = Protector::new(seed);
    
    // Protect sensitive data
    let api_key = SecureVault::new("sk_live_secret_key".to_string());
    
    let is_valid = protector.run_secure(&api_key, |key, token| {
        // token is only valid in clean environment
        key.len() == 18 && (token % 7) == 0
    });
    
    if is_valid {
        println!("[+] API key validated");
    } else {
        eprintln!("[-] Running under debugger - data corrupted");
    }
}
```

### Advanced Pattern

```rust
use fdebug::protector::{CoupledLogic, Corruptible, get_dynamic_seed};

#[derive(Clone)]
struct PaymentData {
    amount: f64,
    valid: bool,
}

impl Corruptible for PaymentData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        if token == 0 {
            self.amount = 0.0;
            self.valid = false;
        }
        self
    }
}

let protector = Protector::new(get_dynamic_seed());
let payment = protector.run_coupled(|token| {
    PaymentData {
        amount: 1000.0 + (token as f64 * 0.001),
        valid: token != 0,
    }
});

// If debugged: amount = 0.0, valid = false
// If clean: amount ≈ 1000.0, valid = true
```

## Documentation

Comprehensive documentation is available in the `/docs` directory:

### [DOC] [Advanced Integration Guide](docs/implementation_guide_NEW.md)
Overview, integration checklist, threat model, and FAQ. **Start here if new to fdebug.**

### [ARCH] [Architecture Guide](docs/architecture_guide_NEW.md)
Deep technical analysis of all **five protection layers**:
- **Layer 1**: Seed Orchestrator & Entropy Reconstruction [NEW]
- **Layer 2**: Multi-Vector Detection System
- **Layer 3**: Polymorphic Virtual Execution (TinyVM)
- **Layer 4**: Distributed Suspicion Scoring & Integrity
- **Layer 5**: Decoy System (Honey Pot Pattern)

### [SEC] [Layer 1: Seed Orchestrator (Foundation)](docs/ARCHITECTURE_LAYER5.md) [NEW]
Detailed explanation of runtime seed reconstruction:
- Three entropy shards (Build-Time, Hardware, PE Integrity)
- Avalanche mixing and XOR composition
- Polymorphism across users and hardware
- Performance characteristics (50-100μs first call, then cached)
- Defense against static analysis and memory attacks

### [API] [API Reference Guide](docs/reference_guide_NEW.md)
Complete API documentation with code examples:
- Quick Start (updated with `get_dynamic_seed()`)
- Core API Reference
- Detection Severity Levels
- Usage Patterns (5 essential patterns)
- Advanced Configuration
- Performance Characteristics
- FAQ and Troubleshooting

### [IMPL] [Implementation Guide](docs/implementation_guide_NEW.md)
Best practices and design patterns:
- Architectural Design Patterns (Shield, Sentinel, Checksum)
- Integration Strategies
- Real-World Use Cases (Licensing, API Keys, Data Protection)
- Performance Optimization
- Testing and Validation
- Security Considerations
- Troubleshooting Guide

### [BUILD] [Build Guide - Custom Entropy Setup](docs/BUILD_GUIDE.md) [NEW]
Complete guide for developers customizing the build system:
- Understanding fdebug's three-shard entropy system
- How `build.rs` generates Shard 1 (Build-Time Seed)
- Five customization patterns (Deterministic, High-Entropy, Custom Secrets, etc.)
- Integration with CI/CD pipelines
- Best practices and troubleshooting
- Real-world code examples with detailed comments

### [LOG] [Documentation Updates Summary](docs/DOCUMENTATION_UPDATE_SUMMARY.md) [NEW]
Complete changelog of recent updates:
- Summary of Seed Orchestrator changes
- Before/after code examples
- All updated files and modifications
- Integration points explained

### [UPD] [Updates & Change Guide](docs/UPDATES.md) [NEW]
Detailed technical guide for developers:
- Code changes explained
- Module structure
- Testing validation
- Consistency guidelines

## Examples

Complete working examples are in the `/examples` directory:

- **basic_protection.rs** - Simple API key protection
- **guarded_logic.rs** - Token-based financial calculations with corruption
- **custom_vm_op.rs** - Guide to extending the VM with custom opcodes

Run them:
```bash
cargo run --example basic_protection
cargo run --example guarded_logic
```

## Architecture Overview

```
Application Layer
    ↓ (uses run_secure, run_coupled, SecureVault)
Protection Layer
    ├─→ Layer 5: Decoy System (watchdog monitoring, honey traps)
    ├─→ Layer 4: Integrity (distributed shards, SipHash verification)
    ├─→ Layer 3: Obfuscation (polymorphic TinyVM, control flow flattening)
    ├─→ Layer 2: Detection (VEH hooks, timing, hardware BP, PEB checks)
    └─→ Layer 1: Entropy (Seed Orchestrator - runtime seed reconstruction)
```

## How It Works

### Layer 1: Seed Orchestrator (Foundation) [NEW]

**Runtime seed reconstruction from three entropy sources:**

- **Build-Time Seed** (random per compilation): Each binary gets unique value
- **Hardware Entropy** (CPU fingerprint): CPUID data makes seed hardware-specific  
- **PE Integrity Hash** (code checksum): Any code modification invalidates seed

**Formula**: `FINAL_SEED = avalanche_mix(BUILD_SEED ^ HW_ENTROPY ^ PE_HASH)`

**Result**: 
- No static keys to extract from memory
- Each build gets unique opcode values
- Same binary runs differently on different CPUs
- Code patches instantly detected
- Polymorphic per-user, per-hardware-platform

### Layer 2: Detection (Multi-Vector)

### Layer 2: Detection (Multi-Vector)

- **Vectored Exception Handling** catches INT3 and single-step exceptions
- **Hardware Breakpoint Detection** monitors CPU debug registers (Dr0-Dr7)
- **RDTSC Timing** detects execution delays from stepping/breakpoints
- **PEB Memory Checks** read BeingDebugged and NtGlobalFlag flags
- **Environment Detection** identifies virtual machines and cloud environments

### Layer 3: Obfuscation (Polymorphic VM)

- Custom bytecode VM with stack-based architecture using indirect threading
- **Entangled Execution**: The VM loop is now "entangled" with the environment:
  - **RIP Entanglement**: Binds the decryption key to the physical entry address. If code is relocated (typical of DBI tools), the key becomes invalid.
  - **Thread Cycle Heartbeat**: Detects excessive CPU cycle consumption via `QueryThreadCycleTime`. Tracing or single-stepping triggers silent key corruption.
- Control flow flattening converts sequential code into opaque state machines
- Opcodes change every build (polymorphic - different per binary)
- Derived from runtime-reconstructed seed via `auto_op!()` macro
- Zero external dependencies (No `winapi`/`windows-rs`); uses manual FFI and inline assembly
- Analysis tools (IDA, Ghidra) produce unusable output

### Layer 4: Integrity (Distributed Scoring)

- **128-Shard Atomic Architecture**: Suspicion score is split across 128 independent shards (64 Active, 64 Decoy).
- **Active/Decoy Dilution**: Decoy shards store high-entropy "noise" while active shards track real detections, making state-freezing attacks exponentially harder.
- **XOR Masking**: Each shard is masked with a build-time derived value; zeroing shards creates a massive score spike.
- **VM Entanglement**: TinyVM decryption is mathematically tied to the sharded integrity hash; tampering breaks the VM loop.

### Layer 5: Deception (Honey Pots)

- Decoy functions explicitly exposed (easy to find)
- Watchdog continuously monitors function bytecode
- Patching detected instantly → DECOY_TAMPERED flag set
- All future security tokens become corrupted
- Attacker's "successful patch" silently corrupts everything

## Performance

Typical overhead: **3-5%** for average applications

```
Per-operation cost:    <1ms
Heartbeat overhead:    <1ms every 10 operations
Watchdog check:        <5ms probabilistically
Startup cost:          ~1ms (VEH registration)
```

Optimizable: protect only critical operations, batch processes, etc.

## Threat Model

### [+] Defends Against

- Software debuggers (WinDbg, x64dbg, IDA Debugger)
- Automated analysis (IDA Pro, Ghidra, Binary Ninja)
- Patch attacks (bytecode modification)
- Hook attacks (IAT/EAT hooking)
- Memory freezing (breakpoint data freezing)
- Single-stepping attacks
- DLL injection attempts

### [-] Limitations

- Kernel-mode debuggers have lower-level access
- Hypervisor escapes may bypass some checks
- Physical attacks (DMA, side-channels) out of scope
- Source code availability doesn't help (polymorphic per-user)

## Deployment

Each build automatically generates a **unique runtime seed** reconstructed from three sources:

```bash
cargo build --release  
# BUILD_SEED = random value (unique)
# HW_ENTROPY = your CPU fingerprint
# PE_HASH = your code checksum
# FINAL_SEED = avalanche_mix(BUILD ^ HW ^ PE)

cargo build --release  
# BUILD_SEED = different random value!
# (Even on same hardware, different binary)
```

**Result:** Version 1.0 exploits are useless against Version 1.1. Each user's binary is uniquely protected, and any code modification invalidates all security tokens.

See [Seed Orchestrator Documentation](docs/ARCHITECTURE_LAYER5.md) for technical details.

## Configuration

### Using the Runtime-Reconstructed Seed

```rust
use fdebug::protector::{Protector, get_dynamic_seed, get_dynamic_seed_u8};

// Get 32-bit seed (reconstructed at runtime)
let seed = get_dynamic_seed();
let protector = Protector::new(seed);

// Or use u8 variant if needed
let seed_u8 = get_dynamic_seed_u8();
```

### Diagnostic Mode

```rust
use fdebug::protector::global_state::DIAGNOSTIC_MODE;
use std::sync::atomic::Ordering;

DIAGNOSTIC_MODE.store(true, Ordering::Relaxed);
// Logs which checkpoints trigger and their suspicion scores
```

### Feature Flags

```rust
#[cfg(feature = "max-protection")]
let protector = Protector::new(get_dynamic_seed());

#[cfg(not(feature = "max-protection"))]
let protector = DummyProtector::new();
```

## Building & Testing

```bash
# Build with protection (release)
cargo build --release

# Build without protection (debug/testing)
cargo build

# Run examples
cargo run --example basic_protection
cargo run --example guarded_logic

# Run with diagnostics
RUST_LOG=debug cargo run --release
```

## Module Structure

```
src/protector/
├── mod.rs                    # Main API & integration layer
├── seed_orchestrator.rs      # Runtime seed reconstruction [NEW]
├── hardware_entropy.rs       # Hardware fingerprint (Windows)
├── pe_integrity.rs           # PE code section hash (Windows)
├── anti_debug.rs             # Multi-vector detection (2300+ lines)
├── global_state.rs           # Distributed scoring & integrity (667 lines)
├── tiny_vm.rs                # Polymorphic VM bytecode (1169 lines)
├── decoy_system.rs           # Honey pot functions (284 lines)
└── tiny_vm/
    └── generated_constants.rs
```

Total: ~4500+ lines of anti-debugging logic + Seed Orchestrator runtime reconstruction

## Compilation

Only compiles on **Windows x86-64**:
- Requires Windows API features
- Uses inline x86 assembly
- Non-Windows platforms get dummy implementations

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.51", features = [...] }
```

## Security Notes

[!] **Important Security Considerations:**

1. **No static secrets** - Runtime seed reconstruction means no hardcoded keys to find
2. **Seed is hardware and build-specific** - `get_dynamic_seed()` changes based on CPU and code
3. **Don't cache results** across protection boundaries - Always call `run_secure`/`run_coupled`
4. **Validate tokens** before using them in calculations
5. **Monitor suspicion scores** in production (enable diagnostic mode if needed)
6. **Update regularly** - Each build gets new entropy automatically, defeating old exploits

## Performance Tips

```rust
// [OK] GOOD - Single run_secure wrapping batch operation
protector.run_secure(&vault, |data, token| {
    data.iter().map(|x| process(x, token)).collect()
})

// [!] POOR - Separate run_secure per item
for item in data {
    protector.run_secure(&vault, |_, token| process(item, token))
}
```

## FAQ

**Q: Does it work in virtual machines?**
A: Yes, it detects and adapts. VMs may trigger higher suspicion scores, but application still works. See [Detection Layer](docs/architecture_guide_NEW.md) for details.

**Q: Can I use this in open-source projects?**
A: Yes! It's MIT licensed. Even with source available, runtime-reconstructed polymorphic-per-user protection makes it effective.

**Q: What about false positives?**
A: Extremely rare. Enable diagnostic mode to identify causes. Usually legitimate VM/CI environments.

**Q: Does performance matter?**
A: For most applications, 3-5% overhead is negligible. Profile your specific use case. See [Performance](docs/reference_guide_NEW.md#performance-characteristics) section.

**Q: How does the seed reconstruction work?**
A: Three independent entropy sources are combined via XOR and avalanche mixing. See [Seed Orchestrator](docs/ARCHITECTURE_LAYER5.md) documentation for deep dive.

**Q: Can someone just patch all the calls to run_secure?**
A: They could modify your binary, but then PE_HASH changes. The next build has different entropy from that code patch - exploit fails.

**Q: What if attackers know my source code?**
A: The runtime seed is unique per user and per hardware. Even identical code produces different opcodes on different CPUs and builds. See [Polymorphism](docs/ARCHITECTURE_LAYER5.md#54-polymorphism-across-users-and-hardware) section.

## License

MIT License - See LICENSE file for details

## Author

Created by anhdeface aka Julian Kmut
## Contributing

This is a reference implementation of advanced anti-debugging techniques. It's suitable for:

- Educational purposes (understand protection mechanisms)
- Production protection (shipping with applications)
- Security research (study evasion techniques)
- Competition purposes (CTF challenges)

Not suitable for:

- Obfuscating malware (illegal)
- Defeating legitimate security research
- Preventing legitimate software updates

---

## Quick Navigation

| I want to... | Go to |
| --- | --- |
| **Learn about latest updates** | [LOG] [Documentation Updates Summary](docs/DOCUMENTATION_UPDATE_SUMMARY.md) |
| **Understand Seed Orchestrator** | [SEC] [Layer 1: Seed Orchestrator (Foundation)](docs/ARCHITECTURE_LAYER5.md) |
| **Customize the build system** | [BUILD] [Build Guide - Custom Entropy Setup](docs/BUILD_GUIDE.md) |
| **Understand how fdebug works** | [ARCH] [Full Architecture Guide](docs/architecture_guide_NEW.md) |
| **Use fdebug in my project** | [DOC] [Complete Integration Guide](docs/FDEBUG_COMPLETE_GUIDE.md) |
| **See all API functions** | [API] [API Reference Guide](docs/reference_guide_NEW.md) |
| **Learn best practices** | [IMPL] [Implementation Guide](docs/implementation_guide_NEW.md) |
| **See working code** | [examples/](examples/) directory |
| **Deploy to production** | [DOC] [Integration Guide - Deployment](docs/FDEBUG_COMPLETE_GUIDE.md#deployment-considerations) |

---

## Start Here

**New to fdebug?** Read in this order:

1. [DOC] [Complete Integration Guide](docs/FDEBUG_COMPLETE_GUIDE.md) - 10 min overview
2. [SEC] [Layer 1: Seed Orchestrator (Foundation)](docs/ARCHITECTURE_LAYER5.md) - Understand the foundation
3. [ARCH] [Architecture Guide](docs/architecture_guide_NEW.md) - Deep technical analysis
4. [examples/](examples/) - See working code
5. [IMPL] [Implementation Guide](docs/implementation_guide_NEW.md) - Best practices

---

**Latest Update**: Runtime seed reconstruction from three entropy sources (Build-Time, Hardware, PE Integrity). See [SEC] [Layer 5](docs/ARCHITECTURE_LAYER5.md) for details.

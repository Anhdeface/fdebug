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

## Key Features

| Feature | Implementation | Effect |
| --- | --- | --- |
| **Multi-Vector Detection** | VEH hooks, RDTSC timing, Hardware BP, PEB checks | Catches debugging from multiple angles simultaneously |
| **Polymorphic VM** | TinyVM with control flow flattening | Bytecode changes every build; signature-based bypass impossible |
| **Distributed State** | 16-shard atomic scoring | Memory freezing attacks fail; manipulation is self-detecting |
| **Silent Corruption** | Token-based key poisoning | No crashes; just silently wrong results |
| **Honey Pot Traps** | Decoy functions with watchdog monitoring | Reverse engineers patch decoys → automatic detection → execution poisoned |
| **Mathematical Coupling** | Security tokens bound to business logic | Cracked protection automatically invalidates calculations |

## Quick Start

### Installation

```rust
// Cargo.toml
[dependencies]
fdebug = { path = "./fdebug" }

// main.rs
use fdebug::protector::{Protector, DYNAMIC_SEED};

fn main() {
    let protector = Protector::new(DYNAMIC_SEED);
    println!("[+] Anti-debug protection initialized");
}
```

### Basic Usage

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

fn main() {
    let protector = Protector::new(DYNAMIC_SEED);
    
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
use fdebug::protector::{CoupledLogic, Corruptible};

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

Complete documentation is available in the `/docs` directory:

### 📖 [Complete Guide - Start Here](docs/FDEBUG_COMPLETE_GUIDE.md)
Overview, integration checklist, threat model, and FAQ. **Read this first.**

### 🏗️ [Architecture Guide](docs/architecture_guide_NEW.md)
Deep technical analysis of all four protection layers:
- Layer 1: Multi-Vector Detection System
- Layer 2: Polymorphic Virtual Execution (TinyVM)
- Layer 3: Distributed Suspicion Scoring & Integrity
- Layer 4: Decoy System (Honey Pot Pattern)

### 📚 [API Reference Guide](docs/reference_guide_NEW.md)
Complete API documentation with code examples:
- Core API Reference
- Detection Severity Levels
- Usage Patterns (5 essential patterns)
- Advanced Configuration
- Performance Characteristics
- FAQ and Troubleshooting

### 🛠️ [Implementation Guide](docs/implementation_guide_NEW.md)
Best practices and design patterns:
- Architectural Design Patterns (Shield, Sentinel, Checksum patterns)
- Integration Strategies
- Real-World Use Cases (Licensing, API Keys, Data Protection)
- Performance Optimization
- Testing and Validation
- Security Considerations
- Troubleshooting Guide

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
    ├─→ Global State (distributed suspicion scoring)
    ├─→ TinyVM (polymorphic bytecode execution)
    ├─→ Anti-Debug (VEH hooks, timing checks)
    └─→ Decoy System (watchdog monitoring)
```

## How It Works

### 1. Detection (Multi-Vector)

- **Vectored Exception Handling** catches INT3 and single-step exceptions
- **Hardware Breakpoint Detection** monitors CPU debug registers (Dr0-Dr7)
- **RDTSC Timing** detects execution delays from stepping/breakpoints
- **PEB Memory Checks** read BeingDebugged and NtGlobalFlag flags
- **Environment Detection** identifies virtual machines and cloud environments

### 2. Obfuscation (Polymorphic VM)

- Custom bytecode VM with stack-based architecture
- Control flow flattening converts sequential code into opaque state machines
- Opcodes change every build (polymorphic - different per binary)
- Even with source code, each user gets unique protection
- Analysis tools (IDA, Ghidra) produce unusable output

### 3. Integrity (Distributed Scoring)

- Suspicion score split across 16 atomic shards
- Each shard masked with build-time derived value
- Reconstructed score: `score = (shard0 ^ mask0) + (shard1 ^ mask1) + ...`
- Memory freezing attacks fail: zeroing shards creates massive score spike
- SipHash integrity verification detects tampering

### 4. Deception (Honey Pots)

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

### ✅ Defends Against

- Software debuggers (WinDbg, x64dbg, IDA Debugger)
- Automated analysis (IDA Pro, Ghidra, Binary Ninja)
- Patch attacks (bytecode modification)
- Hook attacks (IAT/EAT hooking)
- Memory freezing (breakpoint data freezing)
- Single-stepping attacks
- DLL injection attempts

### ⚠️ Limitations

- Kernel-mode debuggers have lower-level access
- Hypervisor escapes may bypass some checks
- Physical attacks (DMA, side-channels) out of scope
- Source code availability doesn't help (polymorphic per-user)

## Deployment

Each build automatically gets a **unique DYNAMIC_SEED**:

```bash
cargo build --release  # Seed = 0x12345678
cargo build --release  # Seed = 0x87654321 (different!)
```

**Result:** Version 1.0 exploits are useless against Version 1.1, even for identical code. Each user's binary is uniquely protected.

## Configuration

### Diagnostic Mode

```rust
use fdebug::protector::global_state::DIAGNOSTIC_MODE;
use std::sync::atomic::Ordering;

DIAGNOSTIC_MODE.store(true, Ordering::Relaxed);
```

### Feature Flags

```rust
#[cfg(feature = "max-protection")]
let protector = Protector::new(DYNAMIC_SEED);

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
├── anti_debug.rs             # Multi-vector detection (2300+ lines)
├── global_state.rs           # Distributed scoring & integrity (667 lines)
├── tiny_vm.rs                # Polymorphic VM bytecode (1169 lines)
├── decoy_system.rs           # Honey pot functions (284 lines)
├── generated_constants.rs    # Build-time DYNAMIC_SEED
└── tiny_vm/
    └── generated_constants.rs
```

Total: ~4500 lines of pure anti-debugging logic

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

⚠️ **Important Security Considerations:**

1. **DYNAMIC_SEED is secret** - If attackers know it, they can simulate the protection
2. **Don't cache results** across protection boundaries
3. **Validate tokens** before using them in calculations
4. **Monitor suspicion scores** in production
5. **Update regularly** - new builds get new seeds automatically

## Performance Tips

```rust
// ✅ GOOD - Single run_secure wrapping batch operation
protector.run_secure(&vault, |data, token| {
    data.iter().map(|x| process(x, token)).collect()
})

// ❌ POOR - Separate run_secure per item
for item in data {
    protector.run_secure(&vault, |_, token| process(item, token))
}
```

## FAQ

**Q: Does it work in virtual machines?**
A: Yes, it detects and adapts. VMs may trigger higher suspicion scores, but application still works.

**Q: Can I use this in open-source projects?**
A: Yes! It's MIT licensed. Even with source available, polymorphic per-user protection makes it effective.

**Q: What about false positives?**
A: Extremely rare. Enable diagnostic mode to identify causes. Usually legitimate VM/CI environments.

**Q: Does performance matter?**
A: For most applications, 3-5% overhead is negligible. Profile your specific use case.

**Q: Can someone just patch all the calls to run_secure?**
A: They could modify your binary, but then DYNAMIC_SEED is gone. Next build has a different seed - exploit fails.

## License

MIT License - See LICENSE file for details

## Author

Created by anhdeface - Advanced anti-reverse engineering systems

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
| Understand how fdebug works | [Architecture Guide](docs/architecture_guide_NEW.md) |
| Use fdebug in my project | [Complete Guide](docs/FDEBUG_COMPLETE_GUIDE.md) |
| See all API functions | [API Reference](docs/reference_guide_NEW.md) |
| Learn best practices | [Implementation Guide](docs/implementation_guide_NEW.md) |
| See working code | [examples/](examples/) directory |
| Deploy to production | [Complete Guide - Deployment](docs/FDEBUG_COMPLETE_GUIDE.md#deployment-considerations) |

---

**Start with:** [docs/FDEBUG_COMPLETE_GUIDE.md](docs/FDEBUG_COMPLETE_GUIDE.md)

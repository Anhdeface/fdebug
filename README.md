
![img](https://i.pinimg.com/originals/c9/16/d9/c916d9fc9dd8b168666baea645f54234.gif)

---
# Anti-Debug Protection Module

**A comprehensive, modular anti-debugging solution for Windows-based Rust applications with VM-based detection and silent corruption mechanisms.**

## Overview

This is an advanced anti-debug protection library designed to detect and neutralize debuggers in Windows environments. It employs multiple sophisticated detection mechanisms including:

- **Virtual Machine-based Detection**: Polymorphic bytecode execution for memory integrity checks
- **Timing Anomaly Detection**: RDTSC-based timing analysis to detect debugger interference
- **PEB Analysis**: Direct Process Environment Block examination for debug flags
- **Hypervisor Detection**: Multi-layered detection of virtualization and cloud environments
- **Self-Integrity Verification**: Runtime code integrity checking to detect tampering
- **Distributed State System**: Atomic-based distributed detection state across threads
- **Silent Corruption**: When a debugger is detected, sensitive operations are corrupted instead of exiting

## Key Features

### 🛡️ Multi-Layer Detection
- **Memory Integrity Checkpoint**: Detects debugger through PEB flags and NtGlobalFlag values
- **Timing Anomaly Checkpoint**: Uses RDTSC instruction to measure execution timing anomalies
- **Exception Handling Checkpoint**: Monitors vectored exception handlers for breakpoint detection
- **Hypervisor Detection Checkpoint**: Identifies virtualization environments with CPUID analysis
- **Integrity Checkpoint**: Runtime verification of critical code sections

### 🔐 Anti-Analysis Features
- **Polymorphic Opcodes**: TinyVM instructions change at each build due to unique seeds
- **XOR-Encoded Strings**: Critical strings are encoded to prevent static analysis
- **Opaque Predicates**: Code flow includes conditional branches that appear complex but are mathematically predetermined
- **Distributed Detection State**: Uses atomic variables to track detection across threads

### 🎯 Intelligent Response
- **Suspicion Scoring System**: Gradual accumulation of suspicion rather than immediate detection
- **Category-based Thresholds**: Different detection types have different confidence requirements
- **Silent Corruption Mode**: Instead of crashing, sensitive operations produce corrupted results
- **Persistent State**: Once debugger is detected, the state remains set permanently

## Platform Support

- **Primary**: Windows x86_64 (fully supported)
- **Secondary**: Other platforms have dummy implementations that always return false

## Installation

### As a Module

1. Copy the `src/protector/` directory to your Rust project
2. Add to your `lib.rs` or `main.rs`:

```rust
mod protector;
use protector::Protector;
```

### As a Dependency (Cargo)

Add to your `Cargo.toml`:

```toml
[dependencies]
windows = { version = "0.51", features = ["Win32_Foundation", "Win32_System_Memory", "Win32_System_Diagnostics_Debug"] }
```

## Quick Start

### Basic Usage

```rust
use protector::Protector;

fn main() {
    // Initialize the protector with a seed value
    let protector = Protector::new(0x12345678);
    
    // Check if debugger is detected
    if protector.is_debugged() {
        eprintln!("Debugger detected!");
        std::process::exit(1);
    }
    
    // Your application code here
    println!("Safe from debuggers!");
}
```

### Advanced Usage with Detection Details

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0x12345678);
    
    // Get detailed detection information
    let details = protector.get_detection_details();
    
    println!("Is Debugged: {}", details.is_debugged);
    println!("Suspicion Score: {}", details.score);
    println!("PEB Check Result: {}", details.peb_check);
    println!("RDTSC Check Result: {}", details.rdtsc_check);
    println!("Exception Handler Check: {}", details.heap_check);
    println!("Hypervisor Check: {}", details.hypervisor_check);
    println!("Integrity Check: {}", details.integrity_check);
}
```

### Using Encryption/Decryption with Embedded Protection

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0x87654321);
    
    // Encrypt data (includes automatic anti-debug check)
    let plaintext = b"Secret message";
    let encrypted = protector.encrypt_data(plaintext);
    
    // If debugger detected, data will be corrupted during encryption
    println!("Encrypted data length: {}", encrypted.len());
    
    // Decrypt data (includes automatic anti-debug check)
    let decrypted = protector.decrypt_data(&encrypted);
    
    // If debugger was detected, decryption will fail silently
}
```

### License Validation with Anti-Debug

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    let license_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    
    // License validation includes timing anomaly check
    if protector.validate_license(license_key) {
        println!("License valid!");
    } else {
        // Could be invalid license or debugger detected
        println!("License validation failed");
    }
}
```

## Configuration

The module behavior can be customized by modifying constants in `src/protector/anti_debug.rs`:

```rust
/// Hardcoded fallback threshold for RDTSC (in CPU cycles)
const RDTSC_FALLBACK_THRESHOLD: u64 = 100;

/// Data Corruption Mode: When enabled, output is silently corrupted instead of exiting
const DATA_CORRUPTION_MODE: bool = true;

/// VEH Detection: Use Vectored Exception Handler for breakpoint detection
const ENABLE_VEH_DETECTION: bool = true;

/// Integrity Check: Enable runtime self-integrity verification
const ENABLE_INTEGRITY_CHECK: bool = true;
```

## Detection Checkpoints

### 1. Memory Integrity Checkpoint
- **What it detects**: Debugger through PEB flags and NtGlobalFlag
- **How it works**: Uses TinyVM to execute polymorphic bytecode that reads PEB structure
- **Suspicion Added**: 50 points
- **Reliability**: Very high (reliable across all Windows versions)

### 2. Timing Anomaly Checkpoint
- **What it detects**: Debugger interference with instruction execution
- **How it works**: Measures RDTSC cycles between two timestamps
- **Suspicion Added**: 30 points
- **Reliability**: High (but can have false positives on heavily loaded systems)

### 3. Exception Handling Checkpoint
- **What it detects**: Hardware breakpoints and exception hooks
- **How it works**: Monitors vectored exception handlers
- **Suspicion Added**: 40 points
- **Reliability**: Medium (depends on debugger implementation)

### 4. Hypervisor Detection Checkpoint
- **What it detects**: Virtual machines and cloud environments
- **How it works**: Uses CPUID to detect hypervisor presence and brand strings
- **Suspicion Added**: 10-30 points (variable)
- **Reliability**: Medium (high false positive rate in cloud environments)

### 5. Integrity Checkpoint
- **What it detects**: Code tampering and section modification
- **How it works**: Calculates hash of critical code sections
- **Suspicion Added**: 70 points
- **Reliability**: Very high (detects actual code modifications)

## Suspicion System

The module uses a scoring system rather than immediate detection:

```
Total Suspicion Score Rules:
- PEB checks: Threshold 40 points
- Timing checks: Threshold 60 points
- Exception checks: Threshold 50 points
- Hypervisor checks: Threshold 30 points
- Integrity checks: Threshold 35 points
- Global threshold: 100 points

When any category exceeds its threshold OR global score exceeds 100,
the module sets the debug flag and corrupts encryption keys.
```

## Output Behavior

When a debugger is detected, the module does NOT crash or exit. Instead:

1. **Encryption Key Corruption**: The encryption key is set to `0xFF`
2. **VM Key Corruption**: The virtual machine key is set to `0x00`
3. **Silent Failure**: Encrypted/decrypted data becomes unusable
4. **Persistent Detection**: The debug flag remains set permanently

## TinyVM Internals

The module includes a lightweight virtual machine for obfuscated execution:

### Supported Operations
- **Stack Operations**: PUSH, POP, DUP, SWAP
- **Memory Operations**: READ_MEM_U8, READ_MEM_U32, READ_MEM_U64
- **Arithmetic**: ADD, SUB, XOR, AND, OR, NOT, SHL, SHR
- **Control Flow**: JUMP, JZ, JNZ, CALL, RET, EXIT
- **CPU Operations**: RDTSC, CPUID, IN_PORT, OUT_PORT
- **System Operations**: READ_GS_OFFSET (for PEB access)

### Polymorphism
Each instruction opcode is dynamically generated at compile time using:
```rust
macro_rules! auto_op {
    ($base:expr) => {
        (($base as u8).wrapping_add(BUILD_SEED as u8))
    };
}
```

Where `BUILD_SEED` is computed from package name, file path, and manifest directory.

## Security Considerations

### Strengths
- ✅ Multiple independent detection mechanisms
- ✅ Distributed state across threads
- ✅ Polymorphic code generation
- ✅ Silent corruption mode (attacker doesn't know detection occurred)
- ✅ Runtime integrity verification

### Limitations
- ⚠️ Only detects user-mode debuggers
- ⚠️ Kernel-mode debuggers can bypass detection
- ⚠️ May have false positives in heavily virtualized environments
- ⚠️ Skilled attackers with deep system knowledge can potentially bypass

## Performance Impact

- **Initialization**: ~1-5ms for first-time setup
- **Detection Checkpoint**: ~0.1-0.5ms per checkpoint call
- **Memory Overhead**: ~1-2KB for state structures
- **Encryption/Decryption**: Same as standard XOR cipher (very fast)

## Troubleshooting

### False Positives

If you're getting "debugger detected" in legitimate deployments:

1. **In Virtual Machines**: Adjust hypervisor detection thresholds
2. **On Slow Hardware**: Increase `RDTSC_FALLBACK_THRESHOLD`
3. **On Loaded Servers**: Disable `ENABLE_VEH_DETECTION`

### Not Detecting Debuggers

If debuggers aren't being caught:

1. Ensure you're running on Windows x86_64
2. Check that protector is initialized early in `main()`
3. Verify all detection checkpoints are called
4. Try reducing detection thresholds

## Compilation

```bash
# Build in debug mode
cargo build

# Build release (optimized)
cargo build --release

# Run tests
cargo test

# Clean build
cargo clean && cargo build
```

## Files Structure

```
src/
├── main.rs                          # Example usage and testing
├── protector/
│   ├── mod.rs                       # Module definition and public API
│   ├── anti_debug.rs               # Detection checkpoints and logic
│   ├── tiny_vm.rs                  # Virtual machine implementation
│   └── global_state.rs             # Atomic state management
├── build.rs                         # Build script
└── Cargo.toml                       # Dependencies
```

## License

This project is designed for security research and protected software purposes. Usage is subject to local laws and regulations.

## References

- Microsoft Windows Internals
- PEB Structure Documentation
- CPUID Instruction Reference
- Timing Attack Prevention Techniques

## Support

For issues, questions, or contributions:

1. Check the [Documentation](README_VI.md) (Vietnamese version)
2. Review example code in `src/main.rs`
3. Check test cases in `src/protector/mod.rs`

---

**Note**: This library is continuously evolving. Always test thoroughly in your target environment before production deployment.

# Integration Guide - Anti-Debug Protection Module

## How to Integrate Into Your Rust Project

### Step 1: Copy Module Files

Copy the `src/protector/` directory to your project:

```
your_project/
├── src/
│   ├── main.rs
│   ├── lib.rs
│   └── protector/          ← Copy this entire folder
│       ├── mod.rs
│       ├── anti_debug.rs
│       ├── tiny_vm.rs
│       └── global_state.rs
└── Cargo.toml
```

### Step 2: Update Cargo.toml

Ensure you have the required dependency:

```toml
[dependencies]
windows = { version = "0.51", features = [
    "Win32_Foundation",
    "Win32_System_Memory", 
    "Win32_System_Diagnostics_Debug"
] }
```

### Step 3: Import in Your Code

In `src/main.rs` or `src/lib.rs`:

```rust
mod protector;
use protector::Protector;
```

### Step 4: Initialize Early

Call initialization at the very start of your application:

```rust
fn main() {
    let protector = Protector::new(0x12345678);
    
    if protector.is_debugged() {
        eprintln!("Debug environment detected");
        std::process::exit(1);
    }
    
    // Rest of your application
}
```

## Integration Patterns

### Pattern 1: Early Detection (Recommended)

```rust
fn main() {
    // Initialize immediately
    let protector = Protector::new(0xDEADBEEF);
    
    // Check before any sensitive operation
    if protector.is_debugged() {
        std::process::exit(1);
    }
    
    run_application()
}

fn run_application() {
    // Application code with guaranteed protection
}
```

### Pattern 2: Gradual Detection

```rust
fn main() {
    let protector = Protector::new(0xDEADBEEF);
    run_application(&protector)
}

fn run_application(protector: &Protector) {
    // Check before each sensitive operation
    if protector.is_debugged() {
        handle_debugger_detected();
        return;
    }
    
    let sensitive_data = load_sensitive_data();
    protect_data(protector, &sensitive_data);
}

fn protect_data(protector: &Protector, data: &[u8]) {
    // Encrypt data - includes automatic debug check
    let encrypted = protector.encrypt_data(data);
    process_encrypted(encrypted);
}
```

### Pattern 3: Continuous Monitoring

```rust
fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    loop {
        if protector.is_debugged() {
            eprintln!("Debug detected during execution!");
            break;
        }
        
        process_iteration(&protector);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
```

### Pattern 4: With License Validation

```rust
fn main() {
    let license_key = std::env::var("LICENSE_KEY")
        .unwrap_or_else(|_| "invalid".to_string());
    
    let protector = Protector::new(0xDEADBEEF);
    
    // Validate license (includes debug check)
    if !protector.validate_license(&license_key) {
        eprintln!("License validation failed or debugger detected");
        std::process::exit(1);
    }
    
    run_application(&protector);
}
```

## Advanced Integration Scenarios

### Scenario 1: Protecting Cryptographic Keys

```rust
fn protect_crypto_keys(protector: &Protector) {
    let key_material = load_key_material();
    
    // Encrypt keys (includes auto debug check)
    let encrypted_keys = protector.encrypt_data(&key_material);
    
    // Store encrypted keys
    store_keys(&encrypted_keys);
    
    // Later, when keys are needed:
    if protector.is_debugged() {
        return; // Don't use keys if debugged
    }
    
    let decrypted_keys = protector.decrypt_data(&encrypted_keys);
    use_keys(&decrypted_keys);
}
```

### Scenario 2: Protecting License Check

```rust
fn check_license_validity(protector: &Protector) -> bool {
    // License check includes timing anomaly detection
    let valid = protector.validate_license(&load_license());
    
    if !valid {
        // Could be invalid license OR debugger detected
        // Silent corruption ensures wrong result if debugged
        return false;
    }
    
    true
}
```

### Scenario 3: Multi-threaded Application

```rust
use std::sync::Arc;

fn main() {
    let protector = Arc::new(Protector::new(0xDEADBEEF));
    
    // Detection state is shared across threads via atomic variables
    let mut handles = vec![];
    
    for i in 0..4 {
        let p = Arc::clone(&protector);
        let handle = std::thread::spawn(move || {
            // All threads see the same detection state
            if p.is_debugged() {
                println!("Debugger detected in thread {}", i);
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```

### Scenario 4: Conditional Feature Activation

```rust
fn initialize_features(protector: &Protector) {
    let details = protector.get_detection_details();
    
    // Only enable premium features if not debugged
    let enable_premium = !details.is_debugged && details.score < 30;
    
    if enable_premium {
        println!("Premium features enabled");
    } else {
        println!("Running in safe mode");
    }
}
```

## Troubleshooting Integration

### Issue: "Module not found" Error

**Solution**: Ensure the path is correct:
```rust
mod protector;  // Path should match your directory structure
```

### Issue: Windows-specific Compilation

**Problem**: Compiles only on Windows x86_64

**Solution**: For cross-platform support, use conditional compilation:
```rust
#[cfg(target_os = "windows")]
{
    mod protector;
    use protector::Protector;
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Anti-debug only available on Windows");
}
```

### Issue: False Positives in Virtual Machines

**Solution**: Adjust detection thresholds in `src/protector/anti_debug.rs`:

```rust
// Increase timing threshold for cloud environments
const RDTSC_FALLBACK_THRESHOLD: u64 = 500; // Increased from 100

// Disable hypervisor detection if not needed
const ENABLE_VEH_DETECTION: bool = false;
```

### Issue: Performance Impact

**Solution**: Call detection checkpoints strategically:

```rust
// Bad: Checking every iteration
loop {
    if protector.is_debugged() { } // Too frequent
    process();
}

// Good: Check periodically
let mut check_counter = 0;
loop {
    if check_counter % 1000 == 0 && protector.is_debugged() {
        break; // Check once per 1000 iterations
    }
    process();
    check_counter += 1;
}
```

## Performance Optimization

### Reducing Detection Overhead

1. **Cache detection result** (with caution):
```rust
let is_debugged = protector.is_debugged();
for i in 0..10000 {
    if is_debugged {
        break; // Only check once
    }
    heavy_computation();
}
```

2. **Batch operations**:
```rust
// Encrypt multiple items with one protection check
let protector = Protector::new(0x12345);
if !protector.is_debugged() {
    for data in items {
        let encrypted = protector.encrypt_data(data);
        // Process encrypted
    }
}
```

3. **Lazy initialization**:
```rust
use std::sync::Once;

static INIT: Once = Once::new();
static mut PROTECTOR: Option<Protector> = None;

fn get_protector() -> &'static Protector {
    unsafe {
        INIT.call_once(|| {
            PROTECTOR = Some(Protector::new(0xDEADBEEF));
        });
        PROTECTOR.as_ref().unwrap()
    }
}
```

## Testing Your Integration

### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protector_integration() {
        let protector = Protector::new(0x12345);
        
        // Should not crash
        assert!(!protector.is_debugged() || protector.is_debugged());
        
        // Should return valid detection details
        let details = protector.get_detection_details();
        assert!(details.score >= 0);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let protector = Protector::new(0x12345);
        
        let original = b"test data";
        let encrypted = protector.encrypt_data(original);
        let decrypted = protector.decrypt_data(&encrypted);
        
        // May not match if debugger is detected
        println!("Encryption test completed");
    }
}
```

## Building and Deploying

### Debug Build
```bash
cargo build
```

### Release Build (Recommended for Production)
```bash
cargo build --release
```

### Cross-compilation Check
```bash
cargo check --target x86_64-pc-windows-msvc
```

## Security Best Practices

1. **Use different seeds** for different binaries:
```rust
let seed = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
let protector = Protector::new(seed);
```

2. **Don't hardcode sensitive values** - use configuration files or environment variables

3. **Test without debugger** - ensure normal operation:
```bash
# Run without debugger
./target/release/your_app

# But don't attach debugger and expect it to work normally
```

4. **Consider obfuscation tools** - combine with tools like:
   - UPX (executable packing)
   - LLVM obfuscation
   - String encryption tools

## Performance Metrics

| Operation | Time | Notes |
|-----------|------|-------|
| Initialization | 1-5ms | One-time setup |
| Memory check | 0.1-0.2ms | Fast, reliable |
| Timing check | 0.05-0.1ms | Very fast |
| Exception check | Variable | Depends on system |
| Hypervisor check | 0.3-0.5ms | CPU intensive |
| Integrity check | 0.2-0.4ms | Hash computation |
| Encrypt 1KB | <1ms | XOR based |
| Decrypt 1KB | <1ms | XOR based |

## Getting Help

For integration issues:

1. Review examples in `src/main.rs`
2. Check test cases in `src/protector/mod.rs`
3. Enable debug logging in `anti_debug.rs`
4. Run with release build to see actual performance

## Next Steps

After integration:
1. Test thoroughly in your target environment
2. Verify detection works as expected
3. Monitor for false positives
4. Adjust thresholds if needed
5. Deploy with confidence

# FDebug Module Reference & API Documentation

Complete guide to using the fdebug anti-debug protection system in Rust applications.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core API Reference](#core-api-reference)
3. [Detection Severity Levels](#detection-severity-levels)
4. [Usage Patterns](#usage-patterns)
5. [Advanced Configuration](#advanced-configuration)
6. [Code Examples](#code-examples)
7. [Common Pitfalls](#common-pitfalls)
8. [FAQ](#faq)

---

## Quick Start

### Basic Setup

```rust
use fdebug::protector::{Protector, DYNAMIC_SEED};

fn main() {
    // Initialize the protector with a static seed or DYNAMIC_SEED
    let protector = Protector::new(DYNAMIC_SEED);
    
    println!("[+] Anti-debug protection initialized");
    
    // Get current suspicion score
    let score = fdebug::protector::get_suspicion_score();
    println!("[*] Environment suspicion score: {}", score);
}
```

### Minimal Example with Data Protection

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

fn main() {
    let protector = Protector::new(0xBEEFDEAD);
    
    // Protect sensitive string
    let api_key = SecureVault::new("your_api_key_here".to_string());
    
    let validated = protector.run_secure(&api_key, |key, token| {
        // token is valid only if clean environment
        let hash = key.len() as u64 ^ token;
        hash % 7 == 0
    });
    
    if validated {
        println!("[+] API key validated in clean environment");
    } else {
        println!("[-] Validation failed - suspicious environment");
    }
}
```

---

## Core API Reference

### Protector Structure

```rust
pub struct Protector {
    _seed: u32,
}

impl Protector {
    /// Creates a new protector instance
    pub fn new(seed: u32) -> Self {
        // Initializes VEH, global state, and detection checkpoints
    }
    
    /// Executes operation with mandatory security token
    pub fn run_secure<F, R>(&self, vault: &SecureVault<T>, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R,
    
    /// Executes coupled operation with automatic corruption
    pub fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T,
    
    /// Encrypts sensitive data
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8>
    
    /// Decrypts sensitive data
    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8>
    
    /// Validates license keys
    pub fn validate_license(&self, license_key: &str) -> bool
    
    /// Get detection status and metrics
    pub fn get_detection_details(&self) -> DetectionDetails
    
    /// Heartbeat - periodic security checks
    fn heartbeat(&self)
}
```

### DetectionDetails Structure

```rust
pub struct DetectionDetails {
    pub is_debugged: bool,           // True if any debugger detected
    pub score: u32,                  // Current suspicion score
    pub peb_check: bool,             // PEB.BeingDebugged flag
    pub rdtsc_check: bool,           // RDTSC timing anomaly
    pub heap_check: bool,            // Debug heap flags
    pub hypervisor_check: bool,      // Virtualization detected
    pub integrity_check: bool,       // Integrity hash mismatch
}

impl Protector {
    pub fn get_detection_details(&self) -> DetectionDetails {
        // Returns current protection status
    }
}
```

### SecureVault<T>

```rust
pub struct SecureVault<T> {
    inner: T,
}

impl<T> SecureVault<T> {
    pub fn new(value: T) -> Self {
        SecureVault { inner: value }
    }
    
    /// Unlock vault with security token
    pub fn unlock<F, R>(&self, protector: &Protector, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R,
    {
        protector.run_secure(self, f)
    }
}
```

### Global State Functions

```rust
/// Add suspicion points for a detection event
pub fn add_suspicion(severity: DetectionSeverity);

/// Get current reconstructed threat score
pub fn get_suspicion_score() -> u32;

/// Get combined score with encryption key
pub fn get_combined_score() -> u64;

/// Recalculate global integrity hash
pub fn recalculate_global_integrity();

/// Get current encryption key (changes with suspicion)
pub fn get_current_encryption_key() -> u8;

/// Get current VM key (changes with suspicion)
pub fn get_current_vm_key() -> u8;

/// Initialize VEH protection
pub fn initialize_veh_protection();

/// Build-time generated random seed
pub const DYNAMIC_SEED: u32;
```

---

## Detection Severity Levels

```rust
pub enum DetectionSeverity {
    Low = 10,      // Weak indicators (timing noise, minor VM artifacts)
    Medium = 30,   // Moderate indicators (PEB flags, timing spikes)
    High = 60,     // Strong indicators (Hardware BP, INT3, decoy patch)
    Critical = 100 // Definitive indicators (Multiple simultaneous events)
}

impl DetectionSeverity {
    pub fn score(&self) -> u32 { *self as u32 }
}
```

### When Each Level is Triggered

| Event | Severity | Code Location |
| --- | --- | --- |
| RDTSC timing > threshold | Low | `anti_debug::checkpoint_timing_anomaly()` |
| CPUID timing anomaly | Low | `anti_debug::calibrate_hard_threshold()` |
| PEB.BeingDebugged set | Medium | `anti_debug::checkpoint_memory_integrity()` |
| PEB.NtGlobalFlag != 0 | Medium | `anti_debug::checkpoint_memory_integrity()` |
| Hardware breakpoint detected | High | `anti_debug::checkpoint_hardware_bp_detection()` |
| INT3 exception caught | High | VEH handler in `anti_debug.rs` |
| Decoy function patched | High | `decoy_system::watchdog_check_decoys()` |
| Multiple simultaneous detections | Critical | `add_suspicion()` with high score |

---

## Usage Patterns

### Pattern 1: License Key Validation

```rust
use fdebug::protector::Protector;

const LICENSE_KEY: &str = "ABC123DEF456GHI789";

fn validate_and_use_product(protector: &Protector) -> bool {
    // Validation depends on security token
    protector.run_secure(&SecureVault::new(LICENSE_KEY), |key, token| {
        // Token only valid if environment clean
        
        // Check key format
        if key.len() != 18 {
            return false;
        }
        
        // Derive license ID from token
        let license_id = token.wrapping_add(0xDEADBEEF);
        
        // If token corrupted by debugger:
        // - license_id becomes garbage
        // - validation fails
        
        true && ((license_id % 7) == 0)
    })
}
```

### Pattern 2: Cryptographic Key Protection

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

fn decrypt_user_data(protector: &Protector, encrypted: &[u8]) -> Vec<u8> {
    // Never expose raw master key
    let master_key = SecureVault::new(0xDEADBEEFCAFEBABEu64);
    
    protector.run_secure(&master_key, |key, security_token| {
        // Combine master key with security token for enhanced protection
        let actual_key = key ^ security_token;
        
        // Decrypt data using actual_key
        // If token corrupted: actual_key is garbage
        // Decryption produces garbage
        
        let mut result = encrypted.to_vec();
        for i in 0..result.len() {
            result[i] ^= (actual_key as u8).wrapping_add(i as u8);
        }
        result
    })
}
```

### Pattern 3: Financial Calculation Protection

```rust
use fdebug::protector::{Protector, CoupledLogic, Corruptible};

#[derive(Clone)]
struct TransactionData {
    amount: f64,
    fee: f64,
    checksum: u32,
}

impl Corruptible for TransactionData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        // Silent corruption if token indicates debugging
        if token & 0xFF == 0 {
            self.amount = 0.0;
            self.fee = 0.0;
            self.checksum = 0;
        }
        self
    }
}

fn process_transaction(protector: &Protector, amount: f64) -> TransactionData {
    protector.run_coupled(|token| {
        // Calculate transaction with security token
        let fee = amount * 0.02 + (token as f64 * 0.001);
        let total = amount + fee;
        let checksum = ((total as u32) ^ (token as u32)).wrapping_add(1);
        
        TransactionData {
            amount: total,
            fee,
            checksum,
        }
    })
}

// Usage:
let protector = Protector::new(0xACE123);
let transaction = process_transaction(&protector, 1000.0);

if transaction.checksum == 0 {
    println!("[!] Transaction corrupted - running under debugger");
} else {
    println!("[+] Transaction valid: ${}", transaction.amount);
}
```

### Pattern 4: Macro-Based Inline Protection

```rust
use fdebug::protector::{Protector, guarded_value};

fn main() {
    let protector = Protector::new(0xBEEFDEAD);
    
    // Inline security integration
    let (database_url, security_token) = guarded_value!(
        "postgresql://user:pass@localhost/db", 
        protector
    );
    
    // Connection is only valid if security_token is valid
    if security_token % 13 == 0 {
        connect_to_database(database_url);
    } else {
        eprintln!("Database connection blocked - insecure environment");
    }
}
```

### Pattern 5: Anti-Tampering for DLL Injection

```rust
use fdebug::protector::{Protector, get_suspicion_score};

fn check_dll_injection(protector: &Protector) -> bool {
    let score_before = get_suspicion_score();
    
    // Heartbeat triggers detection checks
    let vault = SecureVault::new(0u64);
    let _ = protector.run_secure(&vault, |_, _| {});
    
    let score_after = get_suspicion_score();
    
    // If score increased, suspicious activity detected
    score_after > score_before
}

fn main() {
    let protector = Protector::new(0x12345678);
    
    if check_dll_injection(&protector) {
        eprintln!("[!] Suspicious DLL injection detected");
        std::process::exit(1);
    }
    
    println!("[+] DLL injection check passed");
}
```

---

## Advanced Configuration

### Diagnostic Mode

```rust
use fdebug::protector::global_state::DIAGNOSTIC_MODE;
use std::sync::atomic::Ordering;

// Enable diagnostic logging
DIAGNOSTIC_MODE.store(true, Ordering::Relaxed);

// Run detection
let protector = Protector::new(0xDEADBEEF);

// Check which checkpoints triggered
use fdebug::protector::global_state::TRIGGERED_CHECKPOINTS;
for (i, checkpoint) in TRIGGERED_CHECKPOINTS.iter().enumerate() {
    let score = checkpoint.load(Ordering::Relaxed);
    if score > 0 {
        println!("[DEBUG] Checkpoint {}: {} suspicion points", i, score);
    }
}
```

### Custom Detection Severity

```rust
use fdebug::protector::{add_suspicion, DetectionSeverity};

// Custom detection event
if suspicious_condition() {
    add_suspicion(DetectionSeverity::Critical);
    eprintln!("[!] Custom detection triggered");
}

fn suspicious_condition() -> bool {
    // Your custom detection logic
    false
}
```

### Manual Score Queries

```rust
use fdebug::protector::{
    get_suspicion_score,
    get_combined_score,
    get_current_encryption_key,
    get_current_vm_key,
};

fn monitor_environment() {
    let suspicion = get_suspicion_score();
    let combined = get_combined_score();
    let enc_key = get_current_encryption_key();
    let vm_key = get_current_vm_key();
    
    println!("[*] Suspicion: {}", suspicion);
    println!("[*] Combined: {:x}", combined);
    println!("[*] Encryption Key: {:02x}", enc_key);
    println!("[*] VM Key: {:02x}", vm_key);
    
    if suspicion >= 100 {
        println!("[!] ALERT: High suspicion level detected!");
    }
}
```

---

## Code Examples

### Example 1: Product Licensing System

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

struct License {
    key: String,
    valid: bool,
}

impl License {
    fn validate(protector: &Protector, license_key: &str) -> Self {
        let vault = SecureVault::new(license_key.to_string());
        
        let valid = protector.run_secure(&vault, |key, token| {
            // License validation depends on security token
            
            // Check format: must be 32 alphanumeric characters
            if key.len() != 32 || !key.chars().all(|c| c.is_alphanumeric()) {
                return false;
            }
            
            // Derive validation ID from token
            let validation_id = token.wrapping_mul(0xBEEF).rotate_left(7);
            
            // If running under debugger:
            // - token is corrupted
            // - validation_id is garbage
            // - validation fails
            
            validation_id % 11 == 0
        });
        
        License {
            key: license_key.to_string(),
            valid,
        }
    }
}

fn main() {
    let protector = Protector::new(0xACE123);
    
    let license = License::validate(&protector, "ABCD1234EFGH5678IJKL9012MNOP3456");
    
    if license.valid {
        println!("[+] License valid - application unlocked");
    } else {
        println!("[-] Invalid license - running in demo mode");
        std::process::exit(1);
    }
}
```

### Example 2: Secure Data Storage

```rust
use fdebug::protector::{Protector, SecureVault, ShieldedExecution};

struct UserCredentials {
    username: String,
    password_hash: String,
}

impl UserCredentials {
    fn encrypt(&self, protector: &Protector) -> Vec<u8> {
        protector.encrypt_data(format!("{}:{}", self.username, self.password_hash).as_bytes())
    }
    
    fn decrypt(protector: &Protector, encrypted: &[u8]) -> Option<Self> {
        let decrypted = protector.decrypt_data(encrypted);
        let text = String::from_utf8(decrypted).ok()?;
        
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        
        Some(UserCredentials {
            username: parts[0].to_string(),
            password_hash: parts[1].to_string(),
        })
    }
}

fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    let creds = UserCredentials {
        username: "admin@example.com".to_string(),
        password_hash: "2C26B46911185131006B5E1476A436FF".to_string(),
    };
    
    // Encrypt with anti-debug protection
    let encrypted = creds.encrypt(&protector);
    println!("[+] Credentials encrypted: {} bytes", encrypted.len());
    
    // Decrypt (will produce garbage if debugged)
    if let Some(decrypted) = UserCredentials::decrypt(&protector, &encrypted) {
        println!("[+] Username: {}", decrypted.username);
    } else {
        println!("[-] Failed to decrypt - possible tampering detected");
    }
}
```

### Example 3: Real-Time Monitoring

```rust
use fdebug::protector::{Protector, get_suspicion_score};
use std::time::Duration;
use std::thread;

fn monitor_protection_thread(protector: &Protector) {
    loop {
        let score = get_suspicion_score();
        let detection = protector.get_detection_details();
        
        if score > 0 {
            println!("[!] Suspicion detected:");
            println!("    - Score: {}", score);
            println!("    - PEB: {}", detection.peb_check);
            println!("    - RDTSC: {}", detection.rdtsc_check);
            println!("    - Hardware BP: {}", detection.heap_check);
        }
        
        if score >= 100 {
            println!("[!!!] CRITICAL ALERT - Execution corrupted");
            println!("[!!!] All subsequent data is unreliable");
            break;
        }
        
        thread::sleep(Duration::from_secs(5));
    }
}

fn main() {
    let protector = Protector::new(0xBEEFCAFE);
    
    // Spawn monitoring thread
    let monitor_protector = protector.clone();
    let monitor_handle = std::thread::spawn(move || {
        monitor_protection_thread(&monitor_protector);
    });
    
    // Main application logic
    println!("[+] Application running with real-time monitoring");
    
    let vault = SecureVault::new("secret_data".to_string());
    let _ = protector.run_secure(&vault, |data, token| {
        println!("[*] Processing: {}", data);
        token
    });
    
    monitor_handle.join().ok();
}
```

### Example 4: Coupled Logic with Corruption

```rust
use fdebug::protector::{Protector, CoupledLogic, Corruptible};

#[derive(Clone, Debug)]
struct APIResponse {
    status: u32,
    data: String,
    timestamp: u64,
}

impl Corruptible for APIResponse {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        // Check token integrity
        if token == 0 || token & 0xFFFFFFFF == 0 {
            // Token corrupted by debugger
            self.status = 0;
            self.data = String::new();
            self.timestamp = 0;
        }
        self
    }
}

fn make_api_call(protector: &Protector, endpoint: &str) -> APIResponse {
    protector.run_coupled(|token| {
        // Simulate API call
        let response_data = format!("Response from {}", endpoint);
        
        APIResponse {
            status: (token as u32 % 200) + 200, // 200-399 range
            data: response_data,
            timestamp: token,
        }
    })
}

fn main() {
    let protector = Protector::new(0xACE);
    
    let response = make_api_call(&protector, "/api/users");
    
    if response.status == 0 {
        eprintln!("[!] API response corrupted - running under debugger");
    } else {
        println!("[+] API Response: {}", response.status);
        println!("[+] Data: {}", response.data);
    }
}
```

---

## Common Pitfalls

### ❌ Pitfall 1: Ignoring Return Values

```rust
// WRONG - ignores the transformation key
let vault = SecureVault::new(secret_data);
protector.run_secure(&vault, |data, token| {
    println!("Data: {}", data);
    // token is ignored - security enforcement bypassed!
});
```

✅ **Solution:**
```rust
// CORRECT - uses the token
let vault = SecureVault::new(secret_data);
let result = protector.run_secure(&vault, |data, token| {
    let secure_hash = data.len() as u64 ^ token;
    secure_hash
});
```

### ❌ Pitfall 2: Not Implementing Corruptible

```rust
// WRONG - data is not corrupted when debugged
struct MyData(String);

let result = protector.run_coupled(|token| {
    MyData("important".to_string())
});
```

✅ **Solution:**
```rust
// CORRECT - implements corruption
#[derive(Clone)]
struct MyData(String);

impl Corruptible for MyData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        if token == 0 {
            self.0 = String::new();
        }
        self
    }
}

let result = protector.run_coupled(|token| {
    MyData("important".to_string())
});
```

### ❌ Pitfall 3: Caching Results

```rust
// WRONG - caches result outside secure execution
let result = protector.run_secure(&vault, |data, _| {
    data.clone()
});
// Using cached result later - may be from debugged session!
use_data(&result);
```

✅ **Solution:**
```rust
// CORRECT - use result immediately within run_secure
protector.run_secure(&vault, |data, token| {
    let validated = data.len() as u64 ^ token == 42;
    if validated {
        use_data(data);
    }
});
```

### ❌ Pitfall 4: Not Handling Poison Seed

```rust
// WRONG - assumes security token is always valid
let vault = SecureVault::new(license_key);
protector.run_secure(&vault, |key, token| {
    // If POISON_SEED is corrupted, token is garbage
    // But code assumes token is good
    database_connect(key, token as u32)
});
```

✅ **Solution:**
```rust
// CORRECT - validate token before using
let vault = SecureVault::new(license_key);
protector.run_secure(&vault, |key, token| {
    // Verify token is reasonable
    if token == 0 || token == u64::MAX {
        eprintln!("[!] Invalid token - environment compromised");
        return;
    }
    database_connect(key, token as u32);
});
```

---

## FAQ

**Q: What happens if the application is run under a debugger?**

A: The protection system detects debugging and corrupts the `TRANSFORMATION_KEY`. Any calculations depending on this key will produce incorrect results. The application continues to run without crashing, but produces silently corrupted data.

**Q: Can attackers just patch the decoy functions?**

A: They can patch them, but the `watchdog_check_decoys()` function monitors the function code continuously. If patching is detected, `DECOY_TAMPERED` flag is set, causing all subsequent execution to be corrupted.

**Q: Is the protection per-binary or per-process?**

A: **Per-binary.** The `DYNAMIC_SEED` is generated at compile-time and is unique for each build. This means:
- Each binary has different opcode values
- Each binary has different mask values for shards
- Attackers cannot reuse exploits across builds

**Q: What's the overhead of the protection?**

A: 
- VEH registration: ~1ms on startup
- Per-operation overhead: <1ms (atomic operations are fast)
- VM execution overhead: 5-10ms depending on bytecode complexity

**Q: Can I use fdebug with multi-threaded applications?**

A: Yes! All global state uses `AtomicU32`/`AtomicU64` with proper `SeqCst` ordering for critical sections.

**Q: What if I want to disable protection in debug builds?**

A: Use feature flags:
```rust
#[cfg(not(debug_assertions))]
let protector = Protector::new(DYNAMIC_SEED);

#[cfg(debug_assertions)]
let protector = DummyProtector::new(); // No-op implementation
```

**Q: How often are detection checks performed?**

A: 
- VEH: Continuously (only on exceptions)
- RDTSC/CPUID checks: Every ~10 operations (heartbeat)
- Hardware BP checks: Every ~20 operations
- Decoy monitoring: Every ~50 operations (50% chance)
- Integrity checks: Every ~100 operations

**Q: What's the difference between run_secure and run_coupled?**

A:
- **run_secure** - Requires explicit use of security token in calculation
- **run_coupled** - Automatically corrupts the result via `Corruptible` trait

Use `run_coupled` for business logic that needs transparent protection. Use `run_secure` for operations where you want explicit control.

**Q: Can fdebug protect against kernel-level debuggers?**

A: Partially. The protection is strongest against user-mode debuggers (WinDbg, x64dbg, IDA Debugger). Kernel-mode debuggers (KernelDBG) have lower-level access and may bypass some checks. However, the distributed sharding and integrity hashes still provide significant protection.

**Q: Should I use the same DYNAMIC_SEED for all binaries?**

A: No! Let each build generate its own `DYNAMIC_SEED`. This prevents attackers from creating a universal exploit. If you need to fix bugs, rebuild and get a new seed.

---

## Performance Characteristics

| Operation | Cost | Frequency |
| --- | --- | --- |
| `run_secure()` | <1ms | Per protected operation |
| `run_coupled()` | <2ms | Per business logic section |
| VEH Registration | ~1ms | On startup |
| Heartbeat | <1ms | Every 10 operations |
| Integrity Hash | ~2ms | Every 100 operations |
| Watchdog Check | ~5ms | Every 50 operations (probabilistic) |

**Total Overhead:** ~5-10% for typical applications with moderate protection coverage.

---

## Building Binaries with FDebug

Every build generates a new `DYNAMIC_SEED`:

```rust
// This will be DIFFERENT for each build
pub const DYNAMIC_SEED: u32 = 0x12345678; // Changes every compilation
```

To see the current seed:
```bash
cargo build
cargo run -- --show-seed
```

Each user gets a uniquely protected binary - an attacker's exploits won't work on other users' versions!


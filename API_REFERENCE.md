# API Reference - Anti-Debug Protection Module

## Core Structures

### `Protector`

The main protection structure that manages all detection and encryption operations.

```rust
pub struct Protector {
    seed: u32,
}
```

#### Methods

##### `new(seed: u32) -> Self`

Creates a new Protector instance with the given seed value.

**Parameters:**
- `seed` (u32): A seed value that influences the polymorphic opcode generation

**Returns:** A new Protector instance

**Example:**
```rust
let protector = Protector::new(0x12345678);
```

**Windows-Only Note:** On Windows, this automatically initializes the VEH protection system on first call.

---

##### `is_debugged(&self) -> bool`

Checks if a debugger is currently detected.

**Returns:** 
- `true` if debugger is detected
- `false` if no debugger is detected

**Detection Methods Used:**
- Memory integrity check (PEB flags)
- Timing anomaly detection
- Exception handling checks
- Hypervisor detection

**Example:**
```rust
let protector = Protector::new(0xDEADBEEF);
if protector.is_debugged() {
    println!("Debugger detected!");
    std::process::exit(1);
}
```

**Performance:** ~0.5-2ms depending on active checks

---

##### `get_detection_details(&self) -> DetectionDetails`

Returns detailed information about all detection checks.

**Returns:** `DetectionDetails` structure containing:

```rust
pub struct DetectionDetails {
    pub is_debugged: bool,           // Overall debug detection
    pub score: u32,                  // Total suspicion score (0-200+)
    pub peb_check: bool,             // PEB-based detection result
    pub rdtsc_check: bool,           // Timing-based detection result
    pub heap_check: bool,            // Exception handler result
    pub hypervisor_check: bool,      // Virtualization detection result
    pub integrity_check: bool,       // Code integrity check result
}
```

**Example:**
```rust
let protector = Protector::new(0x12345678);
let details = protector.get_detection_details();

println!("Debugged: {}", details.is_debugged);
println!("Suspicion Score: {}", details.score);
println!("PEB Check: {}", details.peb_check);
println!("RDTSC Check: {}", details.rdtsc_check);
println!("Exception Check: {}", details.heap_check);
println!("Hypervisor Check: {}", details.hypervisor_check);
println!("Integrity Check: {}", details.integrity_check);
```

---

##### `encrypt_data(&self, plaintext: &[u8]) -> Vec<u8>`

Encrypts data using XOR cipher with automatic debug checks.

**Parameters:**
- `plaintext` (&[u8]): Data to encrypt

**Returns:** Encrypted data as Vec<u8>

**Automatic Checks Performed:**
- Memory integrity checkpoint
- Code integrity checkpoint
- If debugger detected, encryption key is corrupted → result is unusable

**Example:**
```rust
let protector = Protector::new(0xDEADBEEF);
let plaintext = b"Secret message";
let encrypted = protector.encrypt_data(plaintext);

println!("Encrypted data: {:?}", encrypted);
```

**Security Note:** If debugger is detected, the encryption key becomes corrupted (0xFF), making the encrypted data invalid.

---

##### `decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8>`

Decrypts data using XOR cipher with automatic debug checks.

**Parameters:**
- `ciphertext` (&[u8]): Data to decrypt

**Returns:** Decrypted data as Vec<u8>

**Automatic Checks Performed:**
- Exception handling checkpoint
- Code integrity checkpoint
- If debugger detected, decryption key is corrupted → result is invalid

**Example:**
```rust
let protector = Protector::new(0xDEADBEEF);
let ciphertext = &[/* encrypted bytes */];
let decrypted = protector.decrypt_data(ciphertext);

println!("Decrypted data: {:?}", decrypted);
```

**Security Note:** If debugger was detected during any previous operation, decryption will fail silently.

---

##### `validate_license(&self, license_key: &str) -> bool`

Validates a license key with automatic timing anomaly checks.

**Parameters:**
- `license_key` (&str): The license key to validate

**Returns:**
- `true` if license is valid and no debugger detected
- `false` if license is invalid or debugger detected

**Validation Rules:**
- License key must be exactly 32 characters
- All characters must be ASCII alphanumeric

**Automatic Checks Performed:**
- Timing anomaly checkpoint
- Code integrity checkpoint
- If debugger detected, validation key is corrupted → returns false

**Example:**
```rust
let protector = Protector::new(0x12345678);
let license = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

if protector.validate_license(license) {
    println!("License is valid!");
} else {
    println!("License validation failed");
}
```

---

## Global Functions

### `is_globally_debugged() -> bool`

Checks the global debug state across all threads.

**Returns:** `true` if any thread has detected a debugger

**Platform Support:** Windows only (returns `false` on other platforms)

**Example:**
```rust
use protector::is_globally_debugged;

if is_globally_debugged() {
    println!("Debugger detected in current process");
}
```

---

### `get_suspicion_score() -> u32`

Returns the current global suspicion score.

**Returns:** Suspicion score (0-255+)

**Scoring Rules:**
- PEB detection: +50 per detection
- Timing anomaly: +30 per detection
- Exception handler: +40 per detection
- Hypervisor: +10-30 per detection
- Code integrity: +70 per detection

**Example:**
```rust
use protector::get_suspicion_score;

let score = get_suspicion_score();
if score > 100 {
    println!("High suspicion: {}", score);
}
```

---

### `add_suspicion(score: u32, checkpoint_type: usize)`

Manually adds suspicion points (for custom checks).

**Parameters:**
- `score` (u32): Points to add
- `checkpoint_type` (usize): Category of suspicion:
  - 0: PEB checks
  - 1: Timing checks
  - 2: Exception checks
  - 3: Hypervisor checks
  - 4: Integrity checks

**Example:**
```rust
use protector::add_suspicion;

// Add custom detection
if suspicious_condition {
    add_suspicion(25, 0);  // Add to PEB category
}
```

---

## Detection Checkpoint Functions

These functions perform individual detection checks and return immediate results.

### `checkpoint_memory_integrity() -> bool`

Performs PEB-based memory integrity check.

**Returns:** `true` if suspicious activity detected

**Detects:** Debugger through PEB flags and NtGlobalFlag values

**Performance:** ~0.1-0.2ms

---

### `checkpoint_timing_anomaly() -> bool`

Performs RDTSC-based timing anomaly detection.

**Returns:** `true` if timing anomalies detected

**Detects:** Debugger interference with instruction timing

**Performance:** ~0.05-0.1ms

---

### `checkpoint_exception_handling() -> bool`

Performs vectored exception handler monitoring.

**Returns:** `true` if exception hooks detected

**Detects:** Breakpoint installation and exception hooks

**Performance:** ~0.2-0.5ms

---

### `checkpoint_hypervisor_detection() -> bool`

Performs hypervisor/virtualization detection.

**Returns:** `true` if hypervisor detected

**Detects:** VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels

**Performance:** ~0.3-0.5ms

**Note:** Has higher false positive rate in cloud environments

---

### `checkpoint_integrity_self_hash() -> bool`

Performs runtime code integrity verification.

**Returns:** `true` if code tampering detected

**Detects:** Memory modification of critical code sections

**Performance:** ~0.2-0.4ms

---

## Configuration Constants

These can be modified in `src/protector/anti_debug.rs`:

```rust
// RDTSC threshold in CPU cycles
const RDTSC_FALLBACK_THRESHOLD: u64 = 100;

// Enable/disable silent corruption mode
const DATA_CORRUPTION_MODE: bool = true;

// Enable/disable VEH-based detection
const ENABLE_VEH_DETECTION: bool = true;

// Enable/disable runtime integrity checks
const ENABLE_INTEGRITY_CHECK: bool = true;

// Maximum acceptable baseline delta during calibration
const CALIBRATION_SANITY_MAX: u64 = 1000;
```

---

## Error Handling

The module does not throw exceptions. Instead:

1. **Invalid Input**: Silently handled with safe defaults
2. **Debugger Detection**: Returns false/corrupts keys (silent corruption mode)
3. **Permission Errors**: Returns false (continues execution)

**Example:**
```rust
let protector = Protector::new(0x12345);

// Will not panic, but may return false/corrupted data
let encrypted = protector.encrypt_data(&[]);
let decrypted = protector.decrypt_data(&[]);
let valid = protector.validate_license("");
```

---

## Thread Safety

The module uses atomic variables for thread-safe state management:

- Detection state is shared across threads
- All operations are atomic
- No mutex locks (lock-free design)

**Example:**
```rust
use std::sync::Arc;
use std::thread;

let protector = Arc::new(Protector::new(0xDEADBEEF));

for i in 0..4 {
    let p = Arc::clone(&protector);
    thread::spawn(move || {
        // All threads see the same detection state
        if p.is_debugged() {
            println!("Thread {} detected debugger", i);
        }
    });
}
```

---

## Platform-Specific Behavior

### Windows (x86_64)
- Full detection support
- All checkpoints active
- VEH initialization on first use

### Other Platforms
```rust
// Dummy implementations
pub struct Protector {
    _seed: u32,
}

impl Protector {
    pub fn new(seed: u32) -> Self { /* ... */ }
    pub fn is_debugged(&self) -> bool { false }  // Always false
    pub fn get_detection_details(&self) -> DetectionDetails { /* empty details */ }
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> { plaintext.to_vec() }
    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> { ciphertext.to_vec() }
    pub fn validate_license(&self, license_key: &str) -> bool { 
        license_key.len() == 32 && license_key.chars().all(|c| c.is_ascii_alphanumeric())
    }
}
```

---

## Macro

### `setup_anti_debug!(seed)`

Convenience macro for quick initialization.

**Example:**
```rust
use fuckDebug::setup_anti_debug;

let protector = setup_anti_debug!(0x12345678);
```

---

## Performance Characteristics

| Operation | Time | Overhead |
|-----------|------|----------|
| `new()` | 1-5ms | One-time |
| `is_debugged()` | 0.5-2ms | Per call |
| `get_detection_details()` | 1-3ms | Per call |
| `encrypt_data()` 1KB | <1ms | Fast |
| `decrypt_data()` 1KB | <1ms | Fast |
| `validate_license()` | 0.1-0.3ms | Fast |

---

## Memory Usage

| Structure | Size | Notes |
|-----------|------|-------|
| Protector | 4 bytes | Just seed |
| DetectionDetails | 28 bytes | Static, on stack |
| Global state | ~64 bytes | Atomic variables |

---

## Version History

- **v0.1.0** - Initial release
  - Multi-layer detection
  - Silent corruption mode
  - Thread-safe state management

---

## Backwards Compatibility

- API is stable and unlikely to change
- Configuration constants can be adjusted safely
- Detection thresholds can be tuned per deployment

---

## FAQ

**Q: Why doesn't `is_debugged()` detect kernel debuggers?**
A: It only monitors user-mode indicators. Kernel debuggers require different detection mechanisms.

**Q: Can I disable specific detection checkpoints?**
A: Yes, modify the constants in `anti_debug.rs` and rebuild.

**Q: What happens if the debugger attaches after initialization?**
A: Subsequent calls to any method will detect the new debugger via checkpoints.

**Q: Is the module thread-safe?**
A: Yes, all state is managed with atomic variables (lock-free).

**Q: Can I use the module in release builds?**
A: Yes, it's designed for release builds. Performance impact is minimal.

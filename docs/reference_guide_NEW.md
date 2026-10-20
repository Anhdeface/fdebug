# fuckDebug Module Reference & API Documentation

> **Complete API & Technical Reference for the `fuckDebug` Protection Engine**  
> *Windows x86_64 Anti-Debugging, Memory Stealth, Polymorphic Virtualization, and Decentralized Integrity*

---

## Table of Contents

1. [Crate Configuration & Quick Start](#1-crate-configuration--quick-start)
2. [Core API Reference](#2-core-api-reference)
   - [Mandatory Initialization Macro (`setup_anti_debug!`)](#mandatory-initialization-macro-setup_anti_debug)
   - [Dynamic Seed Orchestrator (`get_dynamic_seed`)](#dynamic-seed-orchestrator-get_dynamic_seed)
   - [Protector Engine (`Protector`)](#protector-engine-protector)
   - [Vault Storage (`SecureVault<T>`)](#vault-storage-securevaultt)
   - [Coupled Logic Trait (`CoupledLogic<T>` & `Corruptible`)](#coupled-logic-trait-coupledlogict--corruptible)
   - [Decentralized Suspicion Management](#decentralized-suspicion-management)
3. [Memory & Buffer Management](#3-memory--buffer-management)
   - [Stack-Allocated Buffer (`SecureBuffer<N>`)](#stack-allocated-buffer-securebuffern)
   - [Zero-Static-Trace Strings (`dynamic_str!`)](#zero-static-trace-strings-dynamic_str)
4. [Detection Severity Levels](#4-detection-severity-levels)
5. [Anti-Dump & Memory Stealth APIs](#5-anti-dump--memory-stealth-apis)
6. [Internal Primitives & Security Boundaries](#6-internal-primitives--security-boundaries)
7. [Usage Patterns & Code Examples](#7-usage-patterns--code-examples)
8. [Formal Verification Suite Commands](#8-formal-verification-suite-commands)
9. [Common Pitfalls & Best Practices](#9-common-pitfalls--best-practices)
10. [FAQ](#10-faq)

---

## 1. Crate Configuration & Quick Start

### 1.1 Cargo Dependency Setup

The canonical crate name is **`fuckDebug`**.

```toml
# Cargo.toml
[dependencies]
fuckDebug = { path = "../fuckDebug" }
```

If your project conventions require referencing the crate as `fdebug`, Cargo package aliasing provides seamless renaming:

```toml
# Cargo.toml with aliasing
[dependencies]
fdebug = { package = "fuckDebug", path = "../fuckDebug" }
```

### 1.2 Quick Start

The standard and only approved method to instantiate the protection engine is via the `setup_anti_debug!` macro paired with `get_dynamic_seed()`:

```rust
use fuckDebug::protector::{setup_anti_debug, get_dynamic_seed, get_suspicion_score};

fn main() {
    // 1. Mandatory initialization via macro
    // Dynamically reconstructs seed and configures VEH, Anti-Dump, and Decoys
    let seed = get_dynamic_seed();
    let protector = setup_anti_debug!(seed);
    
    println!("[+] fuckDebug initialized with dynamic seed: 0x{:08X}", seed);
    
    // 2. Query environment suspicion score
    let score = get_suspicion_score();
    println!("[*] Environment suspicion score: {}", score);
}
```

---

## 2. Core API Reference

### Mandatory Initialization Macro (`setup_anti_debug!`)

```rust
#[macro_export]
macro_rules! setup_anti_debug {
    ($seed:expr) => { ... }
}
```

The **only recommended method** to construct a `Protector` instance.
- **Arguments**: A `u32` seed (typically from `get_dynamic_seed()`).
- **Initialization Sequence**:
  1. Computes baseline `.text` section checksum and initializes the PE shard table (`pe_integrity::heartbeat_check(0)`).
  2. Registers the 5-phase Master VEH (`enhanced_veh::init_master_veh()`) with strict TEB stack limits (`gs:[0x08]`/`gs:[0x10]`), `frames_walked >= 2` unwinding, and bounded re-entrancy depth guard ($\text{depth} \le 1$).
  3. Scans decoy function prologues and records trusted baseline checksums (`decoy_system::init_decoy_system()`).
  4. Deploys lock-free atomic decoy tracking table (`anti_dump::register_decoy_region`), sets up 64-byte 16-aligned indirect syscall resolution (`SYSCALL_STACK_RESERVED_BYTES = 0x40`), and applies surgical PE NT header obfuscation (`anti_dump::init_anti_dump()`).
  5. Returns an initialized `Protector` instance.

---

### Dynamic Seed Orchestrator (`get_dynamic_seed`)

```rust
/// Reconstructs the 32-bit dynamic seed by mixing build-time entropy,
/// CPUID processor fingerprint, and PE code section integrity checksum.
pub fn get_dynamic_seed() -> u32;

/// 8-bit truncated dynamic seed variant for byte-level operations.
pub fn get_dynamic_seed_u8() -> u8;
```

- **Thread-Safety**: Cached in a `OnceLock<u32>`. Evaluated only once per process execution.
- **Performance**: Initial computation completes in 50–100 microseconds; subsequent calls read cached memory in 1–10 nanoseconds.

---

### Protector Engine (`Protector`)

```rust
pub struct Protector {
    _seed: u32,
}

impl Protector {
    /// Manual constructor. Note: Prefer setup_anti_debug!(seed) for guaranteed initialization.
    pub fn new(seed: u32) -> Self;
    
    /// Executes operation with access to vaulted data and a dynamic TRANSFORMATION_KEY.
    pub fn run_secure<F, R>(&self, vault: &SecureVault<T>, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R;
    
    /// Executes coupled operation with automatic context-aware corruption.
    pub fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T;
    
    /// Encrypts sensitive data using the dynamic runtime key.
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8>;
    
    /// Decrypts sensitive data using the dynamic runtime key.
    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8>;
    
    /// Validates license keys by coupling validation with environmental health.
    pub fn validate_license(&self, license_key: &str) -> bool;
    
    /// Returns detailed detection status metrics.
    pub fn get_detection_details(&self) -> DetectionDetails;
}
```

---

### DetectionDetails Structure

```rust
#[derive(Debug, Clone, Copy)]
pub struct DetectionDetails {
    pub is_debugged: bool,       // True if suspicion score > 50
    pub score: u32,              // Reconstructed threat score (0..500, or 0xFFFFFFFF)
    pub peb_check: bool,         // True if score > 20
    pub rdtsc_check: bool,       // True if score > 30
    pub heap_check: bool,        // True if score > 40
    pub hypervisor_check: bool,  // True if score > 60
    pub integrity_check: bool,   // True if score > 80
}
```

---

### Vault Storage (`SecureVault<T>`)

```rust
pub struct SecureVault<T> {
    inner: T,
}

impl<T> SecureVault<T> {
    /// Creates a new secure vault container.
    pub fn new(value: T) -> Self;
    
    /// Unlocks the vault by proving security state through the Protector.
    pub fn unlock<F, R>(&self, protector: &Protector, f: F) -> R
    where
        F: FnOnce(&T, u64) -> R,
    {
        protector.run_secure(self, f)
    }
}
```

---

### Coupled Logic Trait (`CoupledLogic<T>` & `Corruptible`)

```rust
pub trait CoupledLogic<T> {
    fn run_coupled<F>(&self, operation: F) -> T
    where
        F: FnOnce(u64) -> T;
}

pub trait Corruptible {
    fn corrupt_if_needed(self, token: u64) -> Self;
}
```

Implemented natively for `String`, `Vec<u8>`, `bool`, `u32`, and `f64`. Custom business logic structures implement `Corruptible` to mutate values automatically when `token` indicates an untrusted environment.

---

### Decentralized Suspicion Management

```rust
/// Adds suspicion points to the decentralized 128-shard state.
pub fn add_suspicion(severity: DetectionSeverity);

/// Adds suspicion points and logs event to diagnostic checkpoint.
pub fn add_suspicion_at(severity: DetectionSeverity, checkpoint_id: u8);

/// Reconstructs the total threat score from the 64 Active shards.
pub fn get_suspicion_score() -> u32;

/// Reconstructs the combined security score mixing threat level and POISON_SEED.
pub fn get_combined_score() -> u64;

/// Recomputes SipHash-2-4 over reconstructed threat score and decay timestamp.
pub fn recalculate_global_integrity();

/// Validates memory state against the SipHash integrity hash.
pub fn validate_global_integrity() -> bool;

/// Triggers irreversible silent poisoning of keys, seeds, and hashes.
pub fn trigger_silent_poisoning();
```

---

## 3. Memory & Buffer Management

### Stack-Allocated Buffer (`SecureBuffer<N>`)

Stack-allocated fixed-size buffer providing volatile memory management and RAII memory scrubbing.

```rust
#[repr(C)]
pub struct SecureBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureBuffer<N> {
    /// Creates a zeroed stack buffer.
    pub const fn new() -> Self;
    
    /// Returns raw mutable pointer to buffer data.
    pub fn as_mut_ptr(&mut self) -> *mut u8;
    
    /// Returns raw immutable pointer to buffer data.
    pub fn as_ptr(&self) -> *const u8;
}

impl<const N: usize> std::ops::Deref for SecureBuffer<N> {
    type Target = [u8];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn drop(&mut self) {
        // Pass 1: Scramble buffer with pseudo-random dynamic seed garbage
        // Compiler fence (SeqCst)
        // Pass 2: Overwrite with volatile zeros
        // Unconstrained memory barrier removing options(nomem)
        unsafe {
            std::arch::asm!("", options(nostack, preserves_flags));
        }
    }
}
```

#### Usage Example:
```rust
use fuckDebug::dynamic_str;

fn read_secret() {
    // Returns SecureBuffer<N>
    let buffer = dynamic_str!("ConfidentialKey_123");
    
    // Access via Deref<Target = [u8]>
    println!("Buffer length: {}", buffer.len());
    let text = std::str::from_utf8(&buffer).unwrap_or("");
    println!("Decrypted value: {}", text);
    
    // Automatic 2-pass volatile scrubbing and hardware fence upon scope exit
}
```

---

### Zero-Static-Trace Strings (`dynamic_str!`)

```rust
#[macro_export]
macro_rules! dynamic_str {
    ($s:expr) => { ... }
}

// Backward-compatibility aliases:
#[macro_export] macro_rules! enc_str { ($s:expr) => { dynamic_str!($s) } }
#[macro_export] macro_rules! enc_string { ($s:expr) => { dynamic_str!($s) } }

/// Compile-time constant string hashing function exported publicly for macro expansion:
pub fn const_str_hash(s: &str) -> u32;

/// Hardened TinyVM 2.0 anti-trace key derangement mutation over Z_256:
pub fn anti_trace_mutate_key(key: u8) -> u8;

/// Evaluates whether the anti-trace heartbeat check is active (short program aware):
pub fn is_anti_trace_heartbeat_active(vip: usize, len: usize) -> bool;

/// Evaluates if the execution environment has been poisoned by active debuggers:
pub fn is_environment_poisoned() -> bool;
```

- Replaces static string literals in `.rdata` with TinyVM Mode H encrypted bytecode.
- Decrypts dynamically on the stack with non-linear LSB diffusion and two-phase fallback.

---

## 4. Detection Severity Levels

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionSeverity {
    Low = 10,      // Minor timing variance, non-critical VM artifacts
    Medium = 30,   // PEB flags set (BeingDebugged, NtGlobalFlag)
    High = 60,     // Hardware breakpoints (Dr0-Dr3), INT3, decoy function hooks
    Critical = 100 // Multiple simultaneous alerts, guard page dump violations
}

impl DetectionSeverity {
    pub fn score(&self) -> u32 {
        *self as u32
    }
}
```

---

## 5. Anti-Dump & Memory Stealth APIs

### Core Initialization & SSN Parsing (`anti_dump.rs`)

```rust
/// Initializes anti-dump defenses:
/// - Executes pe_integrity::init_shard_table()
/// - Applies surgical PE NT header erasure (AddressOfEntryPoint, NT signature)
/// - Preserves DOS header and section headers for OS stability
/// - Deploys lock-free atomic decoy tracking table with saturating interval math
/// - Deploys PAGE_GUARD / PAGE_NOACCESS multi-thread quarantine honeytraps
pub fn init_anti_dump() -> bool;

/// Parses and validates NT system service number (SSN) from NTDLL stub bytes.
/// Validates canonical prefix [0x4C, 0x8B, 0xD1, 0xB8], enforces bounded scan
/// min(32, stub.len().saturating_sub(8)), and range-checks 0 < SSN < 0x1000.
pub fn parse_ssn_from_stub(stub: &[u8]) -> Option<u32>;
```

### Lock-Free Decoy Table & KUSER Watchdog (`anti_dump.rs`)

```rust
pub const MAX_DECOY_REGIONS: usize = 8;
pub const SYSCALL_STACK_RESERVED_BYTES: usize = 0x40; // 64 bytes

/// Registers a decoy memory region into the lock-free atomic table.
/// Uses atomic compare-and-swap (CAS) with Acquire/Release ordering.
pub fn register_decoy_region(base: usize, size: usize) -> bool;

/// Clears all registered decoy regions in the atomic table.
pub fn clear_decoy_regions();

/// Lock-free Seqlock reader for KUSER_SHARED_DATA InterruptTime at 0x7FFE0014.
/// Loops until High1Time == High2Time to eliminate 4.29-billion tick torn reads.
pub unsafe fn read_kuser_time_lock_free(base_addr: usize) -> u64;
```

### Master VEH Invariants & ABI Structures (`enhanced_veh.rs`, `global_state.rs`)

```rust
/// Validates stack frames starting from initial CONTEXT, querying TEB stack limits
/// gs:[0x08] (StackBase) and gs:[0x10] (StackLimit) via inline assembly.
pub unsafe fn validate_stack_frames(initial_context: &CONTEXT, image_base: u64) -> bool;

/// Validates stack frames within explicit stack boundary bounds.
/// Enforces frames_walked >= 2, Rip != 0, Rsp % 8 == 0, and TEB stack containment.
pub unsafe fn validate_stack_frames_with_bounds(
    initial_context: &CONTEXT,
    image_base: u64,
    stack_limit: u64,
    stack_base: u64,
) -> bool;

/// Thread-local RAII guard bounding VEH exception recursion depth to <= 1.
pub struct VehReentrancyGuard { /* private fields */ }

impl VehReentrancyGuard {
    pub fn enter() -> Result<Self, usize>;
}

/// Official Win32 x64 CONTEXT structure (1232 bytes, 16-byte alignment).
#[repr(C, align(16))]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16, pub SegDs: u16, pub SegEs: u16, pub SegFs: u16, pub SegGs: u16, pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64, pub Dr1: u64, pub Dr2: u64, pub Dr3: u64, pub Dr6: u64, pub Dr7: u64,
    pub Rax: u64, pub Rcx: u64, pub Rdx: u64, pub Rbx: u64, pub Rsp: u64, pub Rbp: u64,
    pub Rsi: u64, pub Rdi: u64, pub R8: u64,  pub R9: u64,  pub R10: u64, pub R11: u64,
    pub R12: u64, pub R13: u64, pub R14: u64, pub R15: u64,
    pub Rip: u64,
    pub FltSave: XSAVE_FORMAT,          // 512 bytes (includes Xmm0..Xmm15)
    pub VectorRegister: [M128A; 26],    // 416 bytes
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}
```

> **Note on PE Metadata Caching & Lock-Free State**:  
> The legacy function `pe_integrity::force_cache_pe_metadata()` was removed. Shard table caching and section verification is handled automatically by `init_anti_dump()` and `pe_integrity::heartbeat_check(0)`. Decoy intervals are stored in a lock-free atomic table without Mutex overhead.

---

## 6. Internal Primitives & Security Boundaries

The following functions are **private internal primitives** and must not be called directly:
- `opaque_predicate_eq(u32, u32) -> bool` and `opaque_predicate_branch(bool) -> bool`: Private inline functions in `src/protector/mod.rs` used by the compiler and macros to disguise conditional branch evaluation.
- `anti_debug::erase_pe_header()`: Legacy stub superseded by `anti_dump::init_anti_dump()`.
- `pe_integrity::SHARD_TABLE`: Internal atomic storage for 1KB `.text` section hashes.

---

## 7. Usage Patterns & Code Examples

### Pattern 1: Protected Product Licensing

```rust
use fuckDebug::protector::{setup_anti_debug, get_dynamic_seed, SecureVault};

fn verify_license(license_key: &str) -> bool {
    let protector = setup_anti_debug!(get_dynamic_seed());
    let vault = SecureVault::new(license_key.to_string());
    
    vault.unlock(&protector, |key, token| {
        if key.len() != 32 || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }
        
        // Token parity coupling: if debugged, token is rotated garbage
        let derived_checksum = token.wrapping_mul(0x55AA).rotate_left(5);
        (derived_checksum % 7) == 0
    })
}
```

### Pattern 2: Financial Transaction Coupling

```rust
use fuckDebug::protector::{setup_anti_debug, get_dynamic_seed, CoupledLogic, Corruptible};

#[derive(Clone, Debug)]
struct OrderData {
    total: f64,
    valid: bool,
}

impl Corruptible for OrderData {
    fn corrupt_if_needed(mut self, token: u64) -> Self {
        if token.count_ones() > 16 {
            self.total = 0.0;
            self.valid = false;
        }
        self
    }
}

fn process_order(base_amount: f64) -> OrderData {
    let protector = setup_anti_debug!(get_dynamic_seed());
    
    protector.run_coupled(|token| {
        OrderData {
            total: base_amount + (token as f64 * 0.0001),
            valid: token != 0,
        }
    })
}
```

---

## 8. Formal Verification Suite Commands

`fuckDebug` is validated by an extensive formal verification suite combining 35 Verus deductive SMT theorems, 85 Bolero property-based fuzzing harnesses, and 25 verification suite test binaries (355+ total automated tests workspace-wide across root crate and verification suite, maintaining 100% pass rate).

### 8.1 Automated Verification Runners

#### Run Full Formal Suite via PowerShell:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "verification_suite\run_verification.ps1"
```

#### Run Full Formal Suite via Batch File:
```cmd
verification_suite\run_verification.bat
```

### 8.2 Targeted Cargo Test Commands

#### Run Layer 4 TinyVM Defect Suite (D1 through D7):
```cmd
cargo test --manifest-path verification_suite/Cargo.toml --test defect_layer4_tinyvm -- --nocapture
```

#### Run Layer 4 Hypothesis Property Tests (>300k iterations/s):
```cmd
cargo test --manifest-path verification_suite/Cargo.toml --test hypothesis_tiny_vm -- --nocapture
```

#### Run Defect Proofs (FLAW-01 through FLAW-16):
```cmd
cargo test --manifest-path verification_suite/Cargo.toml --test defect_proofs -- --nocapture
```

#### Run All Verification Suite Tests (339+ Tests Across 25 Test Binaries):
```cmd
cargo test --manifest-path verification_suite/Cargo.toml -- --test-threads=1
```

#### Run Root Crate Unit Tests (21 Tests):
```cmd
cargo test --lib
```

---

## 9. Common Pitfalls & Best Practices

1. **Avoid Hardcoded Seeds**:  
   ❌ `Protector::new(0xDEADBEEF)`  
   ✅ `setup_anti_debug!(get_dynamic_seed())`  
   Using static seeds circumvents the polymorphic advantages of Layer 2.

2. **Never Ignore the Security Token**:  
   ❌ `protector.run_secure(&vault, |data, _token| println!("{}", data));`  
   ✅ `vault.unlock(&protector, |data, key| compute_with_key(data, key));`  
   Always mathematically incorporate the token or transformation key into business calculations.

3. **Do Not Cache Results Across Calls**:  
   Executing `run_secure` once and saving the result into a global variable allows attackers to let the initial check pass and attach a debugger afterwards. Wrap sensitive workflows so execution repeatedly traverses the protection pipeline.

4. **Isolate Test Subprocesses**:  
   When writing tests for `Protector`, always execute the protector within an isolated child process to prevent memory header conflicts (Windows OS Error 193).

---

## 10. FAQ

**Q: Does fuckDebug run in virtual machines or cloud environments?**  
A: Yes. Layer 1 detects and accommodates hypervisors (including Windows Hyper-V, VBS, and WSL2) by dynamically validating the `"Microsoft Hv"` brand string, maintaining a stable baseline without false-positive poisoning.

**Q: How does fuckDebug handle thread suspension in debuggers?**  
A: The Watchdog v2 inspects `KUSER_SHARED_DATA.InterruptTime` via paired aligned 32-bit reads. If thread execution pauses for longer than 5 seconds, silent poisoning activates, corrupting keys and seeds. Under heavy CPU load (>85%), timeout adaptively doubles to 10 seconds.

**Q: Can attackers bypass the protection by zeroing memory?**  
A: No. The 128 suspicion shards are encoded with build-time masks: $\text{Encoded} = \text{Value} \oplus \text{Mask}$. If an attacker zeroes memory, $0 \oplus \text{Mask} = \text{Mask}$, which causes an immediate score spike exceeding 500 points, triggering irreversible state corruption.

---

*fuckDebug API & Reference Guide — 2026*

//! Example: Unified Memory Stealth System
//!
//! Run with: cargo run --release --example stealth_system
//!
//! This demonstrates the integrated anti-dump protection including:
//! - Indirect syscalls (dynamic SSN resolution)
//! - RAII StealthGuard with cache flushing  
//! - TinyVM-based key derivation
//! - Decoy structure injection
//! - PE header morphing

use fuckDebug::protector::{init_anti_dump, anti_dump};

fn main() {
    println!("[*] Initializing Unified Memory Stealth System...");
    
    // Initialize the system - this will:
    // 1. Resolve syscalls dynamically from ntdll.dll
    // 2. Morph PE headers (MZ -> 0xFFFF)
    // 3. Register VEH handler
    // 4. Spawn guard page roller thread
    // 5. Spawn heap scrambler with decoy injection
    init_anti_dump();
    
    println!("[+] Memory stealth protection active");
    
    // Example: Using StealthPtr with RAII guard
    let secret_data: u64 = 0xDEADBEEFCAFEBABE;
    let stealth_ptr = anti_dump::StealthPtr::new(&secret_data);
    
    {
        // Access grants RAII guard - auto cache flush on drop
        let guard = stealth_ptr.access();
        println!("[+] Secret data accessed: 0x{:X}", *guard);
        // StealthGuard drops here -> clflush evicts from cache
    }
    
    // Acquire lease for legitimate memory operations
    anti_dump::acquire_access_lease();
    println!("[+] Access lease acquired (100ms)");
    
    // Do memory-intensive work here...
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    anti_dump::release_access_lease();
    println!("[+] Access lease released");
    
    // Verify integrity
    let integrity_ok = anti_dump::verify_stealth_integrity();
    println!("[{}] Stealth integrity: {}", 
        if integrity_ok { "+" } else { "!" },
        if integrity_ok { "VERIFIED" } else { "COMPROMISED" });
    
    println!("\n[*] Press Ctrl+C to exit. Attach Scylla/x64dbg to test...");
    
    // Keep running so you can test with external tools
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

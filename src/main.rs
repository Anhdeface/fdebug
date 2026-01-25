mod protector;
use crate::protector::{Protector, SecureVault, ShieldedExecution, get_dynamic_seed};

/// Entry point - demonstrates the Mandatory Security Enforcement Layer
fn main() {
    // 1. Initialize the Enforcer
    // This triggers decentralized checkpoints and initializes sharded state
    let protector = Protector::new(get_dynamic_seed());
    
    println!("[*] Mandatory Security Enforcement Active");
    println!("[*] Detection Architecture: Decentralized Sharding + TLS Pre-emption");
    
    // 2. Wrap sensitive data in a SecureVault
    // These values cannot be accessed without a dynamic TRANSFORMATION_KEY
    let base_price = SecureVault::new(299u32);
    let secret_key = SecureVault::new(0xABCD_1234_u32);

    println!("\n[1] Accessing Vaulted Data (Forced Mathematical Dependency):");

    // unlock() provides the data and a dynamic key.
    // If a debugger is present, 'key' is a rotated, wrapped, garbage value.
    base_price.unlock(&protector, |val, key| {
        // Correct math: price ^ (key % 0xFFFF)
        // SILENT CORRUPTION: The app runs, but the price will be wrong if debugged.
        let transformed_price = val ^ (key as u32 % 0xFFFF);
        println!("    Vaulted Price Result: ${}", transformed_price);
    });

    secret_key.unlock(&protector, |val, key| {
        // Complex mixing dependency
        let secure_id = (*val as u64).wrapping_add(key).rotate_left((key % 7) as u32);
        println!("    Secure Derived ID: {:x}", secure_id);
    });

    // 3. Using the guarded_value! macro for inline enforcement
    // This is the recommended way to bridge security with business logic.
    println!("\n[2] Testing macro enforcement (guarded_value!):");
    let (data, key) = guarded_value!(1337u64, protector);
    
    // Developer is FORCED to use 'key' to get a valid 'final_result'
    let final_result = data ^ key;
    println!("    Transformed Macro Result: {:x}", final_result);

    // 4. Checking the current atmospheric state (Silent Score)
    let score = protector::get_suspicion_score();
    println!("\n[*] Process environment suspicion: {}", score);
    
    if score >= 100 {
        println!("[!] DATA INTEGRITY COMPROMISED - Execution poisoned by debugger");
        
        // Diagnostic Mode check
        use crate::protector::global_state::TRIGGERED_CHECKPOINTS;
        use std::sync::atomic::Ordering;
        println!("[DEBUG] Triggered checkpoints:");
        for i in 0..8 {
            let val = TRIGGERED_CHECKPOINTS[i].load(Ordering::Relaxed);
            if val > 0 {
                println!("  Checkpoint {}: {} points", i, val);
            }
        }
    } else {
        println!("[+] Operational environment safe.");
    }
}
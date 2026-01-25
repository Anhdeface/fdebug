// build.rs
#![allow(unused_imports)]

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    // Generate a random seed at build time for polymorphic opcodes
    let dynamic_seed = generate_random_seed_u32();

    // Create the dynamic_seed.rs file in OUT_DIR so it can be included
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("dynamic_seed.rs");

    let mut f = File::create(&dest_path).unwrap();

    // Just write the literal value so it can be included as an expression
    writeln!(f, "0x{:08X}u32", dynamic_seed).unwrap();

    // Tell cargo to rerun this build script if something changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/protector/tiny_vm.rs");
}

// Function to generate a pseudo-random 32-bit seed based on build environment
fn generate_random_seed_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Get current time in nanoseconds as a source of randomness
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    // Use multiple sets of bits from the timestamp mixed with environmental factors
    let mut seed = (now & 0xFFFFFFFF) as u32;

    // Mix with upper bits for more entropy
    seed ^= (now >> 32) as u32;

    // Add some environmental entropy
    if let Ok(pwd) = env::current_dir() {
        let h = pwd.to_string_lossy().bytes().fold(0u32, |acc, b| {
            acc.rotate_left(7).wrapping_add(b as u32)
        });
        seed ^= h;
    }

    // Add cargo profile and manifest data to the mix
    if let Ok(profile) = env::var("PROFILE") {
        seed ^= profile.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
    }

    // Mix in manifest directory to ensure different clones have different seeds
    if let Ok(manifest) = env::var("CARGO_MANIFEST_DIR") {
        let h = manifest.bytes().fold(0u32, |acc, b| {
            acc.rotate_right(5) ^ (b as u32)
        });
        seed ^= h;
    }

    // Ensure the seed is not zero
    if seed == 0 {
        seed = 0x9A3F_C5D7; // Default fallback
    }

    seed
}
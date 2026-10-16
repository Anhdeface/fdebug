//! Empirical Adversarial Stress Test Harness for Module Shims
//!
//! Validates `hardware_entropy_shim` and `pe_integrity_shim` under high-iteration
//! stress, concurrent multi-threading, boundary inputs, and differential oracles.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use verification_suite::shims::hardware_entropy_shim::*;
use verification_suite::shims::pe_integrity_shim::*;

#[test]
fn test_stress_hardware_entropy_100k_iterations() {
    let baseline = get_hardware_entropy();
    assert_ne!(baseline, 0, "Hardware entropy baseline must be non-zero");

    for i in 0..100_000 {
        let val = get_hardware_entropy();
        assert_eq!(
            val, baseline,
            "Hardware entropy diverged at iteration {i}: expected {baseline:#x}, got {val:#x}"
        );
    }
}

#[test]
fn test_stress_hardware_entropy_multithreaded() {
    const NUM_THREADS: usize = 16;
    const ITERS_PER_THREAD: usize = 5_000;

    let baseline = get_hardware_entropy();
    assert_ne!(baseline, 0);

    let error_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for _ in 0..NUM_THREADS {
        let errs = Arc::clone(&error_count);
        handles.push(thread::spawn(move || {
            for _ in 0..ITERS_PER_THREAD {
                let sample = get_hardware_entropy();
                if sample != baseline || sample == 0 {
                    errs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread joined successfully");
    }

    assert_eq!(
        error_count.load(Ordering::SeqCst),
        0,
        "Concurrent get_hardware_entropy calls produced divergence or zeroes"
    );
}

#[test]
fn test_stress_fnv1a_reference_oracle() {
    // 1. Empty buffer
    assert_eq!(fnv1a_hash_ref(b""), 0x811C9DC5);

    // 2. Known test vectors
    assert_eq!(fnv1a_hash_ref(b"test"), 2949673445);
    assert_eq!(fnv1a_hash_ref(b"foobar"), 3214735720);

    // 3. Different inputs produce different hashes
    assert_ne!(fnv1a_hash_ref(b"test1"), fnv1a_hash_ref(b"test2"));
    assert_ne!(fnv1a_hash_ref(b"\x00"), fnv1a_hash_ref(b"\x01"));

    // 4. Large buffer avalanche & no panic
    let zero_buf = [0u8; 1024];
    let h_zero = fnv1a_hash_ref(&zero_buf);
    assert_ne!(h_zero, 0);

    let ff_buf = [0xFFu8; 1024];
    let h_ff = fnv1a_hash_ref(&ff_buf);
    assert_ne!(h_ff, 0);
    assert_ne!(h_zero, h_ff);
}

#[test]
fn test_stress_pe_integrity_heartbeat_10k_iterations() {
    let initial_poison = verification_suite::protector::global_state::POISON_SEED.load(Ordering::Relaxed);

    for i in 0..10_000u32 {
        let seed = i.wrapping_mul(0x9E3779B9);
        let token = heartbeat_check(seed);
        assert_ne!(
            token, 0,
            "Heartbeat check returned 0 at iteration {i} with seed {seed:#x}"
        );
        assert_ne!(
            token, 0xDEAD_DEAD_DEAD_DEAD,
            "Heartbeat check reported instant poison failure at iteration {i}"
        );
    }

    let final_poison = verification_suite::protector::global_state::POISON_SEED.load(Ordering::Relaxed);
    assert_eq!(
        initial_poison, final_poison,
        "Normal heartbeat execution should not trigger POISON_SEED"
    );
}

#[test]
fn test_stress_pe_integrity_multithreaded() {
    const NUM_THREADS: usize = 16;
    const ITERS_PER_THREAD: usize = 1_000;

    let error_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for tid in 0..NUM_THREADS {
        let errs = Arc::clone(&error_count);
        handles.push(thread::spawn(move || {
            for i in 0..ITERS_PER_THREAD {
                let seed = ((tid as u32) << 16) ^ (i as u32);
                let token = heartbeat_check(seed);
                if token == 0 || token == 0xDEAD_DEAD_DEAD_DEAD {
                    errs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread joined successfully");
    }

    assert_eq!(
        error_count.load(Ordering::SeqCst),
        0,
        "Concurrent heartbeat_check calls failed"
    );
}

#[test]
fn test_stress_pe_integrity_boundary_seeds() {
    let boundary_seeds: [u32; 10] = [
        0,
        1,
        2,
        u32::MAX,
        u32::MAX - 1,
        0x8000_0000,
        0x7FFF_FFFF,
        1024,
        4096,
        0xDEAD_BEEF,
    ];

    for &seed in &boundary_seeds {
        let token = heartbeat_check(seed);
        assert_ne!(token, 0, "Boundary seed {seed:#x} yielded 0 token");
        assert_ne!(
            token, 0xDEAD_DEAD_DEAD_DEAD,
            "Boundary seed {seed:#x} caused instant poison"
        );
    }
}

#[test]
fn test_stress_pe_integrity_heartbeat_timestamp_updating() {
    let _ = heartbeat_check(42);
    let hb1 = verification_suite::protector::global_state::LAST_VM_HEARTBEAT.load(Ordering::Relaxed);
    assert_ne!(hb1, 0, "LAST_VM_HEARTBEAT must be updated after heartbeat check");

    // Sleep a tiny slice to ensure tick advancement
    thread::sleep(std::time::Duration::from_millis(15));
    let _ = heartbeat_check(43);
    let hb2 = verification_suite::protector::global_state::LAST_VM_HEARTBEAT.load(Ordering::Relaxed);
    assert_ne!(hb2, 0);
}

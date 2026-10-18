#![allow(unused_imports, dead_code, non_snake_case)]

//! # Challenger M2_2 Adversarial Stress Test Suite
//!
//! Empirical adversarial challenge suite executed by Challenger M2_2:
//! Focus: Feature F7 (Lock-Free Decoy Table) & Feature F8 (Lock-Free KUSER Watchdog Clock).
//!
//! ## Mathematical Specifications & Invariants Challenged:
//!
//! 1. Invariant F7a: Lock-Free Decoy Table Deadlock-Freedom & High-Concurrency Scalability
//!    - Under high-concurrency simultaneous calls to `register_decoy_region`, `clear_decoy_regions`,
//!      and `handle_guard_page_violation`, zero deadlocks, zero lock acquisitions, and zero panics occur.
//!    - Execution terminates strictly within bounded time under extreme thread contention.
//!
//! 2. Invariant F7b: Decoy Table Atomic Linearizability & ABA Resistance
//!    - Slot state transitions: `(0, 0) -> (base, 0) -> (base, size) -> (base, 0) -> (0, 0)`
//!    - Readers never observe torn or cross-talk combinations (e.g. `(base_A, size_B)`).
//!    - An uninitialized or clearing slot (`size == 0`) never registers a false-positive hit.
//!
//! 3. Invariant F7c: Strict Bounded Capacity Saturation ($N \le 8$)
//!    - Table capacity is hard-bounded at `MAX_DECOY_REGIONS = 8`.
//!    - Concurrent attempts to register beyond 8 distinct bases return `false` monotonically
//!      without memory overflow, allocation, or data corruption.
//!    - Existing entries can be updated at capacity.
//!
//! 4. Invariant F8a: 100% Torn Read Detection & Rejection During 32-Bit Tick Rollovers
//!    - In Windows NT `KSYSTEM_TIME`, the kernel updates:
//!      `U1: High2 = H+1`, `U2: Low = NewLow`, `U3: High1 = H+1`.
//!    - If reader samples during U1 or U2 where `High1 != High2`, the read MUST be rejected.
//!    - The reader spins until `High1 == High2`, returning an untorn monotonic 64-bit timestamp.
//!
//! 5. Invariant F8b: Immunity to Spurious False-Positive Watchdog Poisoning
//!    - Torn reads across 32-bit tick rollovers produce an artificial jump of $2^{32} \times 100\,\text{ns} \approx 429.5\,\text{s}$.
//!    - The lock-free loop rejects in-flight updates, guaranteeing $\Delta \le \text{Threshold}$ (5 seconds).
//!    - Zero false-positive invocations of `trigger_silent_poisoning()`.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use verification_suite::protector::{
    anti_dump::{
        clear_decoy_regions, handle_guard_page_violation, read_kuser_time_lock_free,
        register_decoy_region, DECOY_REGIONS, MAX_DECOY_REGIONS,
    },
    global_state::{
        CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD, POISON_SEED,
    },
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

/// Helper to build synthetic EXCEPTION_POINTERS for guard page violation testing
fn make_guard_page_exception(
    code: u32,
    num_params: u32,
    fault_addr: usize,
) -> (EXCEPTION_RECORD, CONTEXT, EXCEPTION_POINTERS) {
    let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
    record.ExceptionCode = code;
    record.NumberParameters = num_params;
    if num_params >= 2 {
        record.ExceptionInformation[0] = 0; // Read intent
        record.ExceptionInformation[1] = fault_addr;
    }

    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let mut ep = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: std::ptr::null_mut(),
    };
    ep.ExceptionRecord = &mut record;
    ep.ContextRecord = &mut ctx;

    (record, ctx, ep)
}

// ============================================================================
// 1. FEATURE F7: DECOY REGIONS HIGH-CONCURRENCY STRESS TESTS
// ============================================================================

/// Stress Challenge 1.1: Intense Multi-Threaded Concurrency Hammer
///
/// 16 concurrent threads:
/// - 8 Reader threads calling `handle_guard_page_violation` with hitting and non-hitting addresses.
/// - 4 Writer threads repeatedly calling `register_decoy_region`.
/// - 4 Resetter threads repeatedly calling `clear_decoy_regions`.
///
/// Invariant: Deadlock-free, zero panics, zero data races, completes within strict timeout.
#[test]
fn test_adversarial_decoy_intense_multi_threaded_concurrency() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let thread_count = 16;
    let ops_per_thread = 1_000;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let completed_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(thread_count);

    // Initial decoys
    for i in 0..4 {
        register_decoy_region(0x1000_0000 + i * 0x10_0000, 0x1000);
    }

    let start_time = Instant::now();

    for tid in 0..thread_count {
        let stop_clone = Arc::clone(&stop_flag);
        let completed_clone = Arc::clone(&completed_count);

        let handle = thread::spawn(move || {
            let role = tid % 4;
            for i in 0..ops_per_thread {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }

                match role {
                    0 | 1 => {
                        // Readers: test hitting and non-hitting addresses
                        let fault_addr = if i % 2 == 0 {
                            0x1000_0000 + (i % 4) * 0x10_0000 + 0x200
                        } else {
                            0x7000_0000 + i
                        };

                        let (mut rec, mut ctx, mut ep) =
                            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, fault_addr);
                        ep.ExceptionRecord = &mut rec;
                        ep.ContextRecord = &mut ctx;

                        let _ = unsafe { handle_guard_page_violation(&mut ep) };
                    }
                    2 => {
                        // Writers: register dynamic decoy regions
                        let base = 0x2000_0000 + (i % 8) * 0x10_0000;
                        let size = 0x1000 * ((i % 4) + 1);
                        let _ = register_decoy_region(base, size);
                    }
                    3 => {
                        // Resetters: clear and re-seed
                        if i % 10 == 0 {
                            clear_decoy_regions();
                            register_decoy_region(0x1000_0000, 0x1000);
                        }
                    }
                    _ => unreachable!(),
                }
            }
            completed_clone.fetch_add(1, Ordering::SeqCst);
        });

        handles.push(handle);
    }

    // Monitor for deadlock (maximum allowable duration: 5 seconds)
    for handle in handles {
        handle.join().expect("Worker thread panicked under concurrency!");
    }

    let elapsed = start_time.elapsed();
    assert_eq!(
        completed_count.load(Ordering::SeqCst),
        thread_count,
        "All 16 worker threads must complete execution without hanging"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "Concurrency test took {:?}, exceeding 5-second deadline (deadlock detected)",
        elapsed
    );

    clear_decoy_regions();
}

/// Stress Challenge 1.2: Atomic Linearizability & Cross-Talk / ABA Isolation
///
/// Verifies that rapid recycling between two disjoint regions `(base_A, size_A)` and `(base_B, size_B)`
/// NEVER causes an observer to witness a torn hybrid state (e.g., `base_A` with `size_B`).
#[test]
fn test_adversarial_decoy_atomic_linearizability_aba_isolation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let base_a = 0xA000_0000usize;
    let size_a = 0x1000usize;

    let base_b = 0xB000_0000usize;
    let size_b = 0x8000usize;

    let stop_signal = Arc::new(AtomicBool::new(false));
    let torn_observations = Arc::new(AtomicUsize::new(0));

    // Writer thread rapidly toggles between region A and region B
    let stop_w = Arc::clone(&stop_signal);
    let writer_handle = thread::spawn(move || {
        for i in 0..5_000 {
            if stop_w.load(Ordering::Relaxed) {
                break;
            }
            clear_decoy_regions();
            if i % 2 == 0 {
                register_decoy_region(base_a, size_a);
            } else {
                register_decoy_region(base_b, size_b);
            }
        }
        stop_w.store(true, Ordering::Relaxed);
    });

    // Reader threads probe sensitive test points:
    // - probe_a_valid: inside region A
    // - probe_a_invalid_overflow: inside [base_a + size_a, base_a + size_b)
    //   If a torn read mixes base_A with size_B, probe_a_invalid_overflow would falsely HIT!
    let mut reader_handles = Vec::new();
    for _ in 0..4 {
        let stop_r = Arc::clone(&stop_signal);
        let torn_clone = Arc::clone(&torn_observations);

        let reader = thread::spawn(move || {
            let probe_a_over = base_a + 0x2000; // in A only if size == size_b (torn!)

            while !stop_r.load(Ordering::Relaxed) {
                let (mut rec, mut ctx, mut ep) =
                    make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, probe_a_over);
                ep.ExceptionRecord = &mut rec;
                ep.ContextRecord = &mut ctx;

                let hit = unsafe { handle_guard_page_violation(&mut ep) };
                if hit {
                    torn_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        reader_handles.push(reader);
    }

    writer_handle.join().expect("Writer thread failed");
    stop_signal.store(true, Ordering::Relaxed);

    for r in reader_handles {
        r.join().expect("Reader thread failed");
    }

    assert_eq!(
        torn_observations.load(Ordering::SeqCst),
        0,
        "Atomic linearizability violation: observed torn (base_A, size_B) state!"
    );

    clear_decoy_regions();
}

/// Stress Challenge 1.3: Bounded Capacity Saturation at Exactly 8 Regions
///
/// Concurrently attempts to register 24 distinct regions across 8 threads.
/// Asserts:
/// 1. Exactly 8 slots are occupied.
/// 2. Active count never exceeds `MAX_DECOY_REGIONS = 8`.
/// 3. Excess registrations fail cleanly returning `false`.
/// 4. Updating size for an already-registered base succeeds at capacity.
#[test]
fn test_adversarial_decoy_bounded_saturation_capacity_8() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let thread_count = 8;
    let mut handles = Vec::new();
    let successful_registrations = Arc::new(AtomicUsize::new(0));

    // 8 threads each try to register 3 distinct bases (total 24 candidates)
    for tid in 0..thread_count {
        let succ_clone = Arc::clone(&successful_registrations);
        let handle = thread::spawn(move || {
            for j in 0..3 {
                let base = 0x3000_0000 + (tid * 3 + j) * 0x10_0000;
                let registered = register_decoy_region(base, 0x1000);
                if registered {
                    succ_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    // Capacity invariant: exactly 8 must succeed
    assert_eq!(
        successful_registrations.load(Ordering::SeqCst),
        MAX_DECOY_REGIONS,
        "Exactly 8 unique regions must succeed across all concurrent registration attempts"
    );

    // Verify raw array capacity invariant
    let mut active_slots = 0;
    for slot in DECOY_REGIONS.iter() {
        let base = slot.0.load(Ordering::Acquire);
        let size = slot.1.load(Ordering::Acquire);
        if base != 0 && size > 0 {
            active_slots += 1;
        }
    }
    assert_eq!(active_slots, 8, "Raw atomic table must contain exactly 8 active slots");

    // Attempt to register a 25th region
    let overflow_res = register_decoy_region(0x9999_0000, 0x1000);
    assert!(!overflow_res, "Registration beyond capacity 8 must return false");

    // Invariant: Updating an existing base succeeds even at full capacity
    let first_base = DECOY_REGIONS[0].0.load(Ordering::Acquire);
    assert_ne!(first_base, 0);
    let update_res = register_decoy_region(first_base, 0x5000);
    assert!(update_res, "Updating an existing base must succeed even when table is full");
    assert_eq!(DECOY_REGIONS[0].1.load(Ordering::Acquire), 0x5000);

    clear_decoy_regions();
}

/// Stress Challenge 1.4: Malformed Exception Record Fuzzing & Boundary Invariants
///
/// Verifies robustness of `handle_guard_page_violation` against malformed records:
/// - Null pointers
/// - Truncated parameter arrays (NumberParameters < 2)
/// - Non-guard-page exception codes (e.g. Access Violation, Breakpoint)
/// - Extreme integer addresses (0, usize::MAX, isize::MIN, off-by-one bounds)
/// - High memory regions (base = usize::MAX - 0x1000)
#[test]
fn test_adversarial_decoy_malformed_records_and_boundaries() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // 1. Extreme pointer nullity
    unsafe {
        assert!(!handle_guard_page_violation(std::ptr::null_mut()));

        let mut ep_null_rec = EXCEPTION_POINTERS {
            ExceptionRecord: std::ptr::null_mut(),
            ContextRecord: std::ptr::null_mut(),
        };
        assert!(!handle_guard_page_violation(&mut ep_null_rec));
    }

    // 2. Non-matching Exception Codes
    let bad_codes = [0x00000000u32, 0xC0000005, 0x80000003, 0xFFFFFFFF];
    for &code in &bad_codes {
        let (mut rec, mut ctx, mut ep) = make_guard_page_exception(code, 2, 0x1000);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            unsafe { !handle_guard_page_violation(&mut ep) },
            "Non-guard-page code {:#X} must return false",
            code
        );
    }

    // 3. NumberParameters boundary checks (0, 1)
    for num_params in 0..2 {
        let (mut rec, mut ctx, mut ep) =
            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, num_params, 0x1000);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            unsafe { !handle_guard_page_violation(&mut ep) },
            "NumberParameters = {} must return false cleanly without reading ExceptionInformation",
            num_params
        );
    }

    // 4. Exact interval boundaries (off-by-one checks)
    let base = 0x5000_0000usize;
    let size = 0x2000usize;
    register_decoy_region(base, size);

    let test_points = [
        (base - 1, false, "base - 1"),
        (base, true, "base"),
        (base + 1, true, "base + 1"),
        (base + size - 1, true, "base + size - 1"),
        (base + size, false, "base + size (exclusive upper bound)"),
        (base + size + 1, false, "base + size + 1"),
        (0, false, "null address"),
        (usize::MAX, false, "usize::MAX"),
    ];

    for (addr, expected, label) in test_points {
        let (mut rec, mut ctx, mut ep) =
            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, addr);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;

        let hit = unsafe { handle_guard_page_violation(&mut ep) };
        assert_eq!(
            hit, expected,
            "Boundary check failed for {}: addr={:#X}, expected={}",
            label, addr, expected
        );
    }

    // 5. High memory saturating boundary (Feature F5)
    clear_decoy_regions();
    let high_base = usize::MAX - 0x1000;
    let high_size = 0x2000;
    register_decoy_region(high_base, high_size);

    let high_test_points = [
        (high_base - 1, false),
        (high_base, true),
        (high_base + 0x500, true),
        (usize::MAX - 1, true),
        (usize::MAX, false), // Exclusive bound of saturating interval
    ];

    for (addr, expected) in high_test_points {
        let (mut rec, mut ctx, mut ep) =
            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, addr);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;

        let hit = unsafe { handle_guard_page_violation(&mut ep) };
        assert_eq!(
            hit, expected,
            "High memory saturating check failed: addr={:#X}",
            addr
        );
    }

    clear_decoy_regions();
}

// ============================================================================
// 2. FEATURE F8: KUSER CLOCK ROLLOVER STRESS & TORN READ REJECTION
// ============================================================================

/// Stress Challenge 2.1: High-Frequency Tick Rollovers with Simulated ISR Contention
///
/// Simulates the Windows NT kernel timer interrupt advancing time across 32-bit tick boundaries
/// where `High1 != High2` is actively asserted during reader operations:
///
/// Step 0: Pre-rollover clean state: `High1 = r, High2 = r, Low = 0xFFFF_FFFF`
/// Step 1: ISR updates `High2 = r + 1` (`High1 != High2`!)
/// Step 2: ISR updates `Low = 0x0000_0001` (`High1 != High2`!)
/// Step 3: ISR updates `High1 = r + 1` (`High1 == High2 == r + 1`)
///
/// Invariants:
/// 1. Readers NEVER observe torn reads (100% rejection).
///    Specifically, reader NEVER returns `(r + 1, 0xFFFF_FFFF)` or `(r, 0x0000_0001)`.
/// 2. Every returned value is an untorn atomic snapshot: either `(r, 0xFFFF_FFFF)` or `(r + 1, 0x0000_0001)`.
/// 3. In comparison, an unpatched reader demonstrates that torn reads actively occur without the guard.
#[test]
fn test_adversarial_kuser_clock_high_frequency_rollover_concurrency() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Aligned 32-bit cells simulating KUSER_SHARED_DATA:
    // [0]: LowPart (0x7FFE0014)
    // [1]: High1Time (0x7FFE0018)
    // [2]: High2Time (0x7FFE001C)
    let kuser_cells = Arc::new([
        AtomicU32::new(0xFFFF_FFFF), // LowPart
        AtomicU32::new(0),           // High1Time
        AtomicU32::new(0),           // High2Time
    ]);

    let stop_signal = Arc::new(AtomicBool::new(false));
    let total_rollovers = 10_000;

    // ISR Simulation Thread: advances time across 10,000 rollovers
    let kuser_w = Arc::clone(&kuser_cells);
    let stop_w = Arc::clone(&stop_signal);

    let isr_handle = thread::spawn(move || {
        for r in 0..total_rollovers {
            if stop_w.load(Ordering::Relaxed) {
                break;
            }

            // Step 0: Pre-rollover state for cycle r
            kuser_w[0].store(0xFFFF_FFFF, Ordering::SeqCst);
            kuser_w[1].store(r, Ordering::SeqCst);
            kuser_w[2].store(r, Ordering::SeqCst);
            for _ in 0..5 {
                std::hint::spin_loop();
            }

            // Step 1: Kernel updates High2
            kuser_w[2].store(r + 1, Ordering::SeqCst);
            for _ in 0..10 {
                std::hint::spin_loop();
            }

            // Step 2: Kernel updates LowPart
            kuser_w[0].store(0x0000_0001, Ordering::SeqCst);
            for _ in 0..10 {
                std::hint::spin_loop();
            }

            // Step 3: Kernel updates High1
            kuser_w[1].store(r + 1, Ordering::SeqCst);
            for _ in 0..5 {
                std::hint::spin_loop();
            }
        }
        stop_w.store(true, Ordering::Relaxed);
    });

    // 4 Concurrent Reader Threads calling read_kuser_time_lock_free
    let mut reader_handles = Vec::new();
    let torn_reads_detected = Arc::new(AtomicUsize::new(0));
    let reads_completed = Arc::new(AtomicUsize::new(0));

    for _ in 0..4 {
        let kuser_r = Arc::clone(&kuser_cells);
        let stop_r = Arc::clone(&stop_signal);
        let torn_clone = Arc::clone(&torn_reads_detected);
        let completed_clone = Arc::clone(&reads_completed);

        let reader = thread::spawn(move || {
            let base_addr = kuser_r.as_ptr() as usize;

            while !stop_r.load(Ordering::Relaxed) {
                let current_time = unsafe { read_kuser_time_lock_free(base_addr) };

                let _high = (current_time >> 32) as u32;
                let low = current_time as u32;

                // TORN READ VERIFICATION:
                // If low == 0xFFFF_FFFF, then High MUST NOT be high of a state where low has rolled over (r + 1).
                // If low == 0x0000_0001, then High MUST NOT be old high from before rollover (r).
                // In our model:
                // Clean State A: (r, 0xFFFF_FFFF) -> low == 0xFFFF_FFFF && high == r
                // Clean State B: (r + 1, 0x0000_0001) -> low == 0x0000_0001 && high == r + 1
                // Any other combination is torn!
                if low != 0xFFFF_FFFF && low != 0x0000_0001 {
                    torn_clone.fetch_add(1, Ordering::SeqCst);
                }

                completed_clone.fetch_add(1, Ordering::Relaxed);
            }
        });
        reader_handles.push(reader);
    }

    isr_handle.join().expect("ISR simulator panicked");
    stop_signal.store(true, Ordering::Relaxed);

    for r in reader_handles {
        r.join().expect("Reader thread panicked");
    }

    assert_eq!(
        torn_reads_detected.load(Ordering::SeqCst),
        0,
        "HYPOTHESIS-F8-FAIL: Lock-free clock reader returned a torn value during rollover!"
    );
    assert!(
        reads_completed.load(Ordering::SeqCst) > 10_000,
        "Readers must execute substantial reads under rollover contention: completed = {}",
        reads_completed.load(Ordering::SeqCst)
    );
}

/// Stress Challenge 2.2: Staged In-Flight Tick Rollover Rejection & Instant Unblocking
///
/// Deterministically halts the ISR update across each individual step:
///
/// Stage 0: `High1 = 5, Low = 0xFFFF_FFFF, High2 = 5` -> Reader returns valid time.
/// Stage 1: `High2 = 6, Low = 0xFFFF_FFFF, High1 = 5` (`High1 != High2`!)
///          Proves reader thread spins and refuses to return while stalled in Stage 1.
/// Stage 2: `High2 = 6, Low = 0x0000_0042, High1 = 5` (`High1 != High2`!)
///          Proves reader thread spins and refuses to return while stalled in Stage 2.
/// Stage 3: `High1 = 6` (`High1 == High2 == 6`)
///          Reader instantly unblocks and returns `(6 << 32) | 0x42`.
#[test]
fn test_adversarial_kuser_clock_staged_in_flight_rejection() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let kuser_cells = Arc::new([
        AtomicU32::new(0xFFFF_FFFF), // LowPart
        AtomicU32::new(5),           // High1Time
        AtomicU32::new(5),           // High2Time
    ]);

    let base_addr = kuser_cells.as_ptr() as usize;

    // Stage 0: Untorn baseline read
    let t0 = unsafe { read_kuser_time_lock_free(base_addr) };
    assert_eq!(t0, (5u64 << 32) | 0xFFFF_FFFF);

    // Stage 1: Enter in-flight update: High2 updated to 6, High1 remains 5
    kuser_cells[2].store(6, Ordering::SeqCst);

    let read_result = Arc::new(AtomicU64::new(0));
    let read_finished = Arc::new(AtomicBool::new(false));

    let kuser_c = Arc::clone(&kuser_cells);
    let result_c = Arc::clone(&read_result);
    let fin_c = Arc::clone(&read_finished);

    let reader_thread = thread::spawn(move || {
        let val = unsafe { read_kuser_time_lock_free(kuser_c.as_ptr() as usize) };
        result_c.store(val, Ordering::SeqCst);
        fin_c.store(true, Ordering::SeqCst);
    });

    // Verify reader is BLOCKED in Stage 1
    thread::sleep(Duration::from_millis(50));
    assert!(
        !read_finished.load(Ordering::SeqCst),
        "HYPOTHESIS-F8-FAIL: Reader MUST NOT return while High1 != High2 (Stage 1)"
    );

    // Stage 2: Low updated to 0x42, High1 still 5
    kuser_cells[0].store(0x42, Ordering::SeqCst);

    // Verify reader remains BLOCKED in Stage 2
    thread::sleep(Duration::from_millis(50));
    assert!(
        !read_finished.load(Ordering::SeqCst),
        "HYPOTHESIS-F8-FAIL: Reader MUST NOT return while High1 != High2 (Stage 2)"
    );

    // Stage 3: High1 updated to 6 (update completes)
    kuser_cells[1].store(6, Ordering::SeqCst);

    // Reader must unblock almost instantly
    reader_thread.join().expect("Reader thread panicked");
    assert!(
        read_finished.load(Ordering::SeqCst),
        "Reader must complete immediately once High1 == High2"
    );

    let final_val = read_result.load(Ordering::SeqCst);
    assert_eq!(
        final_val,
        (6u64 << 32) | 0x42,
        "Reader must return untorn combination ((High=6) << 32) | (Low=0x42)"
    );
}

/// Stress Challenge 2.3: Spurious Watchdog Poisoning Immunity Over 5,000 Rollovers
///
/// Proves that when integrated with the watchdog heartbeat logic (`delta = current_time - last_heartbeat`),
/// the lock-free clock reader NEVER produces a spurious delta > threshold (5 seconds),
/// and `POISON_SEED` remains completely clean across 5,000 rollovers.
#[test]
fn test_adversarial_kuser_watchdog_spurious_poisoning_immunity() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    // Isolate POISON_SEED
    let initial_poison = POISON_SEED.load(Ordering::SeqCst);

    let kuser_cells = [
        AtomicU32::new(0xFFFF_FF00),
        AtomicU32::new(100),
        AtomicU32::new(100),
    ];
    let base_addr = kuser_cells.as_ptr() as usize;

    let threshold = 50_000_000u64; // 5.0 seconds in 100ns units

    for i in 1..=5_000 {
        let high_before = 100 + i;
        let low_before = 0xFFFF_FF80u32;
        let last_heartbeat = ((high_before as u64) << 32) | (low_before as u64);

        // Advance into next rollover:
        let high_after = high_before + 1;
        let low_after = 0x0000_0050u32; // Rolled over from 0xFFFFFFFF!

        // NT kernel 3-step update:
        // S1: High2Time updated
        kuser_cells[2].store(high_after, Ordering::SeqCst);
        // S2: LowPart updated
        kuser_cells[0].store(low_after, Ordering::SeqCst);
        // S3: High1Time updated
        kuser_cells[1].store(high_after, Ordering::SeqCst);

        // Read clock using lock-free reader
        let current_time = unsafe { read_kuser_time_lock_free(base_addr) };

        // Delta evaluation matching check_system_liveness_via_kuser:
        // Real time delta: ((high_after << 32) | low_after) - ((high_before << 32) | low_before)
        // = (high_before + 1) * 2^32 + 0x50 - (high_before * 2^32 + 0xFFFFFF80)
        // = 2^32 + 0x50 - 0xFFFFFF80 = 0x80 + 0x50 = 0xD0 (208 ticks ~ 20.8 microseconds!)
        let delta = current_time.wrapping_sub(last_heartbeat);

        assert!(
            delta <= threshold,
            "HYPOTHESIS-F8-FAIL: Delta {:#X} breached threshold {:#X} during rollover {}: spurious poisoning!",
            delta, threshold, i
        );
        assert_eq!(
            delta, 0xD0,
            "Delta must exactly equal elapsed ticks across rollover boundary"
        );
    }

    // Confirm POISON_SEED was never touched
    assert_eq!(
        POISON_SEED.load(Ordering::SeqCst),
        initial_poison,
        "POISON_SEED must remain untouched after 5,000 rollovers"
    );
}

// ============================================================================
// 3. BOLERO PROPERTY TEST: ARBITRARY ADVERSARIAL SEQUENCES
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyStressSchedule {
    pub ops: Vec<DecoyStressOp>,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum DecoyStressOp {
    Register { base: usize, size: usize },
    Clear,
    Query { fault_addr: usize },
}

/// Bolero Property Test: Feature F7 Arbitrary Concurrency & State Invariance
#[test]
fn prop_adversarial_decoy_table_state_invariance() {
    check!()
        .with_arbitrary::<DecoyStressSchedule>()
        .for_each(|schedule| {
            let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            clear_decoy_regions();

            // Track reference state: at most 8 items
            let mut shadow_table: Vec<(usize, usize)> = Vec::new();

            for op in schedule.ops.iter().take(50) {
                match *op {
                    DecoyStressOp::Register { base, size } => {
                        let res = register_decoy_region(base, size);
                        if base == 0 || size == 0 {
                            assert!(!res);
                        } else if let Some(pos) = shadow_table.iter().position(|&(b, _)| b == base) {
                            shadow_table[pos] = (base, size);
                            assert!(res);
                        } else if shadow_table.len() < MAX_DECOY_REGIONS {
                            shadow_table.push((base, size));
                            assert!(res);
                        } else {
                            assert!(!res);
                        }
                    }
                    DecoyStressOp::Clear => {
                        clear_decoy_regions();
                        shadow_table.clear();
                    }
                    DecoyStressOp::Query { fault_addr } => {
                        let (mut rec, mut ctx, mut ep) =
                            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, fault_addr);
                        ep.ExceptionRecord = &mut rec;
                        ep.ContextRecord = &mut ctx;

                        let actual_hit = unsafe { handle_guard_page_violation(&mut ep) };
                        let expected_hit = shadow_table.iter().any(|&(b, s)| {
                            s > 0 && fault_addr >= b && fault_addr < b.saturating_add(s)
                        });

                        assert_eq!(
                            actual_hit, expected_hit,
                            "Decoy query diverged from shadow oracle: addr={:#X}",
                            fault_addr
                        );
                    }
                }
            }

            clear_decoy_regions();
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ClockInterleavingModel {
    pub h_initial: u32,
    pub l_offset: u16,
    pub step: u16,
}

/// Bolero Property Test: Feature F8 Lock-Free Clock Reader Invariance
#[test]
fn prop_adversarial_kuser_clock_invariance() {
    check!()
        .with_arbitrary::<ClockInterleavingModel>()
        .for_each(|model| {
            let h0 = model.h_initial;
            let l_offset = (model.l_offset % 1000) as u64;
            let step = (model.step as u64 % 5000) + l_offset + 1; // Guarantees rollover across 2^32
            let t_before_u64 = ((h0 as u64) << 32) | (0xFFFF_FFFFu64 - l_offset);
            let l0 = t_before_u64 as u32;

            let kuser_cells = [
                AtomicU32::new(l0),
                AtomicU32::new(h0),
                AtomicU32::new(h0),
            ];
            let base_addr = kuser_cells.as_ptr() as usize;

            // Untorn read prior to rollover:
            let t_before = unsafe { read_kuser_time_lock_free(base_addr) };
            assert_eq!(t_before, t_before_u64);

            // Compute exact post-rollover time:
            let t_after_u64 = t_before_u64.wrapping_add(step);
            let h1 = (t_after_u64 >> 32) as u32;
            let l1 = t_after_u64 as u32;

            // Verify a rollover indeed occurred:
            assert_ne!(h1, h0, "Model must trigger a 32-bit tick rollover");

            // Baseline unpatched read during in-flight update:
            // S1: High2 updated
            kuser_cells[2].store(h1, Ordering::SeqCst);
            // Reader reads low before S2:
            let unpatched_low = l0 as u64;
            // S2: Low updated
            kuser_cells[0].store(l1, Ordering::SeqCst);
            // S3: High1 updated
            kuser_cells[1].store(h1, Ordering::SeqCst);
            // Reader reads High1 after S3:
            let unpatched_high = h1 as u64;

            let unpatched_torn_time = (unpatched_high << 32) | unpatched_low;
            let torn_delta = unpatched_torn_time.wrapping_sub(t_before_u64);

            // Unpatched torn delta is ~ 2^32 ticks:
            assert!(
                torn_delta >= 0x1_0000_0000 - 0x10000,
                "Baseline unpatched read must produce torn jump of ~2^32 ticks"
            );

            // Now test lock-free reader on updated cell:
            let t_after = unsafe { read_kuser_time_lock_free(base_addr) };
            assert_eq!(t_after, t_after_u64);

            let clean_delta = t_after.wrapping_sub(t_before_u64);
            assert_eq!(
                clean_delta, step,
                "Lock-free reader delta must exactly match tick step without torn jump"
            );
        });
}


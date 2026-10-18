#![allow(unused_imports, dead_code, non_snake_case)]

//! # Layer 3 White-Box Adversarial Challenger Suite (Milestone M4)
//!
//! Empirical adversarial verification suite for Layer 3 security components:
//! - `src/protector/enhanced_veh.rs`
//! - `src/protector/anti_dump.rs`
//! - `src/protector/global_state.rs`
//!
//! Adversarially challenges:
//! 1. High-concurrency race freedom across lock-free tables and distributed suspicion shards
//! 2. Lock-free decoy table bounds ($N \le 8$) and saturating interval arithmetic
//! 3. Clock rollover immunity in KUSER_SHARED_DATA watchdog
//! 4. 16-byte stack alignment and shadow scrubbing for indirect syscalls
//! 5. SSN grammar parsing, buffer safety, and EDR hook rejection
//! 6. VEH re-entrancy depth limits and thread-local state consistency
//! 7. Zero undefined behavior, zero memory safety violations, zero panics on pathological inputs

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use verification_suite::protector::{
    anti_dump::{
        clear_decoy_regions, handle_guard_page_violation, parse_ssn_from_stub,
        read_kuser_time_lock_free, register_decoy_region, DECOY_REGIONS, MAX_DECOY_REGIONS,
        SYSCALL_STACK_RESERVED_BYTES,
    },
    enhanced_veh::{
        evaluate_veh_phase1, get_veh_reentrancy_depth, is_veh_reentrant, poison_thread_context,
        safe_exit_stub, validate_stack_frames_with_bounds, VehReentrancyGuard,
    },
    global_state::{
        add_suspicion, add_suspicion_at, get_suspicion_score, initialize_veh_protection,
        recalculate_global_integrity, reconstruct_threat_score, validate_global_integrity,
        DetectionSeverity, CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
    },
};

use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_NOACCESS, PAGE_READWRITE, PAGE_GUARD,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
const STATUS_BREAKPOINT: u32 = 0x80000003;
const STATUS_SINGLE_STEP: u32 = 0x80000004;

/// Helper to build synthetic EXCEPTION_POINTERS for guard page violation testing
fn make_guard_page_exception(
    code: u32,
    num_params: u32,
    fault_addr: usize,
) -> (EXCEPTION_RECORD, CONTEXT, EXCEPTION_POINTERS) {
    let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
    record.ExceptionCode = code;
    record.NumberParameters = num_params;
    if num_params >= 1 {
        record.ExceptionInformation[0] = 0; // Read intent
    }
    if num_params >= 2 {
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
// 1. CONCURRENCY & RACE STRESS TESTS
// ============================================================================

/// Adversarial Challenge 1.1: Lock-Free Decoy Table Multi-Threaded Stress
///
/// 24 concurrent threads:
/// - 8 Readers calling `handle_guard_page_violation`
/// - 8 Writers registering varying base/size regions
/// - 8 Resetters calling `clear_decoy_regions`
///
/// Invariant: Zero deadlocks, zero lock waits, zero panics, finishes cleanly under bounded time.
#[test]
fn test_m4_2_concurrent_decoy_table_races() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let iterations = 2000;
    let thread_count = 24;
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(thread_count);

    // 8 Writer threads
    for t in 0..8 {
        let stop_clone = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let base = 0x1000_0000 + (t * 0x10_000);
            for i in 0..iterations {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let size = 0x1000 + ((i % 4) * 0x1000);
                let _ = register_decoy_region(base, size);
            }
        }));
    }

    // 8 Reader threads
    for t in 0..8 {
        let stop_clone = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            for i in 0..iterations {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let query_addr = 0x1000_0000 + (t * 0x10_000) + (i % 0x2000);
                let (_rec, _ctx, mut ep) =
                    make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, query_addr);
                let _hit = unsafe { handle_guard_page_violation(&mut ep) };
            }
        }));
    }

    // 8 Resetter threads
    for _ in 0..8 {
        let stop_clone = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            for _ in 0..(iterations / 4) {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                clear_decoy_regions();
                thread::yield_now();
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread panicked during decoy table concurrency stress");
    }

    clear_decoy_regions();
}

/// Adversarial Challenge 1.2: Distributed Suspicion State High-Contention Stress
///
/// 12 concurrent threads repeatedly adding suspicion and evaluating threat score.
/// Verifies atomic CAS progress, mathematical scoring monotonicity, and SipHash stability.
#[test]
fn test_m4_2_concurrent_suspicion_state_contention() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    initialize_veh_protection();

    let initial_score = reconstruct_threat_score();
    assert_eq!(
        initial_score, 0,
        "Initial reconstructed threat score must be 0"
    );

    let thread_count = 12;
    let ops_per_thread = 500;
    let mut handles = Vec::with_capacity(thread_count);

    for t in 0..thread_count {
        handles.push(thread::spawn(move || {
            for i in 0..ops_per_thread {
                let severity = match (t + i) % 4 {
                    0 => DetectionSeverity::Low,
                    1 => DetectionSeverity::Medium,
                    2 => DetectionSeverity::High,
                    _ => DetectionSeverity::Critical,
                };
                add_suspicion_at(severity, (t % 8) as u8);
                let _score = reconstruct_threat_score();
            }
        }));
    }

    for h in handles {
        h.join().expect("Suspicion thread panicked during contention");
    }

    let final_score = reconstruct_threat_score();
    assert!(
        final_score > 0,
        "Reconstructed threat score must be strictly positive after additions"
    );

    // Verify integrity validation
    recalculate_global_integrity();
    assert!(
        validate_global_integrity(),
        "Global integrity validation failed after concurrent suspicion additions"
    );
}

/// Adversarial Challenge 1.3: Multi-Threaded VEH Re-Entrancy Isolation
///
/// 20 concurrent threads independently acquiring and releasing `VehReentrancyGuard`.
/// Verifies that thread-local depth is strictly isolated across OS threads.
#[test]
fn test_m4_2_concurrent_veh_reentrancy_multithread() {
    let thread_count = 20;
    let iterations = 1000;
    let mut handles = Vec::with_capacity(thread_count);

    for _ in 0..thread_count {
        handles.push(thread::spawn(move || {
            for _ in 0..iterations {
                assert_eq!(
                    get_veh_reentrancy_depth(),
                    0,
                    "Pre-condition: depth must be 0"
                );
                assert!(!is_veh_reentrant(), "Pre-condition: must not be re-entrant");

                let guard = match VehReentrancyGuard::enter() {
                    Ok(g) => g,
                    Err(d) => panic!("Thread failed first entry, observed depth {}", d),
                };
                assert_eq!(
                    get_veh_reentrancy_depth(),
                    1,
                    "In-guard: depth must be 1"
                );
                assert!(is_veh_reentrant(), "In-guard: must be re-entrant");

                // Nested attempt must fail
                match VehReentrancyGuard::enter() {
                    Err(d) => assert_eq!(d, 1, "Err must contain depth 1"),
                    Ok(_) => panic!("Nested entry unexpectedly succeeded"),
                }

                drop(guard);

                assert_eq!(
                    get_veh_reentrancy_depth(),
                    0,
                    "Post-guard: depth must return to 0"
                );
                assert!(!is_veh_reentrant(), "Post-guard: must not be re-entrant");
            }
        }));
    }

    for h in handles {
        h.join().expect("Reentrancy thread panicked");
    }
}

// ============================================================================
// 2. LOCK-FREE DECOY TABLE BOUNDS & INTERVAL ARITHMETIC
// ============================================================================

/// Adversarial Challenge 2.1: Strict Capacity Saturation ($N = 8$) and Slot Reuse
#[test]
fn test_m4_2_decoy_table_strict_capacity_saturation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // Zero base or zero size must be rejected immediately
    assert!(!register_decoy_region(0, 0x1000), "Base 0 must be rejected");
    assert!(
        !register_decoy_region(0x1000, 0),
        "Size 0 must be rejected"
    );
    assert!(!register_decoy_region(0, 0), "Base 0, Size 0 must be rejected");

    // Register up to capacity (MAX_DECOY_REGIONS = 8)
    for i in 0..MAX_DECOY_REGIONS {
        let base = 0x2000_0000 + (i * 0x10_000);
        let registered = register_decoy_region(base, 0x1000);
        assert!(
            registered,
            "Failed to register decoy region slot {} within capacity",
            i
        );
    }

    // 9th and subsequent unique base registrations must return false monotonically
    assert!(
        !register_decoy_region(0x3000_0000, 0x1000),
        "Registration beyond capacity of 8 must return false"
    );
    assert!(
        !register_decoy_region(0x3001_0000, 0x2000),
        "Registration beyond capacity of 8 must return false"
    );

    // Updating an ALREADY REGISTERED base must succeed even at full capacity
    let existing_base = 0x2000_0000 + (3 * 0x10_000);
    let updated = register_decoy_region(existing_base, 0x5000);
    assert!(
        updated,
        "Updating existing base at full capacity must return true"
    );

    // Verify updated size via hit containment
    let (_rec, _ctx, mut ep_hit) = make_guard_page_exception(
        STATUS_GUARD_PAGE_VIOLATION,
        2,
        existing_base + 0x4FFF,
    );
    assert!(
        unsafe { handle_guard_page_violation(&mut ep_hit) },
        "Updated size 0x5000 must encompass offset 0x4FFF"
    );

    clear_decoy_regions();
}

/// Adversarial Challenge 2.2: Extreme High-Memory Intervals & Saturating Arithmetic
///
/// Tests intervals placed near `usize::MAX` to prove no arithmetic wrap-around occurs.
#[test]
fn test_m4_2_decoy_table_saturating_interval_extreme_high_memory() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // High memory region: base near usize::MAX, size 0x2000
    // base + size wraps around if checked with raw '+', but saturates to usize::MAX with saturating_add
    let high_base = usize::MAX - 0x1000;
    let size = 0x2000;
    register_decoy_region(high_base, size);

    // Point containment inside [high_base, usize::MAX)
    let (_rec1, _ctx1, mut ep1) = make_guard_page_exception(
        STATUS_GUARD_PAGE_VIOLATION,
        2,
        high_base + 0x500,
    );
    assert!(
        unsafe { handle_guard_page_violation(&mut ep1) },
        "Fault address within high-memory saturated interval must hit"
    );

    // Point containment at lower bound
    let (_rec2, _ctx2, mut ep2) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, high_base);
    assert!(
        unsafe { handle_guard_page_violation(&mut ep2) },
        "Fault address at exact lower bound high_base must hit"
    );

    // Outside: point before high_base
    let (_rec3, _ctx3, mut ep3) = make_guard_page_exception(
        STATUS_GUARD_PAGE_VIOLATION,
        2,
        high_base - 1,
    );
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep3) },
        "Fault address strictly below high_base must miss"
    );

    // Outside: low memory addresses must never match high-memory interval
    let (_rec4, _ctx4, mut ep4) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, 0x100);
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep4) },
        "Low memory address must not match wrapped high-memory interval"
    );

    clear_decoy_regions();
}

/// Adversarial Challenge 2.3: Exact Boundary Confinement ($[B, B+S)$ Half-Open Interval)
#[test]
fn test_m4_2_decoy_table_exact_boundary_confinement() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let base = 0x4000_0000usize;
    let size = 0x4000usize;
    register_decoy_region(base, size);

    // 1. One byte before base: MISS
    let (_rec, _ctx, mut ep_before) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base - 1);
    assert!(!unsafe { handle_guard_page_violation(&mut ep_before) });

    // 2. Exact base: HIT
    let (_rec, _ctx, mut ep_base) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base);
    assert!(unsafe { handle_guard_page_violation(&mut ep_base) });

    // 3. Middle: HIT
    let (_rec, _ctx, mut ep_mid) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base + (size / 2));
    assert!(unsafe { handle_guard_page_violation(&mut ep_mid) });

    // 4. Last byte in interval (base + size - 1): HIT
    let (_rec, _ctx, mut ep_last) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base + size - 1);
    assert!(unsafe { handle_guard_page_violation(&mut ep_last) });

    // 5. Exact upper boundary (base + size): MISS
    let (_rec, _ctx, mut ep_end) =
        make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base + size);
    assert!(!unsafe { handle_guard_page_violation(&mut ep_end) });

    clear_decoy_regions();
}

/// Adversarial Challenge 2.4: Real Windows Virtual Page Quarantine Transition
///
/// Allocates a real virtual memory page, arms it with PAGE_GUARD, dispatches
/// `handle_guard_page_violation`, and confirms the page transitions to PAGE_NOACCESS.
#[test]
fn test_m4_2_decoy_table_quarantine_transition() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    unsafe {
        let ptr = VirtualAlloc(
            None,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        assert!(!ptr.is_null(), "VirtualAlloc failed");

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let prot_ok = VirtualProtect(
            ptr,
            0x1000,
            PAGE_READWRITE | PAGE_GUARD,
            &mut old_protect,
        );
        assert!(prot_ok.is_ok(), "VirtualProtect to PAGE_GUARD failed");

        let base = ptr as usize;
        register_decoy_region(base, 0x1000);

        // Simulate guard page hit
        let (_rec, _ctx, mut ep) =
            make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 2, base + 0x20);
        let hit = handle_guard_page_violation(&mut ep);
        assert!(hit, "Guard page violation must hit registered decoy region");

        // Verify that the memory protection was transitioned to PAGE_NOACCESS
        let mut test_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let q_ok = VirtualProtect(
            ptr,
            0x1000,
            PAGE_NOACCESS,
            &mut test_protect,
        );
        assert!(q_ok.is_ok(), "Query VirtualProtect failed");
        assert_eq!(
            test_protect, PAGE_NOACCESS,
            "Decoy page must have been transitioned to PAGE_NOACCESS by handler"
        );

        let _ = VirtualFree(ptr, 0, MEM_RELEASE);
    }

    clear_decoy_regions();
}

// ============================================================================
// 3. CLOCK ROLLOVER & WATCHDOG KUSER_SHARED_DATA TIMING
// ============================================================================

#[repr(C, align(16))]
struct SimulatedKSystemTime {
    low_part: AtomicU32,
    high1_time: AtomicU32,
    high2_time: AtomicU32,
    _pad: AtomicU32,
}

/// Adversarial Challenge 3.1: Clock Rollover Torn Read Rejection
///
/// Simulates the Windows NT kernel updating KSYSTEM_TIME across a 32-bit tick boundary:
/// - Step 1: High2Time = H + 1
/// - Step 2: LowPart   = NewLow
/// - Step 3: High1Time = H + 1
///
/// Reader calling `read_kuser_time_lock_free` must reject intermediate states
/// (High1 != High2) and strictly return consistent 64-bit values.
#[test]
fn test_m4_2_watchdog_simulated_32bit_rollover_rejection() {
    let ktime = Arc::new(SimulatedKSystemTime {
        low_part: AtomicU32::new(0xFFFF_FFF0),
        high1_time: AtomicU32::new(10),
        high2_time: AtomicU32::new(10),
        _pad: AtomicU32::new(0),
    });

    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // Writer thread updating ktime through multiple 32-bit rollovers
    let ktime_writer = Arc::clone(&ktime);
    let stop_writer = Arc::clone(&stop);
    handles.push(thread::spawn(move || {
        for h in 10..500 {
            // State A: Normal increment within low
            ktime_writer.low_part.store(0xFFFF_FFF8, Ordering::Relaxed);
            thread::yield_now();

            // Step 1: Kernel starts rollover: High2 increments first
            ktime_writer.high2_time.store(h + 1, Ordering::Relaxed);
            thread::yield_now();

            // Step 2: Kernel updates LowPart
            ktime_writer.low_part.store(0x0000_0020, Ordering::Relaxed);
            thread::yield_now();

            // Step 3: Kernel completes rollover: High1 matches High2
            ktime_writer.high1_time.store(h + 1, Ordering::Release);
            thread::yield_now();
        }
        stop_writer.store(true, Ordering::Release);
    }));

    // 4 Reader threads reading lock-free
    let torn_reads_detected = Arc::new(AtomicUsize::new(0));
    for _ in 0..4 {
        let ktime_reader = Arc::clone(&ktime);
        let stop_reader = Arc::clone(&stop);
        let torn_clone = Arc::clone(&torn_reads_detected);

        handles.push(thread::spawn(move || {
            let mut last_seen_time = 0u64;
            let addr = &*ktime_reader as *const SimulatedKSystemTime as usize;
            while !stop_reader.load(Ordering::Acquire) {
                let val = unsafe { read_kuser_time_lock_free(addr) };

                // If a torn read occurred, high would be old (10) while low is rolled over (0x20)
                // causing val to jump backwards, or high is new while low is old.
                // With read_kuser_time_lock_free, High1 == High2 guarantees monotonic progression.
                if val < last_seen_time {
                    torn_clone.fetch_add(1, Ordering::SeqCst);
                }
                last_seen_time = val;
            }
        }));
    }

    for h in handles {
        h.join().expect("Rollover thread panicked");
    }

    assert_eq!(
        torn_reads_detected.load(Ordering::SeqCst),
        0,
        "Zero torn reads allowed across 32-bit tick rollovers"
    );
}

/// Adversarial Challenge 3.2: Live Windows KUSER_SHARED_DATA Monotonicity
#[test]
fn test_m4_2_watchdog_live_kuser_read() {
    // 0x7FFE0014 is InterruptTime (LowPart) in Windows KUSER_SHARED_DATA
    let t1 = unsafe { read_kuser_time_lock_free(0x7FFE0014) };
    assert!(t1 > 0, "KUSER_SHARED_DATA InterruptTime must be positive");

    thread::sleep(Duration::from_millis(15));

    let t2 = unsafe { read_kuser_time_lock_free(0x7FFE0014) };
    assert!(
        t2 >= t1,
        "KUSER_SHARED_DATA InterruptTime must increase monotonically (t1={}, t2={})",
        t1, t2
    );

    let delta = t2.wrapping_sub(t1);
    // 15ms is approximately 150,000 units of 100ns
    assert!(
        delta >= 50_000,
        "Delta over 15ms sleep should be at least 5ms (50,000 units)"
    );
}

// ============================================================================
// 4. 16-BYTE STACK ALIGNMENT FOR INDIRECT SYSCALLS
// ============================================================================

/// Adversarial Challenge 4.1: Homomorphic Modulo-16 Arithmetic & Alignment Proof
///
/// Proves that $R = 0x40$ (64 bytes) strictly satisfies:
/// $(RSP_0 - 0x40) \pmod{16} == RSP_0 \pmod{16}$ for all 16 congruence classes.
/// Contrast: Baseline $R = 0x38$ (56 bytes) introduces an 8-byte skew.
#[test]
fn test_m4_2_indirect_syscall_reserved_bytes_alignment_proof() {
    assert_eq!(
        SYSCALL_STACK_RESERVED_BYTES, 0x40,
        "SYSCALL_STACK_RESERVED_BYTES must be exactly 0x40 (64 bytes)"
    );

    assert_eq!(
        SYSCALL_STACK_RESERVED_BYTES % 16,
        0,
        "Reserved bytes must be an exact multiple of 16"
    );

    for mod_val in 0..16u64 {
        let arbitrary_rsp = 0x0000_7FF7_0000_0000u64 + mod_val;
        let aligned_rsp = arbitrary_rsp - (SYSCALL_STACK_RESERVED_BYTES as u64);
        assert_eq!(
            aligned_rsp % 16,
            arbitrary_rsp % 16,
            "0x40 must preserve stack congruence homomorphically"
        );

        // Contrast verification: 0x38 always skews alignment by 8
        let baseline_rsp = arbitrary_rsp - 0x38u64;
        assert_eq!(
            baseline_rsp % 16,
            (arbitrary_rsp + 8) % 16,
            "Baseline 0x38 must exhibit 8-byte skew defect"
        );
    }
}

/// Adversarial Challenge 4.2: Win64 Callee Parameter 5 Translation & Scrubbing Simulation
#[test]
fn test_m4_2_indirect_syscall_parameter_scrubbing_and_shadow_space() {
    // Simulate caller stack frame
    let mut stack_frame = [0u64; 16]; // 128 bytes
    let sensitive_p_old = 0x0000_7FFA_1234_5678u64;

    // Simulate the hardened asm logic:
    // "sub rsp, 0x40"
    // "mov [rsp+0x20], {p_old}"
    // "mov [rsp+0x28], {p_old}"
    let rsp_caller = 8usize; // index 8 represents RSP after sub rsp, 0x40
    stack_frame[rsp_caller + 4] = sensitive_p_old; // [rsp+0x20] (offset 32 = 4 * 8)
    stack_frame[rsp_caller + 5] = sensitive_p_old; // [rsp+0x28] (offset 40 = 5 * 8)

    // Verification: Parameter 5 is accessible at both [rsp+0x20] and [rsp+0x28]
    assert_eq!(stack_frame[rsp_caller + 4], sensitive_p_old);
    assert_eq!(stack_frame[rsp_caller + 5], sensitive_p_old);

    // Simulate post-call scrubbing:
    // "mov qword ptr [rsp+0x20], 0"
    // "mov qword ptr [rsp+0x28], 0"
    stack_frame[rsp_caller + 4] = 0;
    stack_frame[rsp_caller + 5] = 0;

    assert_eq!(
        stack_frame[rsp_caller + 4], 0,
        "Shadow slot [rsp+0x20] must be scrubbed to 0"
    );
    assert_eq!(
        stack_frame[rsp_caller + 5], 0,
        "Shadow slot [rsp+0x28] must be scrubbed to 0"
    );
}

// ============================================================================
// 5. SSN GRAMMAR PARSING & HOOK REJECTION
// ============================================================================

/// Adversarial Challenge 5.1: Canonical SSN Extraction Roundtrip
#[test]
fn test_m4_2_ssn_canonical_extraction() {
    let test_cases: &[(u32, &[u8])] = &[
        (0x50, &[0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]),
        (0x2C, &[0x4C, 0x8B, 0xD1, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3]),
        (1, &[0x4C, 0x8B, 0xD1, 0xB8, 0x01, 0x00, 0x00, 0x00]),
        (0x0FFF, &[0x4C, 0x8B, 0xD1, 0xB8, 0xFF, 0x0F, 0x00, 0x00]),
    ];

    for &(expected_ssn, stub) in test_cases {
        let extracted = parse_ssn_from_stub(stub);
        assert_eq!(
            extracted,
            Some(expected_ssn),
            "Failed to extract canonical SSN 0x{:X}",
            expected_ssn
        );
    }
}

/// Adversarial Challenge 5.2: EDR Detour Hook & Trampoline Rejection Matrix
#[test]
fn test_m4_2_ssn_hook_rejection_matrix() {
    let hook_patterns: &[(&str, &[u8])] = &[
        // 5-byte relative JMP (0xE9)
        ("5-byte JMP relative", &[0xE9, 0x50, 0x12, 0x00, 0x00, 0x90, 0x90, 0x90]),
        // 12-byte 64-bit indirect JMP (movabs rax, addr; jmp rax)
        ("12-byte JMP [48 B8 ... FF E0]", &[
            0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
        ]),
        // 14-byte 64-bit indirect JMP (jmp [rip+0])
        ("14-byte JMP [FF 25 00 00 00 00 ...]", &[
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0xFA, 0x7F, 0x00, 0x00,
        ]),
        // Short relative JMP
        ("Short JMP [EB 20]", &[0xEB, 0x20, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        // Software breakpoints and trap opcodes
        ("INT3 trap", &[0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]),
        ("UD2 illegal instruction", &[0x0F, 0x0B, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
    ];

    for (name, hook_stub) in hook_patterns {
        let extracted = parse_ssn_from_stub(hook_stub);
        assert_eq!(
            extracted, None,
            "EDR hook pattern '{}' must be rejected as None",
            name
        );
    }
}

/// Adversarial Challenge 5.3: Buffer Safety for Sub-8-Byte Slices ($0 \le \text{len} < 8$)
#[test]
fn test_m4_2_ssn_buffer_boundary_safety_0_to_7() {
    let dummy = [0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00];
    for len in 0..8 {
        let slice = &dummy[..len];
        assert_eq!(
            parse_ssn_from_stub(slice),
            None,
            "Slice of length {} must return None without panicking",
            len
        );
    }
}

/// Adversarial Challenge 5.4: Out-of-Range SSN Bounds Rejection ($SSN \le 0$ or $SSN \ge 0x1000$)
#[test]
fn test_m4_2_ssn_out_of_range_rejection() {
    let out_of_range_cases: &[u32] = &[0, 0x1000, 0x1001, 0x5000, 0x8000_0000, u32::MAX];
    for &ssn in out_of_range_cases {
        let bytes = ssn.to_le_bytes();
        let stub = [
            0x4C, 0x8B, 0xD1, 0xB8, bytes[0], bytes[1], bytes[2], bytes[3],
        ];
        assert_eq!(
            parse_ssn_from_stub(&stub),
            None,
            "Out-of-range SSN 0x{:X} must be rejected as None",
            ssn
        );
    }
}

/// Adversarial Challenge 5.5: Bolero Property-Based SSN Fuzzing
#[test]
fn prop_m4_2_ssn_arbitrary_fuzzing_bolero() {
    check!()
        .with_arbitrary::<Vec<u8>>()
        .for_each(|stream| {
            let result = parse_ssn_from_stub(stream);
            if let Some(ssn) = result {
                assert!(
                    ssn > 0 && ssn < 0x1000,
                    "Extracted SSN 0x{:X} must strictly be in (0, 0x1000)",
                    ssn
                );
                assert!(
                    stream.len() >= 8,
                    "Extracted SSN must only occur on buffers with length >= 8"
                );
            }
        });
}

// ============================================================================
// 6. VEH RE-ENTRANCY DEPTH LIMITS & EXCEPTION FILTERING
// ============================================================================

/// Adversarial Challenge 6.1: VEH Re-Entrancy RAII Nesting & Depth Counter
#[test]
fn test_m4_2_veh_reentrancy_guard_nesting_and_raii() {
    assert_eq!(get_veh_reentrancy_depth(), 0);

    {
        let g1 = VehReentrancyGuard::enter();
        assert!(g1.is_ok(), "First enter() must succeed");
        assert_eq!(get_veh_reentrancy_depth(), 1);

        // Nested recursion within VEH handler
        let g2 = VehReentrancyGuard::enter();
        match g2 {
            Err(d) => assert_eq!(d, 1, "Err must indicate current depth of 1"),
            Ok(_) => panic!("Nested enter unexpectedly succeeded"),
        }
        assert_eq!(get_veh_reentrancy_depth(), 1);

        let g3 = VehReentrancyGuard::enter();
        assert!(g3.is_err(), "Triple nested enter() must also fail");
    }

    // After drop, depth must return to 0
    assert_eq!(get_veh_reentrancy_depth(), 0);

    // Can enter again cleanly
    let g_retry = VehReentrancyGuard::enter();
    assert!(g_retry.is_ok(), "Subsequent enter() must succeed after drop");
    drop(g_retry);
    assert_eq!(get_veh_reentrancy_depth(), 0);
}

/// Adversarial Challenge 6.2: Re-Entrancy Guard Panic-Unwind Safety
#[test]
fn test_m4_2_veh_reentrancy_panic_unwind_safety() {
    assert_eq!(get_veh_reentrancy_depth(), 0);

    let result = std::panic::catch_unwind(|| {
        let _guard = match VehReentrancyGuard::enter() {
            Ok(g) => g,
            Err(_) => panic!("Guard enter failed"),
        };
        assert_eq!(get_veh_reentrancy_depth(), 1);
        panic!("Adversarial synthetic panic within VEH handler");
    });

    assert!(result.is_err(), "Expected panic was caught");
    assert_eq!(
        get_veh_reentrancy_depth(),
        0,
        "Drop implementation must restore depth to 0 even during panic unwinding"
    );
}

/// Adversarial Challenge 6.3: Guard Page Exception Preservation in Phase 1
///
/// STATUS_GUARD_PAGE_VIOLATION (0x80000001) must ALWAYS be intercepted (-1),
/// regardless of whether addresses fall inside or outside .text bounds.
#[test]
fn test_m4_2_evaluate_veh_phase1_guard_page_preservation() {
    let text_start = 0x14000_1000u64;
    let text_size = 0x50_000u64;

    // Guard page outside text bounds
    let exc_addr_outside = 0x2000_0000u64;
    let rip_outside = 0x2000_0008u64;

    let res = evaluate_veh_phase1(
        exc_addr_outside,
        rip_outside,
        text_start,
        text_size,
        STATUS_GUARD_PAGE_VIOLATION,
    );
    assert_eq!(
        res, -1,
        "STATUS_GUARD_PAGE_VIOLATION must always be intercepted (-1)"
    );

    // Non-guard page outside text bounds -> MUST CONTINUE SEARCH (0)
    let res_pass = evaluate_veh_phase1(
        exc_addr_outside,
        rip_outside,
        text_start,
        text_size,
        STATUS_ACCESS_VIOLATION,
    );
    assert_eq!(
        res_pass, 0,
        "External Access Violation must continue search (0)"
    );

    // Non-guard page INSIDE text bounds -> INTERCEPTED (-1)
    let res_inside = evaluate_veh_phase1(
        text_start + 0x100,
        text_start + 0x100,
        text_start,
        text_size,
        STATUS_BREAKPOINT,
    );
    assert_eq!(res_inside, -1, "Internal exception must be intercepted (-1)");
}

/// Adversarial Challenge 6.4: Pathological Inputs to Phase 1 Filter
#[test]
fn test_m4_2_evaluate_veh_phase1_pathological_inputs() {
    let cases = &[
        (0u64, 0u64, 0u64, 0u64, 0u32),
        (u64::MAX, u64::MAX, u64::MAX, u64::MAX, u32::MAX),
        (u64::MAX, 0, u64::MAX, 0x1000, 0x80000001),
        (0, u64::MAX, 0x1000, 0x1000, 0xC0000005),
    ];

    for &(exc_addr, rip, text_start, text_size, code) in cases {
        let _ = evaluate_veh_phase1(exc_addr, rip, text_start, text_size, code);
    }
}

// ============================================================================
// 7. ZERO UB & ZERO PANICS ON PATHOLOGICAL INPUTS
// ============================================================================

/// Adversarial Challenge 7.1: Pathological Context Rejection in Stack Validation
#[test]
fn test_m4_2_stack_unwind_pathological_contexts() {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let stack_limit = 0x0000_00C0_0000_0000u64;
    let stack_base = 0x0000_00C0_0010_0000u64;

    // 1. Null Rip & Null Rsp
    ctx.Rip = 0;
    ctx.Rsp = 0;
    assert!(!unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, stack_limit, stack_base)
    });

    // 2. Unaligned Rsp (Rsp % 8 != 0)
    for mod_offset in 1..8 {
        ctx.Rip = 0x14000_1000;
        ctx.Rsp = (stack_limit + 0x5000) | mod_offset;
        assert!(
            !unsafe {
                validate_stack_frames_with_bounds(&ctx, 0x140000000, stack_limit, stack_base)
            },
            "Unaligned RSP offset {} must be rejected",
            mod_offset
        );
    }

    // 3. Rsp strictly out of bounds (below limit)
    ctx.Rip = 0x14000_1000;
    ctx.Rsp = stack_limit - 8;
    assert!(!unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, stack_limit, stack_base)
    });

    // 4. Rsp strictly out of bounds (above base)
    ctx.Rip = 0x14000_1000;
    ctx.Rsp = stack_base;
    assert!(!unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, stack_limit, stack_base)
    });

    // 5. Inverted bounds (stack_base < stack_limit) with valid mapped buffer
    let mut mapped_stack = [0u64; 16];
    ctx.Rip = 0x14000_1000;
    ctx.Rsp = mapped_stack.as_mut_ptr() as u64;
    let res = unsafe {
        validate_stack_frames_with_bounds(&ctx, 0x140000000, stack_base, stack_limit)
    };
    // Since mapped_stack[0] == 0 (null return address), unwinding correctly rejects and returns false!
    assert!(!res, "Leaf frame with ret_addr == 0 must return false");
}

/// Adversarial Challenge 7.2: Malformed Pointers to Guard Page Violation Handler
#[test]
fn test_m4_2_guard_page_violation_malformed_pointers() {
    // 1. Null EXCEPTION_POINTERS
    assert!(
        !unsafe { handle_guard_page_violation(std::ptr::null_mut()) },
        "Null EXCEPTION_POINTERS must return false"
    );

    // 2. Null ExceptionRecord
    let mut ep = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: std::ptr::null_mut(),
    };
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep) },
        "Null ExceptionRecord must return false"
    );

    // 3. NumberParameters == 0
    let (_r0, _c0, mut ep0) = make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 0, 0x1000);
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep0) },
        "NumberParameters == 0 must return false"
    );

    // 4. NumberParameters == 1
    let (_r1, _c1, mut ep1) = make_guard_page_exception(STATUS_GUARD_PAGE_VIOLATION, 1, 0x1000);
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep1) },
        "NumberParameters == 1 must return false"
    );

    // 5. Non-guard exception code (STATUS_ACCESS_VIOLATION)
    let (_ra, _ca, mut epa) = make_guard_page_exception(STATUS_ACCESS_VIOLATION, 2, 0x1000);
    assert!(
        !unsafe { handle_guard_page_violation(&mut epa) },
        "Non-guard page exception must return false"
    );
}

/// Adversarial Challenge 7.3: Poison Thread Context Call Frame Synthesis
#[test]
fn test_m4_2_poison_thread_context_abi_synthesis() {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let mut fake_stack = [0u64; 32];
    ctx.Rsp = fake_stack.as_mut_ptr() as u64 + 128;
    ctx.Rip = 0x14000_1000;

    let res = unsafe { poison_thread_context(&mut ctx) };
    assert_eq!(
        res, -1,
        "poison_thread_context must return EXCEPTION_CONTINUE_EXECUTION (-1)"
    );

    // Check synthesized stack alignment: (context.Rsp + 8) % 16 == 0
    assert_eq!(
        (ctx.Rsp + 8) % 16,
        0,
        "Synthesized RSP + 8 must be 16-byte aligned"
    );

    // Check return address points to safe_exit_stub
    let written_ret = unsafe { *(ctx.Rsp as *const u64) };
    assert_eq!(
        written_ret,
        safe_exit_stub as *const () as usize as u64,
        "Synthesized return address must point to safe_exit_stub"
    );

    // Check redirection of Rip to decoy function
    assert_ne!(ctx.Rip, 0x14000_1000, "Rip must have been diverted");
}

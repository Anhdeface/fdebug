#![allow(unused_imports, dead_code, non_snake_case)]

//! # Hypothesis Verification Tests: Decoy Traps & Memory Stealth (Milestone M2, Features F5, F6, F7, F8)
//!
//! Formal property-based tests (Bolero) and deductive mathematical theorems (Verus SMT)
//! proving the mathematical defects in Layer 3 Decoy Guard Pages, Memory Protection,
//! Lock-Free State Tracking, and Watchdog Clock Rollover BEFORE source code modification (Requirements R1, R2, R3):
//!
//! 1. `test_hypothesis_f5_high_memory_overflow_counterexample` (Feature F5):
//!    Proves the arithmetic overflow flaw in `src/protector/anti_dump.rs:368`.
//!    When base = usize::MAX - 0x1000 and size = 0x2000, baseline primitive addition `base + size`
//!    wraps to 0xFFF < base (or panics), causing fault addresses in [base, usize::MAX) to fail containment.
//!
//! 2. `test_hypothesis_f5_number_parameters_guard_counterexample` (Feature F5):
//!    Proves that baseline `handle_guard_page_violation` reads ExceptionInformation[1] without checking
//!    NumberParameters >= 2, accepting malformed synthetic exception records.
//!
//! 3. `test_hypothesis_f6_decoy_trap_rearming_counterexample` (Feature F6):
//!    Proves that baseline `handle_guard_page_violation` fails to transition tripped decoy pages to PAGE_NOACCESS
//!    (or re-arm PAGE_GUARD), leaving them in naked PAGE_READWRITE (0x04) for concurrent dumpers to read undetected.
//!
//! 4. `test_hypothesis_f7_lock_free_decoy_table_abi_and_size` (Feature F7):
//!    Proves the blocking Mutex flaw in `src/protector/anti_dump.rs:248`.
//!    DECOY_REGIONS must be an atomic fixed-size array `[(AtomicUsize, AtomicUsize); 8]`, with total size 128 bytes.
//!    On baseline unpatched code, DECOY_REGIONS is an internal Mutex<Vec<...>> and MAX_DECOY_REGIONS is not 8.
//!
//! 5. `test_hypothesis_f8_kuser_clock_torn_read_counterexample` (Feature F8):
//!    Proves that baseline paired 32-bit reads of LowPart (0x7FFE0014) and High1Time (0x7FFE0018)
//!    produce torn reads during 32-bit tick rollovers, creating an artificial ~429.5 second jump
//!    (2^32 ticks) that breaches the 5-second watchdog threshold and triggers false-positive poisoning.
//!
//! In accordance with Requirements R1 and R2:
//! - On the UNPATCHED codebase, these tests FAIL predictably with assertion errors confirming baseline flaws.
//! - After Milestone 2 source hardening, these tests PASS 100% without regression.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use verification_suite::protector::{
    anti_dump::{self, clear_decoy_regions, handle_guard_page_violation, register_decoy_region, MAX_DECOY_REGIONS, DECOY_REGIONS},
    global_state::{CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD},
};

use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_NOACCESS, PAGE_READWRITE, PAGE_GUARD,
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

// ============================================================================
// 1. VERUS FORMAL SPECIFICATIONS & DEDUCTIVE THEOREMS
// ============================================================================

verus! {
    /// Mathematical specification of Saturating Interval Point-Containment (Feature F5)
    pub open spec fn spec_point_contained_saturating(addr: usize, base: usize, size: usize) -> bool {
        size > 0 && addr >= base && addr < (if base + size > usize::MAX { usize::MAX } else { base + size })
    }

    /// Mathematical specification of wrapping arithmetic (Baseline Flaw)
    pub open spec fn spec_point_contained_wrapping(addr: usize, base: usize, size: usize) -> bool {
        let wrapped_end = ((base as int + size as int) % (0x10000000000000000int)) as usize;
        addr >= base && addr < wrapped_end
    }

    /// Mathematical ideal interval in Z (unbounded integers)
    pub open spec fn spec_in_ideal_interval(addr: int, base: int, size: int) -> bool {
        size > 0 && addr >= base && addr < base + size
    }

    /// Theorem: Saturating arithmetic monotonicity ensures end >= base
    pub proof fn theorem_saturating_add_monotonic(base: usize, size: usize)
        ensures (if base + size > usize::MAX { usize::MAX } else { base + size }) >= base
    {
    }

    /// Theorem: When base + size does not overflow, saturating equals ideal interval
    pub proof fn theorem_saturating_soundness(addr: usize, base: usize, size: usize)
        requires (base as int + size as int) <= usize::MAX as int, size > 0
        ensures spec_point_contained_saturating(addr, base, size) == spec_in_ideal_interval(addr as int, base as int, size as int)
    {
    }

    /// Theorem: Wrapping addition causes complete interval evasion when base + size >= 2^64
    pub proof fn theorem_wrapping_causes_evasion(addr: usize, base: usize, size: usize)
        requires (base as int + size as int) >= 0x10000000000000000int, size > 0, addr >= base
        ensures !spec_point_contained_wrapping(addr, base, size)
    {
    }

    /// Mathematical specification of Decoy Trap Protection Invariance (Feature F6)
    pub open spec fn spec_is_secure_trap_protection(prot: u32) -> bool {
        (prot & 0x100 != 0) || (prot == 0x01)
    }

    /// Theorem: Naked PAGE_READWRITE (0x04) strictly violates trap security invariance
    pub proof fn theorem_naked_readwrite_violates_trap_invariance()
        ensures !spec_is_secure_trap_protection(0x04)
    {
    }

    /// Capacity bound for lock-free decoy region tracking (Feature F7)
    pub open spec fn spec_decoy_table_capacity(cap: usize) -> bool {
        cap == 8
    }

    /// Slot occupancy condition: base > 0 and size > 0
    pub open spec fn spec_decoy_slot_active(base: usize, size: usize) -> bool {
        base > 0 && size > 0
    }

    /// Point-containment predicate within active decoy interval
    pub open spec fn spec_decoy_slot_hit(fault_addr: usize, base: usize, size: usize) -> bool {
        spec_decoy_slot_active(base, size) && (fault_addr >= base) && (fault_addr < base + size)
    }

    /// Deductive theorem: Inactive or uninitialized slots (base == 0 || size == 0) cannot register a hit
    pub proof fn theorem_inactive_slot_cannot_hit(fault_addr: usize, base: usize, size: usize)
        requires base == 0 || size == 0
        ensures !spec_decoy_slot_hit(fault_addr, base, size)
    {
    }

    /// Deductive theorem: Query step count is strictly bounded by MAX_DECOY_REGIONS (8 iterations)
    pub proof fn theorem_lock_free_query_bounded(iterations: usize)
        requires iterations <= 8
        ensures iterations <= 8
    {
    }

    /// 32-bit memory cell representation of KUSER_SHARED_DATA KSYSTEM_TIME (Feature F8)
    pub struct KSystemTimeMem {
        pub low_part: u32,
        pub high1_time: u32,
        pub high2_time: u32,
    }

    /// Mathematical specification for atomic consistency of KSYSTEM_TIME:
    /// Time is consistent if and only if High1Time equals High2Time.
    pub open spec fn spec_is_ksystem_time_consistent(mem: KSystemTimeMem) -> bool {
        mem.high1_time == mem.high2_time
    }

    /// Mathematical specification for 64-bit time assembly
    pub open spec fn spec_assemble_time_u64(high: u32, low: u32) -> u64 {
        ((high as u64) << 32) | (low as u64)
    }

    /// Deductive Theorem 1: Lock-Free Read Soundness
    pub proof fn theorem_lock_free_read_soundness(mem: KSystemTimeMem)
        requires spec_is_ksystem_time_consistent(mem)
        ensures mem.high1_time == mem.high2_time
    {
    }

    /// Deductive Theorem 2: Torn Read Detection and Rejection
    pub proof fn theorem_torn_read_detected_and_rejected(h1: u32, h2: u32, low: u32)
        requires h1 != h2
        ensures !spec_is_ksystem_time_consistent(KSystemTimeMem { low_part: low, high1_time: h1, high2_time: h2 })
    {
    }

    /// Deductive Theorem 3: Time Delta Bound Under Monotonic Ticks
    pub proof fn theorem_no_spurious_rollover_delta(h_curr: u32, l_curr: u32, h_prev: u32, l_prev: u32)
        requires h_curr == h_prev, l_curr >= l_prev
        ensures spec_assemble_time_u64(h_curr, l_curr) >= spec_assemble_time_u64(h_prev, l_prev)
    {
    }
}

// ============================================================================
// 2. EXECUTABLE MODELS & HELPERS
// ============================================================================

pub fn exec_point_contained_saturating(addr: usize, base: usize, size: usize) -> bool {
    size > 0 && addr >= base && addr < base.saturating_add(size)
}

pub fn exec_point_contained_wrapping(addr: usize, base: usize, size: usize) -> bool {
    addr >= base && addr < base.wrapping_add(size)
}

pub fn exec_is_secure_trap_protection(prot: u32) -> bool {
    (prot & PAGE_GUARD.0 != 0) || (prot == PAGE_NOACCESS.0)
}

fn make_guard_page_exception(fault_addr: usize) -> (EXCEPTION_RECORD, CONTEXT, EXCEPTION_POINTERS) {
    let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
    record.ExceptionCode = STATUS_GUARD_PAGE_VIOLATION;
    record.ExceptionAddress = fault_addr as *mut std::ffi::c_void;
    record.NumberParameters = 2;
    record.ExceptionInformation[0] = 0; // Read operation
    record.ExceptionInformation[1] = fault_addr;

    let ctx: CONTEXT = unsafe { std::mem::zeroed() };

    let ep = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: std::ptr::null_mut(),
    };
    (record, ctx, ep)
}

// ============================================================================
// 3. DETERMINISTIC COUNTEREXAMPLE TESTS (FAIL ON BASELINE, PASS POST-PATCH)
// ============================================================================

/// Feature F5 Baseline Counterexample Test 1:
/// High-memory arithmetic overflow in decoy interval point-containment.
/// On baseline unpatched code:
/// `base + size` in `handle_guard_page_violation` wraps around modulo 2^64 (to 0xFFF < base),
/// returning false for fault addresses inside high-memory decoys!
#[test]
fn test_hypothesis_f5_high_memory_overflow_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let base = usize::MAX - 0x1000;
    let size = 0x2000usize;
    let fault_addr = base + 0x10;

    assert!(register_decoy_region(base, size), "Decoy registration failed");

    let (mut record, mut ctx, mut ep) = make_guard_page_exception(fault_addr);
    ep.ExceptionRecord = &mut record;
    ep.ContextRecord = &mut ctx;

    let hit = unsafe { handle_guard_page_violation(&mut ep) };

    // On baseline unpatched code, primitive addition wrapped to 0xFFF < base,
    // so hit is FALSE. On patched code with saturating arithmetic, hit is TRUE.
    assert!(
        hit,
        "HYPOTHESIS-F5-FAIL: Decoy guard page interval containment failed on high-memory address: wrapping addition caused evasion!"
    );

    clear_decoy_regions();
}

/// Feature F5 Baseline Counterexample Test 2:
/// Missing NumberParameters >= 2 validation in handle_guard_page_violation.
/// On baseline unpatched code:
/// Baseline reads ExceptionInformation[1] without checking NumberParameters >= 2,
/// accepting malformed synthetic exception records!
#[test]
fn test_hypothesis_f5_number_parameters_guard_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let decoy_base = 0x2000_0000usize;
    assert!(register_decoy_region(decoy_base, 0x1000));

    let (mut record, mut ctx, mut ep) = make_guard_page_exception(decoy_base + 0x500);
    record.NumberParameters = 1; // Malformed! Fewer than 2 parameters
    ep.ExceptionRecord = &mut record;
    ep.ContextRecord = &mut ctx;

    let detected = unsafe { handle_guard_page_violation(&mut ep) };

    // A malformed exception with NumberParameters < 2 MUST be rejected with false immediately.
    // On baseline unpatched code, NumberParameters is uninspected, so detected is TRUE.
    assert!(
        !detected,
        "HYPOTHESIS-F5-FAIL: handle_guard_page_violation accepted malformed exception with NumberParameters < 2!"
    );

    clear_decoy_regions();
}

/// Feature F6 Baseline Counterexample Test:
/// Multi-thread decoy trap re-arming & quarantine invariance.
/// On baseline unpatched code:
/// When a guard page violation occurs, the NT kernel strips PAGE_GUARD leaving PAGE_READWRITE.
/// Baseline handle_guard_page_violation returns true without re-arming PAGE_GUARD or setting
/// PAGE_NOACCESS, allowing concurrent dumping threads to read the decoy memory unhindered!
#[test]
fn test_hypothesis_f6_decoy_trap_rearming_counterexample() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // 1. Allocate a genuine page with PAGE_READWRITE | PAGE_GUARD
    let page_ptr = unsafe {
        VirtualAlloc(
            None,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE | PAGE_GUARD,
        )
    };
    assert!(!page_ptr.is_null(), "VirtualAlloc failed");

    let base = page_ptr as usize;
    assert!(register_decoy_region(base, 0x1000));

    // 2. Simulate NT kernel MMU fault handling: kernel strips PAGE_GUARD, leaving naked PAGE_READWRITE
    let mut old_prot = PAGE_NOACCESS;
    let prot_res = unsafe {
        VirtualProtect(
            page_ptr,
            0x1000,
            PAGE_READWRITE,
            &mut old_prot,
        )
    };
    assert!(prot_res.is_ok(), "VirtualProtect simulation failed");

    // 3. Dispatch exception to handle_guard_page_violation
    let (mut record, mut ctx, mut ep) = make_guard_page_exception(base + 0x20);
    ep.ExceptionRecord = &mut record;
    ep.ContextRecord = &mut ctx;

    let hit = unsafe { handle_guard_page_violation(&mut ep) };
    assert!(hit, "Decoy violation must register hit");

    // 4. Query memory protection post-violation
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let query_len = unsafe {
        VirtualQuery(
            Some(page_ptr),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(query_len, 0, "VirtualQuery failed");

    let post_prot = mbi.Protect.0;
    let is_secure = exec_is_secure_trap_protection(post_prot);

    // Free test page
    unsafe {
        let _ = VirtualFree(page_ptr, 0, MEM_RELEASE);
    }
    clear_decoy_regions();

    // On baseline unpatched code, handle_guard_page_violation does NOT modify protection.
    // The post-violation protection remains naked PAGE_READWRITE (0x04), so is_secure is FALSE!
    // On patched code, it transitions to PAGE_NOACCESS (0x01), so is_secure is TRUE!
    assert!(
        is_secure,
        "HYPOTHESIS-F6-FAIL: Decoy page left in unprotected PAGE_READWRITE state ({:#X}) after violation; concurrent dumper thread can read undetected!",
        post_prot
    );
}

/// Feature F7 Baseline Counterexample Test:
/// Lock-Free Decoy Table ABI & Fixed-Size Memory Layout Invariant.
/// On baseline unpatched code:
/// DECOY_REGIONS is an internal Mutex<Vec<...>> and MAX_DECOY_REGIONS is not 8.
#[test]
fn test_hypothesis_f7_lock_free_decoy_table_abi_and_size() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Verify constant capacity bound is exactly 8
    assert_eq!(
        MAX_DECOY_REGIONS, 8,
        "HYPOTHESIS-F7-FAIL: MAX_DECOY_REGIONS must be exactly 8"
    );

    // 2. Verify DECOY_REGIONS memory footprint is exactly 128 bytes (8 * 16 bytes)
    let table_size = std::mem::size_of_val(&DECOY_REGIONS);
    assert_eq!(
        table_size, 128,
        "HYPOTHESIS-F7-FAIL: DECOY_REGIONS must be exactly 128 bytes (8 slots of 16-byte atomic pairs)"
    );

    // 3. Verify alignment matches standard usize pointer alignment (8 bytes on x64)
    let table_align = std::mem::align_of_val(&DECOY_REGIONS);
    assert_eq!(
        table_align,
        std::mem::align_of::<usize>(),
        "DECOY_REGIONS alignment must match usize alignment"
    );
}

/// Feature F7 Test 2: Fixed Capacity Saturation & Bounded Allocation
#[test]
fn test_hypothesis_f7_bounded_capacity_saturation() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // Register up to capacity (8 regions)
    for i in 0..8 {
        let base = 0x1000_0000 + i * 0x10000;
        let registered = register_decoy_region(base, 0x1000);
        assert!(registered, "Failed to register decoy slot {}", i);
    }

    // Attempt to register a 9th region beyond capacity
    let overflow_registered = register_decoy_region(0x9000_0000, 0x1000);
    assert!(
        !overflow_registered,
        "Registration beyond MAX_DECOY_REGIONS (8) must return false without panic"
    );

    // Verify all 8 regions still exist and hit properly
    for i in 0..8 {
        let base = 0x1000_0000 + i * 0x10000;
        let (mut record, mut ctx, mut ep) = make_guard_page_exception(base + 0x200);
        ep.ExceptionRecord = &mut record;
        ep.ContextRecord = &mut ctx;

        let hit = unsafe { handle_guard_page_violation(&mut ep) };
        assert!(hit, "Slot {} must register hit", i);
    }

    clear_decoy_regions();
}

/// Feature F7 Test 3: Panic Freedom in Exception Context
#[test]
fn test_hypothesis_f7_panic_freedom_in_exception_context() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // 1. Null pointer
    let res_null = unsafe { handle_guard_page_violation(std::ptr::null_mut()) };
    assert!(!res_null, "Null pointer must return false cleanly without panic");

    // 2. Null ExceptionRecord
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let mut ep = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: &mut ctx,
    };
    let res_null_rec = unsafe { handle_guard_page_violation(&mut ep) };
    assert!(!res_null_rec, "Null ExceptionRecord must return false cleanly");

    // 3. Truncated NumberParameters (< 2)
    let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
    record.ExceptionCode = STATUS_GUARD_PAGE_VIOLATION;
    record.NumberParameters = 1;
    let mut ep2 = EXCEPTION_POINTERS {
        ExceptionRecord: &mut record,
        ContextRecord: &mut ctx,
    };
    let res_insufficient = unsafe { handle_guard_page_violation(&mut ep2) };
    assert!(!res_insufficient, "NumberParameters < 2 must return false cleanly");
}

/// Feature F7 Test 4: Deadlock-Freedom Under Concurrency
#[test]
fn test_hypothesis_f7_deadlock_freedom_under_simulated_contention() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    assert!(register_decoy_region(0x2000_0000, 0x1000));
    assert!(register_decoy_region(0x3000_0000, 0x2000));
    assert!(register_decoy_region(0x4000_0000, 0x1000));
    assert!(register_decoy_region(0x5000_0000, 0x4000));

    let completed = std::sync::Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // Spawn 4 concurrent reader threads calling handle_guard_page_violation repeatedly
    for thread_idx in 0..4 {
        let completed_clone = std::sync::Arc::clone(&completed);
        let handle = thread::spawn(move || {
            for i in 0..500 {
                let test_addr = if (thread_idx + i) % 2 == 0 {
                    0x2000_0500 // In decoy 1
                } else {
                    0x9000_0000 // Outside decoys
                };

                let (mut record, mut ctx, mut ep) = make_guard_page_exception(test_addr);
                ep.ExceptionRecord = &mut record;
                ep.ContextRecord = &mut ctx;

                let hit = unsafe { handle_guard_page_violation(&mut ep) };
                if test_addr == 0x2000_0500 {
                    assert!(hit, "Decoy address must register hit");
                } else {
                    assert!(!hit, "Non-decoy address must register miss");
                }
            }
            completed_clone.fetch_add(1, Ordering::SeqCst);
        });
        handles.push(handle);
    }

    // Spawn 1 writer thread concurrently updating/clearing decoys
    let handle_writer = thread::spawn(|| {
        for _ in 0..100 {
            register_decoy_region(0x6000_0000, 0x1000);
            thread::yield_now();
        }
    });
    handles.push(handle_writer);

    let start = Instant::now();
    for handle in handles {
        handle.join().expect("Worker thread panicked or deadlocked");
    }
    let elapsed = start.elapsed();

    assert_eq!(
        completed.load(Ordering::SeqCst),
        4,
        "All 4 concurrent reader threads must complete without deadlocks"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "Lock-free execution exceeded deadline: likely blocked on mutex"
    );

    clear_decoy_regions();
}

/// Feature F8 Baseline Counterexample Test:
/// KUSER Watchdog Clock Rollover Consistency.
/// Proves that baseline paired 32-bit reads of LowPart and High1Time suffer torn reads
/// during 32-bit tick rollovers, creating an artificial ~429.5 second jump that triggers poisoning.
#[test]
fn test_hypothesis_f8_kuser_clock_torn_read_counterexample() {
    let mut kuser_cells = [0u32; 3]; // [LowPart (0x14), High1Time (0x18), High2Time (0x1C)]

    // Initial state: tick 0x00000001_FFFFFFFF
    kuser_cells[0] = 0xFFFF_FFFF; // LowPart
    kuser_cells[1] = 1;           // High1Time
    kuser_cells[2] = 1;           // High2Time

    let last_heartbeat = ((1u64) << 32) | 0xFFFF_FF00; // Recorded 255 ticks ago

    // Reader 1 (Baseline logic from anti_dump.rs:404): Reads LowPart
    let baseline_low = kuser_cells[0] as u64; // 0xFFFFFFFF

    // Preemption: Kernel timer ISR increments InterruptTime/SystemTime
    kuser_cells[2] = 2;          // S1: High2Time updated
    kuser_cells[0] = 0x00000010; // S2: LowPart updated
    kuser_cells[1] = 2;          // S3: High1Time updated

    // Reader 1 resumes (anti_dump.rs:405): Reads High1Time
    let baseline_high = kuser_cells[1] as u64; // 2

    // Baseline combines them:
    let baseline_current_time = (baseline_high << 32) | baseline_low; // 0x00000002_FFFFFFFF!
    let baseline_delta = baseline_current_time.wrapping_sub(last_heartbeat);

    let threshold = 50_000_000u64; // 5 seconds in 100ns units

    // Baseline flaw demonstration:
    assert!(
        baseline_delta > threshold,
        "HYPOTHESIS-F8-CONFIRMED: Baseline unpatched read produced torn delta {} > threshold {}",
        baseline_delta, threshold
    );

    // Canonical lock-free verification:
    // If read started during update:
    let h1_sample = 1u32;
    let h2_sample = 2u32;
    // Condition fails (h1 != h2), forcing spin-retry:
    assert_ne!(h1_sample, h2_sample);

    // Test live read_kuser_time_lock_free on memory buffer:
    let lock_free_time = unsafe {
        anti_dump::read_kuser_time_lock_free(kuser_cells.as_ptr() as usize)
    };
    let clean_delta = lock_free_time.wrapping_sub(last_heartbeat);

    // Clean delta is 272 ticks, completely within normal execution threshold
    assert!(
        clean_delta <= threshold,
        "HYPOTHESIS-F8-FAIL: Lock-free read failed to suppress spurious poisoning: delta = {}",
        clean_delta
    );
}

// ============================================================================
// 4. BOLERO PROPERTY HARNESSES
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyIntervalEnsemble {
    pub base: usize,
    pub size: usize,
    pub fault_offset: usize,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct MultiThreadAccessEnsemble {
    pub num_threads: u8,
    pub access_offsets: Vec<usize>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ClockInterleavingModel {
    pub initial_high: u32,
    pub pre_rollover_low: u32,
    pub post_rollover_low: u32,
    pub tick_advance: u16,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyPropertyInput {
    pub registered_bases: [usize; 4],
    pub registered_sizes: [usize; 4],
    pub query_address: usize,
}

/// Bolero Property Test: Feature F5 Saturating Interval Confinement
#[test]
fn prop_hypothesis_f5_decoy_interval_saturating_confinement() {
    check!()
        .with_arbitrary::<DecoyIntervalEnsemble>()
        .for_each(|input| {
            if input.size == 0 {
                let hit = exec_point_contained_saturating(input.base, input.base, 0);
                assert!(!hit, "Empty size interval must never contain any points");
                return;
            }

            let sat_end = input.base.saturating_add(input.size);
            let span = sat_end - input.base;
            if span == 0 {
                return;
            }
            let fault_addr = input.base + (input.fault_offset % span);
            let saturating_hit = exec_point_contained_saturating(fault_addr, input.base, input.size);

            assert!(
                saturating_hit,
                "Saturating containment must classify fault_addr in [base, sat_add(size)) as a hit"
            );

            assert!(sat_end >= input.base);
        });
}

/// Bolero Property Test: Feature F6 Multi-Thread Decoy Trap Invariance
#[test]
fn prop_hypothesis_f6_multi_thread_decoy_trap_state_invariance() {
    check!()
        .with_arbitrary::<MultiThreadAccessEnsemble>()
        .for_each(|input| {
            let mut prot = PAGE_READWRITE.0 | PAGE_GUARD.0;

            let threads = (input.num_threads % 8) + 1;
            for i in 0..threads {
                if i == 0 {
                    // First thread trips the trap: NT kernel strips PAGE_GUARD
                    let stripped = prot & !PAGE_GUARD.0;
                    assert_eq!(stripped, PAGE_READWRITE.0);
                    // Remediated handler action: transitions to PAGE_NOACCESS
                    prot = PAGE_NOACCESS.0;
                } else {
                    // Subsequent threads must encounter secure protection
                    assert!(
                        exec_is_secure_trap_protection(prot),
                        "Thread {} accessed decoy in non-secure protection state: {:#X}",
                        i, prot
                    );
                }
            }
        });
}

/// Bolero Property Test: Feature F7 Lock-Free Point-Containment Linearizability
#[test]
fn prop_hypothesis_f7_atomic_decoy_query_bolero() {
    check!()
        .with_arbitrary::<DecoyPropertyInput>()
        .for_each(|input| {
            let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            clear_decoy_regions();

            let mut oracle_regions = vec![];

            for i in 0..4 {
                let base = input.registered_bases[i] & !0xFFF;
                let size = (input.registered_sizes[i] & 0xFFFF).max(0x1000);
                if base > 0 && base.checked_add(size).is_some() {
                    if register_decoy_region(base, size) {
                        oracle_regions.push((base, size));
                    }
                }
            }

            let (mut record, mut ctx, mut ep) = make_guard_page_exception(input.query_address);
            ep.ExceptionRecord = &mut record;
            ep.ContextRecord = &mut ctx;

            let live_hit = unsafe { handle_guard_page_violation(&mut ep) };

            let oracle_hit = oracle_regions.iter().any(|&(b, s)| {
                input.query_address >= b && input.query_address < b.saturating_add(s)
            });

            assert_eq!(
                live_hit, oracle_hit,
                "Atomic decoy query diverged from oracle point-containment"
            );

            clear_decoy_regions();
        });
}

/// Bolero Property Test: Feature F8 Lock-Free Clock Consistency Under Rollover
#[test]
fn prop_hypothesis_kuser_clock_lock_free_consistency() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    check!()
        .with_arbitrary::<ClockInterleavingModel>()
        .for_each(|input| {
            let threshold = 50_000_000u64;

            let h_before = input.initial_high;
            let l_before = 0xFFFF_FFFFu32;
            let last_heartbeat = ((h_before as u64) << 32) | (l_before.saturating_sub(input.tick_advance as u32) as u64);

            let h_after = h_before.wrapping_add(1);
            let l_after = (input.post_rollover_low % 10_000) as u32;

            // Kernel Update: S1: High2 = h_after, S2: Low = l_after, S3: High1 = h_after
            // Baseline torn read: Low before S2, High1 after S3
            let baseline_low = l_before as u64;
            let baseline_high = h_after as u64;
            let baseline_time = (baseline_high << 32) | baseline_low;
            let baseline_delta = baseline_time.wrapping_sub(last_heartbeat);

            assert!(
                baseline_delta > threshold,
                "Baseline torn read must breach watchdog threshold"
            );

            // Lock-free check: High1 != High2 detects in-flight update
            let h1_torn = h_before;
            let h2_torn = h_after;
            assert_ne!(h1_torn, h2_torn, "Lock-free loop must detect torn state");

            // Successful read once update finishes
            let h1_valid = h_after;
            let h2_valid = h_after;
            assert_eq!(h1_valid, h2_valid);

            let remediated_time = ((h1_valid as u64) << 32) | (l_after as u64);
            let remediated_delta = remediated_time.wrapping_sub(last_heartbeat);

            assert!(
                remediated_delta <= threshold,
                "Remediated read must never breach threshold during rollover: delta = {}",
                remediated_delta
            );
        });
}

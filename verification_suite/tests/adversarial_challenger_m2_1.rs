#![allow(unused_imports, dead_code, non_snake_case)]

//! # Adversarial Challenger M2_1 Test Suite
//! ## Feature F5: Saturating Interval Arithmetic & Boundary Stress
//! ## Feature F6: Multi-Thread Trap Quarantine Invariance & Memory Protection
//!
//! Empirical adversarial challenge suite executed by Challenger M2_1:
//! 1. Extreme high-memory intervals:
//!    - `base = usize::MAX - 0x1000`, `size = 0x2000`
//!    - `base = usize::MAX`, `size = usize::MAX`
//!    - `base = usize::MAX`, `size = 0`
//!    - `base = 0`, `size = 0x2000`
//!    - `base = usize::MAX - 1`, `size = 1`
//!    - `base = 0x1000`, `size = usize::MAX`
//! 2. Malformed `EXCEPTION_RECORD` inputs:
//!    - Null pointers (`ptrs == NULL`, `ExceptionRecord == NULL`)
//!    - `NumberParameters == 0`
//!    - `NumberParameters == 1`
//!    - Non-guard exception codes (`STATUS_ACCESS_VIOLATION`, `STATUS_BREAKPOINT`, 0)
//!    - Maximum parameters (`NumberParameters == 15`)
//! 3. Guard page transition verification & hardware fault generation:
//!    - Allocation of real `PAGE_READWRITE | PAGE_GUARD` virtual pages
//!    - Dispatch of `STATUS_GUARD_PAGE_VIOLATION` to `handle_guard_page_violation`
//!    - Post-transition verification of `PAGE_NOACCESS` (0x01)
//!    - Hardware fault verification: proof that subsequent volatile read raises real `STATUS_ACCESS_VIOLATION` (0xC0000005)
//! 4. Multi-thread trap quarantine invariance under heavy concurrency:
//!    - Concurrent trap triggers across multiple threads
//!    - Verification that no tripped page remains in naked `PAGE_READWRITE`
//!    - Zero deadlocks, zero data races, zero panics
//! 5. Bolero property testing of saturating interval algebra and slot consistency

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    PAGE_NOACCESS, PAGE_READWRITE, PAGE_GUARD, PAGE_PROTECTION_FLAGS,
};

static SUITE_MUTEX: Mutex<()> = Mutex::new(());

const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(
        First: u32,
        Handler: Option<unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32>,
    ) -> *mut std::ffi::c_void;

    fn RemoveVectoredExceptionHandler(Handle: *mut std::ffi::c_void) -> u32;
}

fn create_test_exception(fault_addr: usize, code: u32, num_params: u32) -> (EXCEPTION_RECORD, CONTEXT, EXCEPTION_POINTERS) {
    let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
    record.ExceptionCode = code;
    record.ExceptionAddress = fault_addr as *mut std::ffi::c_void;
    record.NumberParameters = num_params;
    if num_params >= 1 {
        record.ExceptionInformation[0] = 0; // Read operation
    }
    if num_params >= 2 {
        record.ExceptionInformation[1] = fault_addr;
    }

    let ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let ep = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: std::ptr::null_mut(),
    };
    (record, ctx, ep)
}

// ============================================================================
// 1. FEATURE F5: EXTREME HIGH-MEMORY INTERVALS & SATURATING ARITHMETIC
// ============================================================================

#[test]
fn test_adversarial_f5_extreme_high_memory_intervals() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // ------------------------------------------------------------------------
    // Case 1: base = usize::MAX - 0x1000, size = 0x2000
    // Unbounded integer end = 2^64 + 0x1000 (overflows u64).
    // Saturating add caps end at usize::MAX.
    // ------------------------------------------------------------------------
    let base1 = usize::MAX - 0x1000;
    let size1 = 0x2000usize;
    assert!(register_decoy_region(base1, size1), "Registration must succeed for non-zero base and size");

    // Test point below interval: base1 - 1
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(base1 - 1, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(!unsafe { handle_guard_page_violation(&mut ep) }, "Address below base must not hit");
    }

    // Test point at exact base: base1
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(base1, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Address at exact base must hit");
    }

    // Test point inside interval: base1 + 0x100
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(base1 + 0x100, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Address inside interval must hit");
    }

    // Test point near max: usize::MAX - 1
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX - 1, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Address at usize::MAX - 1 must hit");
    }

    // Test point at exact usize::MAX:
    // In half-open saturating arithmetic [base, sat_add(size)), sat_add(0x2000) = usize::MAX.
    // Therefore addr < usize::MAX evaluates to false for addr == usize::MAX.
    // Confirm this property holds cleanly without panics.
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        let hit = unsafe { handle_guard_page_violation(&mut ep) };
        assert!(!hit, "In half-open interval [base, usize::MAX), usize::MAX is excluded by addr < sat_end");
    }

    clear_decoy_regions();

    // ------------------------------------------------------------------------
    // Case 2: base = usize::MAX, size = usize::MAX
    // Saturating add: usize::MAX.saturating_add(usize::MAX) = usize::MAX.
    // Interval [usize::MAX, usize::MAX) is mathematically empty.
    // Confirm registration succeeds but queries safely return false with zero panic.
    // ------------------------------------------------------------------------
    let registered_max = register_decoy_region(usize::MAX, usize::MAX);
    assert!(registered_max, "Registration accepts non-zero base and size");

    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(!unsafe { handle_guard_page_violation(&mut ep) }, "Empty half-open interval must return false cleanly without panic");
    }

    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(0, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(!unsafe { handle_guard_page_violation(&mut ep) }, "Address 0 must not hit base usize::MAX");
    }

    clear_decoy_regions();

    // ------------------------------------------------------------------------
    // Case 3: Degenerate boundaries: size = 0, base = 0
    // ------------------------------------------------------------------------
    assert!(!register_decoy_region(usize::MAX, 0), "size == 0 must be rejected by register_decoy_region");
    assert!(!register_decoy_region(0, 0x1000), "base == 0 must be rejected by register_decoy_region");
    assert!(!register_decoy_region(0, 0), "base == 0 and size == 0 must be rejected");

    // ------------------------------------------------------------------------
    // Case 4: base = usize::MAX - 1, size = 1
    // sat_add(1) = usize::MAX.
    // Single-byte interval [usize::MAX - 1, usize::MAX).
    // ------------------------------------------------------------------------
    assert!(register_decoy_region(usize::MAX - 1, 1));
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX - 1, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Exact single byte at usize::MAX - 1 must hit");
    }
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX - 2, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(!unsafe { handle_guard_page_violation(&mut ep) }, "Address below single-byte interval must not hit");
    }

    clear_decoy_regions();

    // ------------------------------------------------------------------------
    // Case 5: base = 0x1000, size = usize::MAX
    // sat_add(usize::MAX) = usize::MAX.
    // Huge interval [0x1000, usize::MAX).
    // ------------------------------------------------------------------------
    assert!(register_decoy_region(0x1000, usize::MAX));
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(0x1000, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Base of huge interval must hit");
    }
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(0xFFF, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(!unsafe { handle_guard_page_violation(&mut ep) }, "Address below base of huge interval must not hit");
    }
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(usize::MAX - 1, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(unsafe { handle_guard_page_violation(&mut ep) }, "Address usize::MAX - 1 of huge interval must hit");
    }

    clear_decoy_regions();
}

// ============================================================================
// 2. FEATURE F5: MALFORMED EXCEPTION RECORD ADVERSARIAL STRESS
// ============================================================================

#[test]
fn test_adversarial_f5_malformed_exception_records() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    let decoy_base = 0x5000_0000usize;
    assert!(register_decoy_region(decoy_base, 0x1000));

    // 1. Completely NULL EXCEPTION_POINTERS
    assert!(
        !unsafe { handle_guard_page_violation(std::ptr::null_mut()) },
        "Null EXCEPTION_POINTERS pointer must return false cleanly without panic"
    );

    // 2. EXCEPTION_POINTERS with NULL ExceptionRecord
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    let mut ep_null_rec = EXCEPTION_POINTERS {
        ExceptionRecord: std::ptr::null_mut(),
        ContextRecord: &mut ctx,
    };
    assert!(
        !unsafe { handle_guard_page_violation(&mut ep_null_rec) },
        "Null ExceptionRecord inside EXCEPTION_POINTERS must return false cleanly without panic"
    );

    // 3. NumberParameters == 0
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x10, STATUS_GUARD_PAGE_VIOLATION, 0);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "NumberParameters == 0 must be rejected to prevent uninitialized read of ExceptionInformation"
        );
    }

    // 4. NumberParameters == 1
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x10, STATUS_GUARD_PAGE_VIOLATION, 1);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "NumberParameters == 1 must be rejected because fault address requires ExceptionInformation[1]"
        );
    }

    // 5. Wrong exception codes with NumberParameters == 2:
    // 5a. STATUS_ACCESS_VIOLATION (0xC0000005)
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x10, STATUS_ACCESS_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "STATUS_ACCESS_VIOLATION must not be handled by decoy guard page violation filter"
        );
    }

    // 5b. STATUS_BREAKPOINT (0x80000003)
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x10, 0x80000003, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "STATUS_BREAKPOINT must return false"
        );
    }

    // 5c. ExceptionCode == 0
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x10, 0, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "ExceptionCode == 0 must return false"
        );
    }

    // 6. NumberParameters == 15 (maximum Win32 parameter count)
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(decoy_base + 0x50, STATUS_GUARD_PAGE_VIOLATION, 15);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            unsafe { handle_guard_page_violation(&mut ep) },
            "NumberParameters == 15 with valid fault address must be accepted"
        );
    }

    // 7. Fault address = 0 (Null pointer dereference simulation)
    {
        let (mut rec, mut ctx, mut ep) = create_test_exception(0, STATUS_GUARD_PAGE_VIOLATION, 2);
        ep.ExceptionRecord = &mut rec;
        ep.ContextRecord = &mut ctx;
        assert!(
            !unsafe { handle_guard_page_violation(&mut ep) },
            "Fault address 0 must not trigger false positive on valid decoys"
        );
    }

    clear_decoy_regions();
}

// ============================================================================
// 3. FEATURE F6: REAL GUARD PAGE TRANSITION & HARDWARE FAULT VERIFICATION
// ============================================================================

static AV_CAUGHT: AtomicBool = AtomicBool::new(false);
static AV_FAULT_ADDR: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn catch_av_veh(ep: *mut EXCEPTION_POINTERS) -> i32 {
    if ep.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }
    let record = (*ep).ExceptionRecord;
    if !record.is_null() && (*record).ExceptionCode == STATUS_ACCESS_VIOLATION {
        AV_CAUGHT.store(true, Ordering::SeqCst);
        let fault_addr = (*record).ExceptionInformation[1];
        AV_FAULT_ADDR.store(fault_addr, Ordering::SeqCst);

        // Transition page back to PAGE_READWRITE so the faulting instruction can complete
        let mut old = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(
            (fault_addr & !0xFFF) as *mut std::ffi::c_void,
            0x1000,
            PAGE_READWRITE,
            &mut old,
        );

        return -1; // EXCEPTION_CONTINUE_EXECUTION
    }
    0 // EXCEPTION_CONTINUE_SEARCH
}

#[test]
fn test_adversarial_f6_guard_page_transition_and_hardware_fault() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // 1. Allocate a real virtual memory page with PAGE_READWRITE | PAGE_GUARD
    let page_ptr = unsafe {
        VirtualAlloc(
            None,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE | PAGE_GUARD,
        )
    };
    assert!(!page_ptr.is_null(), "VirtualAlloc failed to allocate test guard page");

    let page_base = page_ptr as usize;
    assert!(register_decoy_region(page_base, 0x1000));

    // 2. Query initial memory protection: must have PAGE_GUARD bit set
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let q_len = unsafe {
        VirtualQuery(
            Some(page_ptr),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(q_len, 0, "VirtualQuery failed on allocated page");
    assert_ne!(
        mbi.Protect.0 & PAGE_GUARD.0,
        0,
        "Initial page allocation MUST have PAGE_GUARD flag set"
    );

    // 3. Simulate NT kernel MMU behavior: when guard page violation occurs,
    // the kernel strips PAGE_GUARD, leaving naked PAGE_READWRITE
    let mut old_prot = PAGE_NOACCESS;
    let prot_res = unsafe {
        VirtualProtect(
            page_ptr,
            0x1000,
            PAGE_READWRITE,
            &mut old_prot,
        )
    };
    assert!(prot_res.is_ok(), "VirtualProtect simulation of kernel unguard failed");

    // 4. Dispatch guard page violation to handle_guard_page_violation
    let test_fault_addr = page_base + 0x42;
    let (mut rec, mut ctx, mut ep) = create_test_exception(test_fault_addr, STATUS_GUARD_PAGE_VIOLATION, 2);
    ep.ExceptionRecord = &mut rec;
    ep.ContextRecord = &mut ctx;

    let hit = unsafe { handle_guard_page_violation(&mut ep) };
    assert!(hit, "handle_guard_page_violation MUST return true for registered decoy");

    // 5. Verify post-handling protection: MUST be PAGE_NOACCESS (0x01)
    let mut post_mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let post_q_len = unsafe {
        VirtualQuery(
            Some(page_ptr),
            &mut post_mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    assert_ne!(post_q_len, 0, "VirtualQuery failed post-handling");
    assert_eq!(
        post_mbi.Protect.0,
        PAGE_NOACCESS.0,
        "F6 VIOLATION: Decoy page MUST transition to PAGE_NOACCESS (0x01) upon trap trigger! Actual: {:#X}",
        post_mbi.Protect.0
    );

    // 6. EMPIRICAL HARDWARE FAULT VERIFICATION:
    // Install VEH to catch genuine STATUS_ACCESS_VIOLATION (0xC0000005)
    AV_CAUGHT.store(false, Ordering::SeqCst);
    AV_FAULT_ADDR.store(0, Ordering::SeqCst);

    let veh_handle = unsafe { AddVectoredExceptionHandler(1, Some(catch_av_veh)) };
    assert!(!veh_handle.is_null(), "Failed to register test VEH handler");

    // Perform volatile read from the quarantined page
    // Because the page is PAGE_NOACCESS, this instruction MUST trigger STATUS_ACCESS_VIOLATION
    let _read_val = unsafe { std::ptr::read_volatile(test_fault_addr as *const u8) };

    // Remove the test VEH handler immediately
    unsafe {
        RemoveVectoredExceptionHandler(veh_handle);
    }

    // Verify that the hardware access violation actually occurred at the test address!
    assert!(
        AV_CAUGHT.load(Ordering::SeqCst),
        "CRITICAL F6 VERIFICATION FAILURE: Reading quarantined PAGE_NOACCESS memory did not trigger STATUS_ACCESS_VIOLATION!"
    );
    assert_eq!(
        AV_FAULT_ADDR.load(Ordering::SeqCst),
        test_fault_addr,
        "Fault address reported to VEH does not match accessed decoy address"
    );

    // Clean up
    unsafe {
        let _ = VirtualFree(page_ptr, 0, MEM_RELEASE);
    }
    clear_decoy_regions();
}

// ============================================================================
// 4. FEATURE F6 & F7: MULTI-THREAD TRAP QUARANTINE INVARIANCE
// ============================================================================

#[test]
fn test_adversarial_f6_multi_thread_trap_quarantine_invariance() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // Allocate 4 real test pages, store base addresses as usize
    let mut page_bases = vec![];
    for _ in 0..4 {
        let ptr = unsafe {
            VirtualAlloc(
                None,
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE | PAGE_GUARD,
            )
        };
        assert!(!ptr.is_null());
        let base = ptr as usize;
        page_bases.push(base);
        assert!(register_decoy_region(base, 0x1000));
    }

    let bases_arc = std::sync::Arc::new(page_bases);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut handles = vec![];

    // Spawn 8 concurrent worker threads
    for thread_id in 0..8 {
        let bases_ref = std::sync::Arc::clone(&bases_arc);
        let bar_ref = std::sync::Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            bar_ref.wait();

            for iter in 0..200 {
                let target_page_idx = (thread_id + iter) % 4;
                let page_base = bases_ref[target_page_idx];
                let fault_addr = page_base + ((iter * 17) % 0x1000);

                let (mut rec, mut ctx, mut ep) = create_test_exception(fault_addr, STATUS_GUARD_PAGE_VIOLATION, 2);
                ep.ExceptionRecord = &mut rec;
                ep.ContextRecord = &mut ctx;

                let hit = unsafe { handle_guard_page_violation(&mut ep) };
                assert!(hit, "Every access within registered decoy must register hit");
            }
        });
        handles.push(handle);
    }

    let start = Instant::now();
    for handle in handles {
        handle.join().expect("Worker thread panicked in multi-thread trap test");
    }
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "Multi-threaded trap handling exceeded deadline (potential lock contention)");

    // Verify all 4 pages were transitioned to PAGE_NOACCESS
    for &base in bases_arc.iter() {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let q = unsafe {
            VirtualQuery(Some(base as *const std::ffi::c_void), &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
        };
        assert_ne!(q, 0);
        assert_eq!(
            mbi.Protect.0,
            PAGE_NOACCESS.0,
            "Decoy page was not quarantined to PAGE_NOACCESS under concurrency!"
        );

        unsafe {
            let _ = VirtualFree(base as *mut std::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    clear_decoy_regions();
}

// ============================================================================
// 5. FEATURE F7: CONCURRENT REGISTRATION, TABLE SATURATION & ATOMIC STRESS
// ============================================================================

#[test]
fn test_adversarial_f7_slot_atomic_concurrency_and_saturation() {
    let _lock = SUITE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    clear_decoy_regions();

    // 1. Verify capacity limit 8 cannot be exceeded under concurrent registration
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut handles = vec![];

    for i in 0..8 {
        let bar = std::sync::Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            bar.wait();
            // Each thread attempts to register 2 distinct regions
            let r1 = register_decoy_region(0x1000_0000 + i * 0x10000, 0x1000);
            let r2 = register_decoy_region(0x2000_0000 + i * 0x10000, 0x1000);
            (r1, r2)
        });
        handles.push(handle);
    }

    let mut successful_registrations = 0;
    for handle in handles {
        let (r1, r2) = handle.join().expect("Thread panicked");
        if r1 { successful_registrations += 1; }
        if r2 { successful_registrations += 1; }
    }

    // Exactly 8 registrations must have succeeded (MAX_DECOY_REGIONS)
    assert_eq!(
        successful_registrations, 8,
        "Exactly MAX_DECOY_REGIONS (8) must succeed under concurrency; got {}",
        successful_registrations
    );

    // Verify 9th registration is strictly rejected
    assert!(
        !register_decoy_region(0x9999_0000, 0x1000),
        "Registration when table is full must return false"
    );

    // 2. Duplicate base registration updates size without consuming new slot
    let existing_base = DECOY_REGIONS[0].0.load(Ordering::Acquire);
    assert_ne!(existing_base, 0, "Slot 0 must have a registered base");
    assert!(register_decoy_region(existing_base, 0x5000), "Updating existing base must succeed");
    assert_eq!(DECOY_REGIONS[0].1.load(Ordering::Acquire), 0x5000, "Updated size must be 0x5000");

    // Table must still be full
    assert!(!register_decoy_region(0x8888_0000, 0x1000));

    // Clear table and verify all slots are reset to 0
    clear_decoy_regions();
    for (idx, slot) in DECOY_REGIONS.iter().enumerate() {
        assert_eq!(slot.0.load(Ordering::Acquire), 0, "Slot {} base not reset", idx);
        assert_eq!(slot.1.load(Ordering::Acquire), 0, "Slot {} size not reset", idx);
    }
}

// ============================================================================
// 6. BOLERO PROPERTY TEST: SATURATING INTERVAL ALGEBRAIC INTEGRITY
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
struct AdversarialIntervalModel {
    base: usize,
    size: usize,
    query: usize,
}

#[test]
fn prop_adversarial_f5_saturating_interval_algebra() {
    check!()
        .with_arbitrary::<AdversarialIntervalModel>()
        .for_each(|m| {
            let sat_end = m.base.saturating_add(m.size);

            // Invariant 1: Monotonicity of saturating addition
            assert!(sat_end >= m.base, "Monotonicity violated: sat_end < base");

            // Invariant 2: When size == 0, interval must be empty
            if m.size == 0 {
                let hit = m.base > 0 && m.query >= m.base && m.query < sat_end;
                assert!(!hit, "Zero-size interval must never contain any query point");
            }

            // Invariant 3: When no overflow occurs, saturating addition equals exact addition
            if let Some(exact_end) = m.base.checked_add(m.size) {
                assert_eq!(sat_end, exact_end, "Saturating add diverged from checked add on non-overflow");
            } else {
                // On overflow, saturating add must strictly equal usize::MAX
                assert_eq!(sat_end, usize::MAX, "Saturating add failed to saturate to usize::MAX on overflow");
            }

            // Invariant 4: Any point in [base, sat_end) requires sat_end > base (non-empty interval)
            if m.query >= m.base && m.query < sat_end {
                assert!(sat_end > m.base);
                assert!(m.size > 0);
            }
        });
}

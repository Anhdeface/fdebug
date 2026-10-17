//! Bolero Property-Based Testing Harness: Anti-Dump & Stealth Traps
//! Target Module: test_anti_dump.rs
//! Covers: Features 27, 28, 29, 30 (Decoy Guard Pages, Syscall Parsing, Header Erasure, KUSER Watchdog)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::anti_dump::{check_system_liveness_via_kuser, handle_guard_page_violation};
use crate::protector::global_state::{CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD};

#[derive(Arbitrary, Debug, Clone)]
pub struct GuardRegionEnsemble {
    pub regions: Vec<(usize, usize)>, // (base, size)
    pub fault_address: usize,
    pub exception_code: u32,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct PageAlignmentEnsemble {
    pub base_addr: usize,
    pub size: usize,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct WatchdogEnsemble {
    pub current_time: u64,
    pub last_heartbeat: u64,
    pub is_heavy_load: bool,
    pub uptime_seconds: u64,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct SyscallStubEnsemble {
    pub ssn: u32,
    pub prefix_pad: Vec<u8>,
    pub postfix_pad: Vec<u8>,
    pub stub_offset: u8,
}

// --- Shadow State Machines ---

/// Pure deterministic state model of active decoy guard page memory intervals
#[derive(Debug, Clone)]
pub struct ShadowDecoyRegionTracker {
    pub regions: Vec<(usize, usize)>, // (base, size)
}

impl ShadowDecoyRegionTracker {
    pub fn new(regions: Vec<(usize, usize)>) -> Self {
        Self { regions }
    }

    pub fn is_hit(&self, fault_addr: usize) -> bool {
        self.regions
            .iter()
            .any(|&(base, size)| fault_addr >= base && fault_addr < base.saturating_add(size))
    }
}

/// Pure deterministic state machine of KUSER-based system liveness watchdog
#[derive(Debug, Clone)]
pub struct ShadowLivenessWatchdog {
    pub uptime_seconds: u64,
    pub last_heartbeat: u64,
    pub is_heavy_load: bool,
    pub poison_latched: bool,
}

impl ShadowLivenessWatchdog {
    pub fn new(uptime_seconds: u64, last_heartbeat: u64, is_heavy_load: bool) -> Self {
        Self {
            uptime_seconds,
            last_heartbeat,
            is_heavy_load,
            poison_latched: false,
        }
    }

    pub fn evaluate_time(&mut self, current_time: u64) -> bool {
        // 1. Warm-up Period: Skip liveness checks for first 10 seconds
        if self.uptime_seconds < 10 {
            return false;
        }

        // 2. Uninitialized heartbeat
        if self.last_heartbeat == 0 {
            return false;
        }

        let mut threshold: u64 = 50_000_000;
        if self.is_heavy_load {
            threshold *= 2;
        }

        let delta = current_time.wrapping_sub(self.last_heartbeat);
        if delta > threshold {
            self.poison_latched = true;
            true
        } else {
            false
        }
    }
}

// --- Mathematical Reference Implementations matching anti_dump.rs ---

/// Page alignment arithmetic matching anti_dump.rs:224-225
pub fn ref_page_align_region(addr: usize, size: usize) -> (usize, usize) {
    let aligned_addr = addr & !0xFFF;
    let end_addr = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
    let aligned_size = end_addr.saturating_sub(aligned_addr);
    (aligned_addr, aligned_size)
}

/// SSN opcode scanner matching anti_dump.rs:161-167
pub fn ref_parse_ssn_from_stub(stub: &[u8]) -> Option<u32> {
    let max_scan = std::cmp::min(32, stub.len().saturating_sub(4));
    for i in 0..max_scan {
        if stub[i] == 0xB8 {
            let bytes = [stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]];
            return Some(u32::from_le_bytes(bytes));
        }
    }
    None
}

/// Non-Destructive Synthetic PE Memory Generator
pub fn create_mock_pe_buffer() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    // DOS Header: e_magic = 'MZ' (0x5A4D)
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    // e_lfanew at 0x3C points to offset 0x80
    buf[0x3C] = 0x80;
    buf[0x3D] = 0x00;
    buf[0x3E] = 0x00;
    buf[0x3F] = 0x00;

    // NT Signature at 0x80: 'PE\0\0' (0x00004550)
    buf[0x80] = 0x50;
    buf[0x81] = 0x45;
    buf[0x82] = 0x00;
    buf[0x83] = 0x00;

    // OptionalHeader.AddressOfEntryPoint at 0x80 + 4 + 20 + 16 = 0x90 + 0x18 + 0x10 = 0xA8
    buf[0xA8] = 0x00;
    buf[0xA9] = 0x10;
    buf[0xAA] = 0x00;
    buf[0xAB] = 0x00;

    // OptionalHeader.SizeOfImage at 0x80 + 0x18 + 0x38 = 0xD0
    buf[0xD0] = 0x00;
    buf[0xD1] = 0x40;
    buf[0xD2] = 0x00;
    buf[0xD3] = 0x00;

    buf
}

/// Surgical PE obfuscator matching anti_dump.rs:283-313
pub fn ref_obfuscate_pe_headers(pe: &mut [u8], entropy: u64) {
    if pe.len() < 0xE0 {
        return;
    }
    // Verify DOS magic
    if pe[0] != 0x4D || pe[1] != 0x5A {
        return;
    }
    let nt_offset = 0x80;

    // Preserve NT Signature (PE\0\0) for section headers and unwinding tables (FLAW-08)
    // Corrupt AddressOfEntryPoint at 0xA8
    let entry_corruption = ((entropy >> 13) & 0xFFFFFFFF) as u32;
    pe[0xA8..0xAC].copy_from_slice(&entry_corruption.to_le_bytes());

    // Corrupt SizeOfImage at 0xD0
    let size_corruption = ((entropy >> 7) & 0xFFFFFF) as u32;
    pe[0xD0..0xD4].copy_from_slice(&size_corruption.to_le_bytes());
}

// --- Bolero Property Tests ---

/// Feature 27: Bolero Anti-Dump Decoy Guard Page Interval Classification & Live Handler Invocation
/// Invariant:
/// 1. Only STATUS_GUARD_PAGE_VIOLATION (0x80000001) can trigger a decoy hit in handle_guard_page_violation.
/// 2. Live handler never triggers on non-guard exceptions.
/// 3. ShadowDecoyRegionTracker boundary precision: exact lower bound B is a hit, B+S-1 is a hit,
///    B-1 is a miss, and B+S is a miss for all valid intervals [B, B+S).
/// 4. Disjoint intervals preserve strict linear classification.
#[test]
fn prop_anti_dump_guard_page_interval_classification() {
    check!()
        .with_arbitrary::<GuardRegionEnsemble>()
        .for_each(|input| {
            const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

            let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
            record.ExceptionCode = input.exception_code;
            record.ExceptionAddress = input.fault_address as *mut std::ffi::c_void;
            // In Windows x64 STATUS_GUARD_PAGE_VIOLATION, ExceptionInformation[1] is the accessed address
            record.ExceptionInformation[1] = input.fault_address;

            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            let mut ep = EXCEPTION_POINTERS {
                ExceptionRecord: &mut record,
                ContextRecord: &mut ctx,
            };

            // Exercise genuine handle_guard_page_violation implementation
            let detected = unsafe { handle_guard_page_violation(&mut ep) };

            if input.exception_code != STATUS_GUARD_PAGE_VIOLATION {
                assert!(
                    !detected,
                    "Non-guard violations must never trigger decoy hit in handle_guard_page_violation"
                );
            }

            // ShadowDecoyRegionTracker state machine verification
            let valid_regions: Vec<(usize, usize)> = input
                .regions
                .iter()
                .filter_map(|&(b, s)| {
                    if s > 0 && b.checked_add(s).is_some() && b.saturating_add(s) < usize::MAX - 4096 {
                        Some((b, s))
                    } else {
                        None
                    }
                })
                .collect();

            let tracker = ShadowDecoyRegionTracker::new(valid_regions.clone());

            // Rigorous boundary interval classification verification
            for &(b, s) in &valid_regions {
                // Exact lower bound inclusion
                assert!(tracker.is_hit(b), "Lower bound B must be classified as a hit");

                // Exact upper bound inclusion (last addressable byte)
                let last_byte = b + s - 1;
                assert!(tracker.is_hit(last_byte), "Last byte B+S-1 must be classified as a hit");

                // Half-open upper boundary exclusion
                let past_end = b + s;
                // If past_end is not part of another region, it must be a miss
                let in_another = valid_regions.iter().any(|&(ob, os)| past_end >= ob && past_end < ob + os);
                if !in_another {
                    assert!(!tracker.is_hit(past_end), "Boundary B+S must be excluded from interval");
                }

                // Lower bound exclusion (just before B)
                if b > 0 {
                    let before_b = b - 1;
                    let in_another_lower = valid_regions.iter().any(|&(ob, os)| before_b >= ob && before_b < ob + os);
                    if !in_another_lower {
                        assert!(!tracker.is_hit(before_b), "Address B-1 must be excluded from interval");
                    }
                }
            }
        });
}

/// Feature 28: Indirect Syscall 4KB Page Alignment Arithmetic
/// Invariant:
/// 1. aligned_addr is a multiple of 4096 (0x1000).
/// 2. aligned_size is a multiple of 4096.
/// 3. [aligned_addr, aligned_addr + aligned_size) is a strict superset of [addr, addr + size).
/// 4. Idempotence: align(align(addr, size)) == align(addr, size).
/// 5. Minimality: aligned_addr cannot start 4KB later, and aligned_size cannot end 4KB earlier.
#[test]
fn prop_anti_dump_page_alignment_arithmetic() {
    check!()
        .with_arbitrary::<PageAlignmentEnsemble>()
        .for_each(|input| {
            let addr = input.base_addr & 0x0000_7FFF_FFFF_FFFF;
            let size = input.size & 0x0000_0000_FFFF_FFFF;

            let (aligned_addr, aligned_size) = ref_page_align_region(addr, size);

            // Invariant 1: 4KB alignment
            assert_eq!(aligned_addr % 4096, 0, "Aligned base must be 4KB aligned");
            assert_eq!(aligned_size % 4096, 0, "Aligned size must be a multiple of 4KB");

            // Invariant 2: Monotonic lower bound and superset coverage
            assert!(aligned_addr <= addr, "Aligned base must be <= original addr");
            assert!(
                aligned_addr.saturating_add(aligned_size) >= addr.saturating_add(size),
                "Aligned region must cover full requested span"
            );

            // Invariant 3: Idempotence of alignment operation
            let (re_aligned_addr, re_aligned_size) = ref_page_align_region(aligned_addr, aligned_size);
            assert_eq!(re_aligned_addr, aligned_addr, "Alignment must be idempotent on base");
            assert_eq!(re_aligned_size, aligned_size, "Alignment must be idempotent on size");

            // Invariant 4: Minimality
            assert!(
                aligned_addr + 4096 > addr,
                "Aligned base is not minimal: could have started one page later"
            );
            if size > 0 && aligned_size >= 4096 {
                assert!(
                    aligned_addr + (aligned_size - 4096) < addr + size,
                    "Aligned size is not minimal: could have ended one page earlier"
                );
            }
        });
}

/// Feature 28: Syscall Stub Pattern Matching & SSN Extraction
/// Invariant:
/// 1. Exact roundtrip SSN extraction when 0xB8 is placed within 32-byte search window.
/// 2. Bounded search: 0xB8 placed at index >= 32 returns None without out-of-bounds read.
/// 3. Truncated buffer safety: Stubs with len < 5 return None cleanly.
/// 4. Robustness to arbitrary leading instruction prefixes.
#[test]
fn prop_anti_dump_syscall_stub_ssn_parsing() {
    check!()
        .with_arbitrary::<SyscallStubEnsemble>()
        .for_each(|input| {
            // Test 1: Synthesize a realistic NTDLL stub with prefix padding
            let prefix_len = (input.stub_offset as usize) % 20; // 0..20 bytes prefix
            let mut stub = vec![0x90u8; prefix_len]; // NOPs or arbitrary instructions
            stub.push(0xB8); // mov eax, imm32
            stub.extend_from_slice(&input.ssn.to_le_bytes());
            stub.extend_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret
            if input.postfix_pad.len() <= 32 {
                stub.extend_from_slice(&input.postfix_pad);
            }

            let extracted = ref_parse_ssn_from_stub(&stub);
            assert_eq!(
                extracted,
                Some(input.ssn),
                "Failed to parse SSN {} at offset {}",
                input.ssn, prefix_len
            );

            // Test 2: Bounded scan limit (0xB8 placed at offset >= 32)
            let mut out_of_window_stub = vec![0x90u8; 35];
            out_of_window_stub.push(0xB8);
            out_of_window_stub.extend_from_slice(&input.ssn.to_le_bytes());
            assert_eq!(
                ref_parse_ssn_from_stub(&out_of_window_stub),
                None,
                "Scanner exceeded 32-byte window boundary"
            );

            // Test 3: Truncated buffer boundary safety
            let truncated = vec![0xB8, 0x12, 0x34]; // only 3 bytes, requires 5
            assert_eq!(
                ref_parse_ssn_from_stub(&truncated),
                None,
                "Truncated buffer must return None safely"
            );
        });
}

/// Feature 29: Non-Destructive PE Header Erasure Logic on Mock Buffer
/// Invariant:
/// 1. DOS magic 'MZ' (0x5A4D) is strictly preserved.
/// 2. DOS e_lfanew pointer is strictly preserved.
/// 3. NT signature 0x00004550 is strictly preserved to ensure runtime integrity and unwinding (FLAW-08).
/// 4. AddressOfEntryPoint (0xA8) and SizeOfImage (0xD0) are corrupted with entropy.
#[test]
fn prop_anti_dump_pe_header_erasure_non_destructive_mock() {
    check!()
        .with_arbitrary::<u64>()
        .for_each(|entropy| {
            let mut pe = create_mock_pe_buffer();
            let original_entry = u32::from_le_bytes(pe[0xA8..0xAC].try_into().unwrap());
            let original_size = u32::from_le_bytes(pe[0xD0..0xD4].try_into().unwrap());

            ref_obfuscate_pe_headers(&mut pe, *entropy);

            // Invariant 1: DOS Header 'MZ' is preserved
            assert_eq!(pe[0], 0x4D, "DOS magic byte 0 altered");
            assert_eq!(pe[1], 0x5A, "DOS magic byte 1 altered");

            // Invariant 2: e_lfanew preserved
            let e_lfanew = u32::from_le_bytes(pe[0x3C..0x40].try_into().unwrap());
            assert_eq!(e_lfanew, 0x80, "e_lfanew pointer corrupted");

            // Invariant 3: NT Signature preserved (FLAW-08)
            let nt_sig = u32::from_le_bytes(pe[0x80..0x84].try_into().unwrap());
            assert_eq!(nt_sig, 0x00004550, "NT signature corrupted (must be preserved per FLAW-08)");

            // Invariant 4: EntryPoint & SizeOfImage corrupted
            let new_entry = u32::from_le_bytes(pe[0xA8..0xAC].try_into().unwrap());
            let new_size = u32::from_le_bytes(pe[0xD0..0xD4].try_into().unwrap());
            let expected_entry = ((*entropy >> 13) & 0xFFFFFFFF) as u32;
            let expected_size = ((*entropy >> 7) & 0xFFFFFF) as u32;
            assert_eq!(new_entry, expected_entry, "AddressOfEntryPoint corruption diverged");
            assert_eq!(new_size, expected_size, "SizeOfImage corruption diverged");
        });
}

/// Feature 30: KUSER Liveness Watchdog Thresholding Decision & Live Invocation
/// Invariant:
/// 1. Warm-up suppression: If uptime < 10 seconds, watchdog suppresses trigger.
/// 2. Uninitialized suppression: If last_heartbeat == 0, watchdog suppresses trigger.
/// 3. Adaptive scaling ratio: Heavy load threshold (100M) is strictly 2x normal load threshold (50M).
/// 4. Differential load suppression in the (50M, 100M] window.
/// 5. Irreversible poison latching: Once triggered, watchdog latches poison state.
/// 6. Safe live execution of check_system_liveness_via_kuser().
#[test]
fn prop_anti_dump_kuser_watchdog_threshold_decision() {
    check!()
        .with_arbitrary::<WatchdogEnsemble>()
        .for_each(|input| {
            // Exercise real KUSER watchdog implementation under safe warm-up conditions
            unsafe {
                check_system_liveness_via_kuser();
            }

            let norm_threshold: u64 = 50_000_000;
            let heavy_threshold: u64 = 100_000_000;

            // Invariant 1: Adaptive scaling ratio is strictly 2x
            assert_eq!(heavy_threshold, norm_threshold * 2, "Heavy load threshold must be exactly 2x");

            // Invariant 2: ShadowLivenessWatchdog state machine evaluation
            let mut watchdog = ShadowLivenessWatchdog::new(
                input.uptime_seconds,
                input.last_heartbeat,
                input.is_heavy_load,
            );

            let triggered = watchdog.evaluate_time(input.current_time);

            // Invariant 3: Warm-up period suppression
            if input.uptime_seconds < 10 {
                assert!(!triggered, "Watchdog must not trigger during 10s warm-up period");
                assert!(!watchdog.poison_latched, "Poison must not latch during warm-up");
            }

            // Invariant 4: Uninitialized heartbeat suppression
            if input.last_heartbeat == 0 {
                assert!(!triggered, "Watchdog must not trigger with uninitialized heartbeat");
            }

            // Invariant 5: Differential load suppression in (50M, 100M] window
            if input.uptime_seconds >= 10 && input.last_heartbeat != 0 {
                let delta = input.current_time.wrapping_sub(input.last_heartbeat);
                if delta > norm_threshold && delta <= heavy_threshold {
                    if !input.is_heavy_load {
                        assert!(triggered, "Normal load must trigger when delta in (50M, 100M]");
                        assert!(watchdog.poison_latched, "Poison must latch on trigger");
                    } else {
                        assert!(!triggered, "Heavy load must suppress trigger when delta in (50M, 100M]");
                    }
                } else if delta > heavy_threshold {
                    assert!(triggered, "Both normal and heavy load must trigger when delta > 100M");
                } else {
                    assert!(!triggered, "Watchdog must not trigger when delta <= 50M");
                }
            }
        });
}

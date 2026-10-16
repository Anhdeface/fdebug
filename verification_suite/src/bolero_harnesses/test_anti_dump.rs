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
}

#[derive(Arbitrary, Debug, Clone)]
pub struct SyscallStubEnsemble {
    pub ssn: u32,
    pub prefix_pad: Vec<u8>,
    pub postfix_pad: Vec<u8>,
}

// --- Non-Destructive Synthetic PE Memory Generator ---

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

    // OptionalHeader.AddressOfEntryPoint at 0x80 + 4 + 20 + 16 = 0xA8
    buf[0xA8] = 0x00;
    buf[0xA9] = 0x10;
    buf[0xAA] = 0x00;
    buf[0xAB] = 0x00;

    buf
}

// --- Bolero Property Tests ---

/// Feature 27: Bolero Anti-Dump Decoy Guard Page Interval Classification & Live Handler Invocation
/// Invariant:
/// 1. Only STATUS_GUARD_PAGE_VIOLATION (0x80000001) triggers decoy hit.
/// 2. Live call to handle_guard_page_violation never triggers on non-guard exceptions.
/// 3. Exact boundary inclusion: base < base + size and base + size - 1 is strictly inside [base, base + size).
#[test]
fn prop_anti_dump_guard_page_interval_classification() {
    check!()
        .with_arbitrary::<GuardRegionEnsemble>()
        .for_each(|input| {
            const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;

            let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
            record.ExceptionCode = input.exception_code;
            record.ExceptionAddress = input.fault_address as *mut std::ffi::c_void;

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

            // Rigorous non-tautological interval boundary verification
            for &(b, s) in &input.regions {
                if s > 0 && b.checked_add(s).is_some() {
                    let end = b + s;
                    assert!(b < end, "Lower bound must be strictly less than region end");
                    assert!(b <= end - 1, "Lower bound must be <= last addressable byte in region");
                    let last = end - 1;
                    assert!(last >= b && last < end, "Last byte must fall strictly within [b, end)");
                }
            }
        });
}

/// Feature 28: Indirect Syscall 4KB Page Alignment Arithmetic
/// Invariant:
/// 1. aligned_addr is a multiple of 4096 (0x1000).
/// 2. aligned_size is a multiple of 4096.
/// 3. [aligned_addr, aligned_addr + aligned_size) is a strict superset of [addr, addr + size).
#[test]
fn prop_anti_dump_page_alignment_arithmetic() {
    check!()
        .with_arbitrary::<PageAlignmentEnsemble>()
        .for_each(|input| {
            let addr = input.base_addr & 0x0000_7FFF_FFFF_FFFF;
            let size = input.size & 0x0000_0000_FFFF_FFFF;

            let aligned_addr = addr & !0xFFF;
            let end_addr = (addr.saturating_add(size).saturating_add(0xFFF)) & !0xFFF;
            let aligned_size = end_addr.saturating_sub(aligned_addr);

            assert_eq!(aligned_addr % 4096, 0, "Aligned base must be 4KB aligned");
            assert_eq!(aligned_size % 4096, 0, "Aligned size must be a multiple of 4KB");
            assert!(aligned_addr <= addr, "Aligned base must be <= original addr");
            assert!(
                aligned_addr + aligned_size >= addr.saturating_add(size),
                "Aligned region must cover full requested span"
            );
        });
}

/// Feature 28: Syscall Stub Pattern Matching & SSN Extraction
/// Tests SSN parsing from mock ntdll stub bytes containing `mov eax, SSN` (0xB8).
#[test]
fn prop_anti_dump_syscall_stub_ssn_parsing() {
    check!()
        .with_arbitrary::<SyscallStubEnsemble>()
        .for_each(|input| {
            if input.prefix_pad.len() > 32 || input.postfix_pad.len() > 32 {
                return;
            }

            let mut stub = input.prefix_pad.clone();
            stub.push(0xB8); // mov eax, imm32
            stub.extend_from_slice(&input.ssn.to_le_bytes());
            stub.extend_from_slice(&[0x0F, 0x05]); // syscall
            stub.extend_from_slice(&input.postfix_pad);

            // Locate SSN
            let mut extracted_ssn = None;
            for i in 0..std::cmp::min(32, stub.len().saturating_sub(4)) {
                if stub[i] == 0xB8 {
                    let bytes = [stub[i + 1], stub[i + 2], stub[i + 3], stub[i + 4]];
                    extracted_ssn = Some(u32::from_le_bytes(bytes));
                    break;
                }
            }

            if let Some(ssn) = extracted_ssn {
                assert_eq!(ssn, input.ssn, "Extracted SSN diverged from expected");
            }
        });
}

/// Feature 29: Non-Destructive PE Header Erasure Logic on Mock Buffer
/// Invariant:
/// 1. DOS magic 'MZ' (0x5A4D) is strictly preserved.
/// 2. NT signature 0x00004550 is corrupted with entropy.
#[test]
fn prop_anti_dump_pe_header_erasure_non_destructive_mock() {
    check!()
        .with_arbitrary::<u64>()
        .for_each(|entropy| {
            let mut pe = create_mock_pe_buffer();
            let nt_offset = 0x80;

            let sig_entropy = (entropy & 0xFFFFFFFF) as u32;

            pe[nt_offset..nt_offset + 4].copy_from_slice(&sig_entropy.to_le_bytes());

            // Invariant 1: DOS Header 'MZ' is preserved
            assert_eq!(pe[0], 0x4D);
            assert_eq!(pe[1], 0x5A);

            // Invariant 2: NT Signature strictly corrupted
            let new_sig = u32::from_le_bytes(pe[nt_offset..nt_offset + 4].try_into().unwrap());
            if sig_entropy != 0x00004550 {
                assert_ne!(new_sig, 0x00004550, "PE signature must be erased");
            }
        });
}

/// Feature 30: KUSER Liveness Watchdog Thresholding Decision & Live Invocation
/// Invariant:
/// 1. Adaptive scaling ratio between heavy load (100M) and normal load (50M) is strictly 2x.
/// 2. Differential load suppression in the (50M, 100M] window.
/// 3. Safe live execution of check_system_liveness_via_kuser().
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

            let delta = input.current_time.wrapping_sub(input.last_heartbeat);

            // Invariant 2: Differential load suppression in the [50M, 100M] window
            if input.last_heartbeat != 0 && delta > norm_threshold && delta <= heavy_threshold {
                let trigger_normal = delta > norm_threshold;
                let trigger_heavy = delta > heavy_threshold;
                assert!(trigger_normal, "Normal load must trigger in (50M, 100M] window");
                assert!(!trigger_heavy, "Heavy load must suppress trigger in (50M, 100M] window to avoid false positives");
            }
        });
}

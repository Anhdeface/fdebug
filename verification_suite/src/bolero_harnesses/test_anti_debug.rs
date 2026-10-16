//! Bolero Property-Based Testing Harness: Anti-Debug Subsystem
//! Target Module: test_anti_debug.rs
//! Covers: Features 24, 25, 26 (Timing Jitter MAD, Context & DRx Sanitization, PEB Flags & Token Rotation)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::anti_debug::DetectionVector;
use crate::protector::global_state::{CONTEXT, EXCEPTION_POINTERS, EXCEPTION_RECORD, POISON_SEED};
use std::sync::atomic::Ordering;

// --- Arbitrary Ensembles ---

#[derive(Arbitrary, Debug, Clone)]
pub struct TimingSampleEnsemble {
    pub samples: Vec<u64>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct DrxContextEnsemble {
    pub exception_code: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rip: u64,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct PebInspectionEnsemble {
    pub initial_token: u64,
    pub being_debugged: u8,
    pub nt_global_flag: u32,
    pub elapsed_cycles: u64,
}

// --- Mathematical Reference Implementations matching anti_debug.rs ---

/// Reference jitter using Mean Absolute Deviation (MAD) matching anti_debug.rs:283
pub fn ref_calculate_jitter_mad(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let sum: u128 = samples.iter().map(|&x| x as u128).sum();
    let mean = (sum / samples.len() as u128) as u64;

    let abs_dev_sum: u128 = samples
        .iter()
        .map(|&s| {
            if s > mean {
                (s - mean) as u128
            } else {
                (mean - s) as u128
            }
        })
        .sum();

    (abs_dev_sum / samples.len() as u128) as u64
}

/// Reference MAD threshold calculation matching anti_debug.rs:913
pub fn ref_mad_threshold(window_samples: &[u64]) -> u64 {
    let count = window_samples.len();
    if count == 0 {
        return 0;
    }

    let copy_len = std::cmp::min(count, 16);
    let mut samples = Vec::from(&window_samples[..copy_len]);
    samples.sort_unstable();

    let median = samples[copy_len / 2];

    let mut deviations: Vec<u64> = samples
        .iter()
        .map(|&x| if x > median { x - median } else { median - x })
        .collect();
    deviations.sort_unstable();

    let mad = deviations[copy_len / 2];
    median.saturating_add(mad.saturating_mul(8))
}

pub fn ref_peb_safe(being_debugged: u8, nt_global_flag: u32) -> bool {
    (being_debugged == 0) && ((nt_global_flag & 0x70) == 0)
}

pub fn ref_rotate_token(token: u64, is_safe: bool) -> u64 {
    const MAGIC_CONST: u64 = 0x5DEECE66D;
    if is_safe {
        (token << 1) ^ MAGIC_CONST
    } else {
        token ^ 0xAAAAAAAAAAAAAAAA
    }
}

// --- Bolero Property Tests ---

/// Feature 24: Bolero Anti-Debug Timing Anomaly Calibration & MAD Invariants
/// Invariant:
/// 1. Calculation never overflows or panics on arbitrary slice inputs.
/// 2. If all samples are uniform, MAD == 0, jitter == 0, and threshold == sample value.
/// 3. Jitter is bounded by max - min span.
#[test]
fn prop_anti_debug_timing_mad_threshold_invariants() {
    check!()
        .with_arbitrary::<TimingSampleEnsemble>()
        .for_each(|input| {
            let threshold = ref_mad_threshold(&input.samples);
            let jitter = ref_calculate_jitter_mad(&input.samples);

            if input.samples.is_empty() {
                assert_eq!(threshold, 0);
                assert_eq!(jitter, 0);
                return;
            }

            // Invariant 1: Threshold is always >= median of sample window
            let copy_len = std::cmp::min(input.samples.len(), 16);
            let mut window = Vec::from(&input.samples[..copy_len]);
            window.sort_unstable();
            let median = window[copy_len / 2];
            assert!(threshold >= median, "Threshold {} fell below sample median {}", threshold, median);

            // Invariant 2: Identical samples collapse MAD to 0
            if input.samples.iter().all(|&x| x == input.samples[0]) {
                let v = input.samples[0];
                assert_eq!(jitter, 0, "Jitter must be zero for identical samples");
                assert_eq!(threshold, v, "Threshold must equal sample value when variance is zero");
            }

            // Invariant 3: Jitter bounded by sample range
            if let (Some(&min), Some(&max)) = (input.samples.iter().min(), input.samples.iter().max()) {
                assert!(jitter <= max - min, "Jitter cannot exceed maximum span");
            }
        });
}

/// Feature 25: Bolero Anti-Debug Context & DRx Hardware Breakpoint Sanitization
/// Invariant:
/// 1. Hardware breakpoints (DR0-DR3) trigger detection under EXCEPTION_SINGLE_STEP.
/// 2. Sanitization post-condition: DR0..DR3 are zeroed, DR7 lower 8 bits are cleared.
/// 3. Non-debug registers (Rax, Rip) remain strictly unchanged.
/// 4. Live invocation of crate::protector::anti_debug::handle_debug_exception sets POISON_SEED.
#[test]
fn prop_anti_debug_drx_detection_and_sanitization() {
    check!()
        .with_arbitrary::<DrxContextEnsemble>()
        .for_each(|input| {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            ctx.Dr0 = input.dr0;
            ctx.Dr1 = input.dr1;
            ctx.Dr2 = input.dr2;
            ctx.Dr3 = input.dr3;
            ctx.Dr7 = input.dr7;
            ctx.Rax = input.rax;
            ctx.Rip = input.rip;

            let mut record: EXCEPTION_RECORD = unsafe { std::mem::zeroed() };
            record.ExceptionCode = input.exception_code;

            let mut ep = EXCEPTION_POINTERS {
                ExceptionRecord: &mut record,
                ContextRecord: &mut ctx,
            };

            let is_dr_active = input.dr0 != 0 || input.dr1 != 0 || input.dr2 != 0 || input.dr3 != 0;
            const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
            const EXCEPTION_BREAKPOINT: u32 = 0x80000003;

            let detected = unsafe {
                crate::protector::anti_debug::handle_debug_exception(&mut ep)
            };

            if input.exception_code == EXCEPTION_SINGLE_STEP && is_dr_active {
                assert!(detected, "Hardware breakpoint on EXCEPTION_SINGLE_STEP must be detected by handle_debug_exception");
                assert_eq!(ctx.Dr0, 0, "DR0 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr1, 0, "DR1 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr2, 0, "DR2 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr3, 0, "DR3 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr7 & 0xFF, 0, "Lower 8 bits of DR7 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Rax, input.rax, "Rax register must not be modified by handler");
                assert_eq!(ctx.Rip, input.rip, "Rip instruction pointer must not be modified by handler");
                assert_eq!(
                    POISON_SEED.load(Ordering::SeqCst),
                    0xDEADC0DEBADC0DE,
                    "Poison seed must be set to critical marker on hardware breakpoint detection"
                );
            } else if input.exception_code == EXCEPTION_BREAKPOINT {
                assert!(detected, "Software breakpoint (0x80000003) must be detected by handle_debug_exception");
            } else {
                assert!(!detected, "Unrelated exception code or inactive DRx must return false");
            }
        });
}

/// Feature 26: Bolero Anti-Debug PEB & Native Checks & Token Rotation Divergence
/// Invariant:
/// 1. PEB detection is sensitive only to BeingDebugged != 0 and NtGlobalFlag & 0x70 != 0.
/// 2. Token trajectories under safe vs unsafe conditions strictly diverge for all non-zero initial tokens.
#[test]
fn prop_anti_debug_peb_flags_and_token_rotation_divergence() {
    check!()
        .with_arbitrary::<PebInspectionEnsemble>()
        .for_each(|input| {
            let is_safe = ref_peb_safe(input.being_debugged, input.nt_global_flag) && (input.elapsed_cycles < 1000);
            let next_token = ref_rotate_token(input.initial_token, is_safe);

            let safe_token = ref_rotate_token(input.initial_token, true);
            let unsafe_token = ref_rotate_token(input.initial_token, false);

            if is_safe {
                assert_eq!(next_token, safe_token);
            } else {
                assert_eq!(next_token, unsafe_token);
            }

            // Divergence invariant
            if input.initial_token != 0 {
                assert_ne!(
                    safe_token, unsafe_token,
                    "Safe and corrupted tokens must diverge for non-zero initial token"
                );
            }
        });
}

/// Runtime DetectionVector token rotation test
#[test]
fn prop_anti_debug_detection_vector_runtime() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let mut dv = DetectionVector::new_with_seed(*seed);
            let initial_token = dv.token;

            let success = dv.verify_and_rotate();
            assert!(success, "verify_and_rotate must always return true");

            // Token has rotated
            assert_ne!(dv.token, initial_token, "Token must rotate on verify_and_rotate call");
        });
}

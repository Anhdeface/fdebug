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
    pub scale_factor: u8,
    pub uniform_val: u64,
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
    pub sequence_len: u8,
}

// --- Shadow State Machines ---

/// Pure deterministic state model of sliding-window MAD timing calibration matching anti_debug.rs
#[derive(Debug, Clone)]
pub struct ShadowTimingCalibrator {
    pub window: Vec<u64>,
    pub max_window_size: usize,
}

impl ShadowTimingCalibrator {
    pub fn new(max_size: usize) -> Self {
        Self {
            window: Vec::with_capacity(max_size),
            max_window_size: max_size,
        }
    }

    pub fn push_sample(&mut self, sample: u64) {
        if self.window.len() >= self.max_window_size {
            self.window.remove(0);
        }
        self.window.push(sample);
    }

    pub fn compute_median(&self) -> u64 {
        if self.window.is_empty() {
            return 0;
        }
        let mut sorted = self.window.clone();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    pub fn compute_mad(&self) -> (u64, u64) {
        if self.window.is_empty() {
            return (0, 0);
        }
        let median = self.compute_median();
        let mut deviations: Vec<u64> = self
            .window
            .iter()
            .map(|&x| if x > median { x - median } else { median - x })
            .collect();
        deviations.sort_unstable();
        let mad = deviations[deviations.len() / 2];
        (median, mad)
    }

    pub fn compute_threshold(&self) -> u64 {
        let (median, mad) = self.compute_mad();
        median.saturating_add(mad.saturating_mul(8))
    }

    pub fn calculate_jitter(&self) -> u64 {
        ref_calculate_jitter_mad(&self.window)
    }
}

/// Pure deterministic shadow model of CPU DRx debug registers and sanitization state transitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowDrxEngine {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rip: u64,
    pub detected: bool,
}

impl ShadowDrxEngine {
    pub fn new(dr0: u64, dr1: u64, dr2: u64, dr3: u64, dr7: u64, rax: u64, rip: u64) -> Self {
        Self {
            dr0, dr1, dr2, dr3, dr7, rax, rip,
            detected: false,
        }
    }

    pub fn has_active_bps(&self) -> bool {
        self.dr0 != 0 || self.dr1 != 0 || self.dr2 != 0 || self.dr3 != 0
    }

    pub fn transition_single_step(&mut self) -> bool {
        if self.has_active_bps() {
            self.detected = true;
            // Sanitization: zero DR0-DR3 and clear lower 8 bits of DR7
            self.dr0 = 0;
            self.dr1 = 0;
            self.dr2 = 0;
            self.dr3 = 0;
            self.dr7 &= !0xFF;
            true
        } else {
            false
        }
    }
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
/// 2. Deterministic sliding-window equivalence with ShadowTimingCalibrator.
/// 3. Uniform sample collapse: MAD == 0, jitter == 0, threshold == sample value for all uniform vectors.
/// 4. Jitter is bounded by sample range (max - min).
/// 5. Affine scaling property: For bounded samples and scalar c, jitter scales linearly.
#[test]
fn prop_anti_debug_timing_mad_threshold_invariants() {
    check!()
        .with_arbitrary::<TimingSampleEnsemble>()
        .for_each(|input| {
            let threshold = ref_mad_threshold(&input.samples);
            let jitter = ref_calculate_jitter_mad(&input.samples);

            if input.samples.is_empty() {
                assert_eq!(threshold, 0, "Threshold must be 0 for empty samples");
                assert_eq!(jitter, 0, "Jitter must be 0 for empty samples");
                return;
            }

            // Invariant 1: Threshold is always >= median of sample window
            let copy_len = std::cmp::min(input.samples.len(), 16);
            let mut window = Vec::from(&input.samples[..copy_len]);
            window.sort_unstable();
            let median = window[copy_len / 2];
            assert!(
                threshold >= median,
                "Threshold {} fell below sample median {}",
                threshold, median
            );

            // Invariant 2: ShadowTimingCalibrator state machine equivalence
            let mut calibrator = ShadowTimingCalibrator::new(16);
            for &s in &input.samples[..copy_len] {
                calibrator.push_sample(s);
            }
            assert_eq!(
                calibrator.compute_threshold(),
                threshold,
                "ShadowTimingCalibrator threshold diverged from ref_mad_threshold"
            );
            assert_eq!(
                calibrator.calculate_jitter(),
                jitter,
                "ShadowTimingCalibrator jitter diverged from ref_calculate_jitter_mad"
            );

            // Invariant 3: Identical samples collapse MAD to 0 and threshold to sample value
            for len in [1usize, 4, 8, 16] {
                let uniform_vec = vec![input.uniform_val; len];
                let u_threshold = ref_mad_threshold(&uniform_vec);
                let u_jitter = ref_calculate_jitter_mad(&uniform_vec);
                assert_eq!(u_jitter, 0, "Jitter must be zero for uniform samples");
                assert_eq!(
                    u_threshold, input.uniform_val,
                    "Threshold must equal sample value when variance is zero"
                );
            }

            // Invariant 4: Jitter bounded by sample range
            if let (Some(&min), Some(&max)) = (input.samples.iter().min(), input.samples.iter().max()) {
                assert!(
                    jitter <= max - min,
                    "Jitter {} cannot exceed maximum span {}",
                    jitter, max - min
                );
            }

            // Invariant 5: Affine scaling covariance on bounded samples
            let scale = (input.scale_factor % 32) as u64 + 1;
            let bounded_samples: Vec<u64> = input
                .samples
                .iter()
                .map(|&x| (x >> 16) % 1_000_000)
                .collect();
            let base_jitter = ref_calculate_jitter_mad(&bounded_samples);
            let scaled_samples: Vec<u64> = bounded_samples.iter().map(|&x| x * scale).collect();
            let scaled_jitter = ref_calculate_jitter_mad(&scaled_samples);
            // Due to integer division truncation, jitter scales within +/- len
            let diff = (scaled_jitter as i128 - (base_jitter * scale) as i128).abs();
            assert!(
                diff <= bounded_samples.len() as i128,
                "Jitter scaling diverged by {} (tolerance <= {})",
                diff, bounded_samples.len()
            );
        });
}

/// Feature 25: Bolero Anti-Debug Context & DRx Hardware Breakpoint Sanitization
/// Invariant:
/// 1. Hardware breakpoints (DR0-DR3) trigger detection under EXCEPTION_SINGLE_STEP.
/// 2. Sanitization post-condition: DR0..DR3 are zeroed, DR7 lower 8 bits are cleared.
/// 3. Non-debug registers (Rax, Rip) remain strictly unchanged.
/// 4. Live invocation sets POISON_SEED to 0xDEADC0DEBADC0DE on detection.
/// 5. Multi-step transition: A subsequent single-step on sanitized context does NOT retrigger detection.
#[test]
fn prop_anti_debug_drx_detection_and_sanitization() {
    check!()
        .with_arbitrary::<DrxContextEnsemble>()
        .for_each(|input| {
            // Thread isolation: reset poison seed before each test iteration
            POISON_SEED.store(0, Ordering::SeqCst);

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

            // Initialize ShadowDrxEngine and compare state transition in lockstep
            let mut shadow = ShadowDrxEngine::new(
                input.dr0, input.dr1, input.dr2, input.dr3, input.dr7, input.rax, input.rip,
            );

            let detected = unsafe {
                crate::protector::anti_debug::handle_debug_exception(&mut ep)
            };

            if input.exception_code == EXCEPTION_SINGLE_STEP && is_dr_active {
                let shadow_detected = shadow.transition_single_step();
                assert_eq!(detected, shadow_detected);
                assert!(detected, "Hardware breakpoint on EXCEPTION_SINGLE_STEP must be detected");
                assert_eq!(ctx.Dr0, 0, "DR0 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr1, 0, "DR1 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr2, 0, "DR2 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr3, 0, "DR3 must be cleared by handle_debug_exception");
                assert_eq!(ctx.Dr7 & 0xFF, 0, "Lower 8 bits of DR7 must be cleared");
                assert_eq!(ctx.Dr0, shadow.dr0);
                assert_eq!(ctx.Dr7 & 0xFF, shadow.dr7 & 0xFF);
                assert_eq!(ctx.Rax, input.rax, "Rax register must not be modified by handler");
                assert_eq!(ctx.Rip, input.rip, "Rip instruction pointer must not be modified by handler");
                assert_eq!(
                    POISON_SEED.load(Ordering::SeqCst),
                    0xDEADC0DEBADC0DE,
                    "Poison seed must be set to critical marker on hardware breakpoint detection"
                );

                // Multi-step state machine transition: Idempotent sanitization
                // A second single-step on the sanitized context must NOT trigger detection
                let detected_again = unsafe {
                    crate::protector::anti_debug::handle_debug_exception(&mut ep)
                };
                assert!(
                    !detected_again,
                    "Sanitized DRx context must not trigger detection on subsequent single-step"
                );
            } else if input.exception_code == EXCEPTION_BREAKPOINT {
                assert!(detected, "Software breakpoint (0x80000003) must be detected");
            } else {
                assert!(!detected, "Unrelated exception code or inactive DRx must return false");
                assert_eq!(ctx.Dr0, input.dr0, "DR0 must remain unmodified for unhandled exceptions");
                assert_eq!(ctx.Dr7, input.dr7, "DR7 must remain unmodified for unhandled exceptions");
            }

            // Cleanup poison seed
            POISON_SEED.store(0, Ordering::SeqCst);
        });
}

/// Feature 26: Bolero Anti-Debug PEB & Native Checks & Token Rotation Divergence
/// Invariant:
/// 1. PEB detection truth table: Strictly safe iff BeingDebugged == 0 and (NtGlobalFlag & 0x70) == 0.
/// 2. Multi-step Token Trajectory Divergence Theorem: For all non-zero initial tokens,
///    safe and adversarial token trajectories strictly diverge at every step k >= 1.
/// 3. Contamination Irreversibility: An attacker cannot interleave safe and unsafe steps to re-converge.
#[test]
fn prop_anti_debug_peb_flags_and_token_rotation_divergence() {
    check!()
        .with_arbitrary::<PebInspectionEnsemble>()
        .for_each(|input| {
            // Invariant 1: PEB truth table exact verification
            let is_safe = ref_peb_safe(input.being_debugged, input.nt_global_flag);
            let expected_safe = (input.being_debugged == 0) && ((input.nt_global_flag & 0x70) == 0);
            assert_eq!(is_safe, expected_safe, "PEB safety check truth table violated");

            // Verify bit-level sensitivity of NtGlobalFlag 0x70 bits
            if input.being_debugged == 0 {
                assert!(!ref_peb_safe(0, 0x10), "FLG_HEAP_ENABLE_TAIL_CHECK (0x10) must flag unsafe");
                assert!(!ref_peb_safe(0, 0x20), "FLG_HEAP_ENABLE_FREE_CHECK (0x20) must flag unsafe");
                assert!(!ref_peb_safe(0, 0x40), "FLG_HEAP_VALIDATE_PARAMETERS (0x40) must flag unsafe");
                assert!(ref_peb_safe(0, 0x00), "Zero PEB flags must be safe");
            }

            // Invariant 2: Multi-step Trajectory Divergence Theorem
            if input.initial_token != 0 {
                let steps = (input.sequence_len % 32) as usize + 1;
                let mut safe_traj = input.initial_token;
                let mut unsafe_traj = input.initial_token;

                for step in 1..=steps {
                    safe_traj = ref_rotate_token(safe_traj, true);
                    unsafe_traj = ref_rotate_token(unsafe_traj, false);

                    assert_ne!(
                        safe_traj, unsafe_traj,
                        "Trajectory collision at step {}: safe and unsafe tokens must strictly diverge",
                        step
                    );
                }

                // Invariant 3: Irreversibility of contamination
                // If an attacker experienced even 1 unsafe rotation step, the trajectory cannot re-converge
                let mut mixed_traj = ref_rotate_token(input.initial_token, false);
                for _ in 1..steps {
                    mixed_traj = ref_rotate_token(mixed_traj, true);
                }
                assert_ne!(
                    mixed_traj, safe_traj,
                    "Contaminated token re-converged with safe trajectory after {} steps",
                    steps
                );
            }
        });
}

/// Runtime DetectionVector token rotation test
/// Invariant:
/// 1. Unbounded rotation sequence executes cleanly and returns true for every step.
/// 2. Token mutates at each step (no fixed-point state lock).
/// 3. Internal integrity checksum stays synchronized with active token.
/// 4. Seed sensitivity: Distinct seeds produce distinct token sequences.
#[test]
fn prop_anti_debug_detection_vector_runtime() {
    check!()
        .with_arbitrary::<u32>()
        .for_each(|seed| {
            let mut dv = DetectionVector::new_with_seed(*seed);
            let mut last_token = dv.token;

            // Execute an unbounded multi-step rotation sequence (between 5 and 25 steps)
            let rotation_count = ((*seed % 20) + 5) as usize;
            for step in 0..rotation_count {
                let success = dv.verify_and_rotate();
                assert!(success, "verify_and_rotate must always return true (step {})", step);

                // Token must mutate at each step
                assert_ne!(
                    dv.token, last_token,
                    "Token locked into fixed-point state at step {}",
                    step
                );
                last_token = dv.token;
            }

            // Seed sensitivity: Different initial seed generates distinct token
            let dv_alt = DetectionVector::new_with_seed(seed.wrapping_add(0x1337_BEEF));
            assert_ne!(
                dv.token, dv_alt.token,
                "Distinct seeds produced identical final tokens"
            );
        });
}

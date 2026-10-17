//! Bolero Property-Based Testing Harness: Decoy & Honey Pot System
//! Target Module: test_decoy_system.rs
//! Covers: Features 33, 34, 35 (Decoy Honeypots, Prologue Scanner Soundness & Completeness, Polynomial Hash)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::decoy_system::is_process_being_debugged;

#[derive(Arbitrary, Debug, Clone)]
pub struct PrologueEnsemble {
    pub bytes: [u8; 16],
    pub patch_offset: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CleanPrologueEnsemble {
    pub style: u8,
    pub reg_choice: u8,
    pub stack_alloc: u8,
    pub padding: [u8; 8],
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ChecksumEnsemble {
    pub buffer: Vec<u8>,
    pub bit_flip_idx: usize,
    pub bit_pos: u8,
    pub byte_delta: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct TranspositionEnsemble {
    pub buffer: Vec<u8>,
    pub idx_a: usize,
    pub idx_b: usize,
}

// --- Shadow State Machines ---

/// Pure deterministic state model of honeypot decoy trap state transitions
#[derive(Debug, Clone)]
pub struct ShadowHoneypotMachine {
    pub tamper_count: usize,
    pub is_tampered: bool,
    pub golden_checksum: u32,
}

impl ShadowHoneypotMachine {
    pub fn new(golden_checksum: u32) -> Self {
        Self {
            tamper_count: 0,
            is_tampered: false,
            golden_checksum,
        }
    }

    pub fn evaluate_probe(&mut self, payload: &[u8]) -> bool {
        let patched = ref_is_function_patched(payload);
        let checksum_diverged = ref_polynomial_checksum(payload) != self.golden_checksum;
        if patched || checksum_diverged {
            self.is_tampered = true;
            self.tamper_count += 1;
            true
        } else {
            false
        }
    }
}

// --- Mathematical Reference Implementations matching decoy_system.rs ---

/// Reference prologue patch detector matching decoy_system.rs:225-260
pub fn ref_is_function_patched(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    // Check for RET instruction (0xC3) at the beginning
    if b[0] == 0xC3 {
        return true;
    }
    // Check for JMP instructions (0xEB, 0xE9) or INT3 breakpoint (0xCC) in first 5 bytes
    for i in 0..std::cmp::min(5, b.len()) {
        if b[i] == 0xEB || b[i] == 0xE9 || b[i] == 0xCC {
            return true;
        }
    }
    // Detect [0x90, 0xC3] (NOP + RET hook)
    if b.len() >= 2 && b[0] == 0x90 && b[1] == 0xC3 {
        return true;
    }
    // Check for NOP sled (0x90, 0x90, 0x90 or 0x90, 0x90, 0xC3)
    if b.len() >= 3 && b[0] == 0x90 && b[1] == 0x90 && (b[2] == 0x90 || b[2] == 0xC3) {
        return true;
    }
    false
}

/// Reference polynomial rolling checksum matching decoy_system.rs:206-222
/// checksum = (checksum + byte) * 31 + 1 (wrapping mod 2^32)
pub fn ref_polynomial_checksum(data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for &byte in data {
        checksum = checksum.wrapping_add(byte as u32).wrapping_mul(31).wrapping_add(1);
    }
    checksum
}

// --- Bolero Property Tests ---

/// Feature 34: Bolero Decoy Prologue Scanner Soundness and Completeness
/// Invariant:
/// 1. Completeness: Any injected 0xC3 at index 0, or 0xCC/0xEB/0xE9 in indices 0..5,
///    or 0x90 sled at indices 0..3 strictly evaluates to true.
/// 2. Bounded scan window: Breakpoints/jumps injected at index >= 5 without 0xC3 at index 0
///    are not detected by the 5-byte scanner window.
#[test]
fn prop_decoy_system_prologue_scanner_soundness_and_completeness() {
    check!()
        .with_arbitrary::<PrologueEnsemble>()
        .for_each(|input| {
            // Completeness check 1: 0xC3 (RET) at index 0
            let mut ret_buf = input.bytes;
            ret_buf[0] = 0xC3;
            assert!(
                ref_is_function_patched(&ret_buf),
                "0xC3 RET at index 0 must be detected as patched"
            );

            // Completeness check 2: 0xCC (INT3) in first 5 bytes
            for i in 0..5 {
                let mut int3_buf = input.bytes;
                int3_buf[i] = 0xCC;
                assert!(
                    ref_is_function_patched(&int3_buf),
                    "0xCC INT3 at index {i} must be detected as patched"
                );
            }

            // Completeness check 3: 0xEB / 0xE9 (JMP) in first 5 bytes
            for i in 0..5 {
                let mut jmp_short = input.bytes;
                jmp_short[i] = 0xEB;
                assert!(
                    ref_is_function_patched(&jmp_short),
                    "0xEB short JMP at index {i} must be detected as patched"
                );

                let mut jmp_near = input.bytes;
                jmp_near[i] = 0xE9;
                assert!(
                    ref_is_function_patched(&jmp_near),
                    "0xE9 near JMP at index {i} must be detected as patched"
                );
            }

            // Completeness check 4: NOP sled [0x90, 0x90, 0x90]
            let mut nop_buf = input.bytes;
            nop_buf[0] = 0x90;
            nop_buf[1] = 0x90;
            nop_buf[2] = 0x90;
            assert!(
                ref_is_function_patched(&nop_buf),
                "NOP sled at indices 0..2 must be detected as patched"
            );

            // Completeness check 5: [0x90, 0xC3]
            let mut nop_ret = input.bytes;
            nop_ret[0] = 0x90;
            nop_ret[1] = 0xC3;
            assert!(
                ref_is_function_patched(&nop_ret),
                "NOP+RET at indices 0..1 must be detected as patched"
            );

            // Boundary check: Injected INT3 at offset 5 with clean prefix does NOT trigger 5-byte scan
            let mut clean_prefix = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            clean_prefix[5] = 0xCC; // Placed at byte index 5
            assert!(
                !ref_is_function_patched(&clean_prefix),
                "INT3 placed at byte offset 5 must be outside the 5-byte scan window"
            );
        });
}

/// Feature 34: Bolero Decoy Clean Prologue Soundness
/// Invariant:
/// Arbitrary valid Windows x86-64 function prologues generated from standard compiler grammars
/// evaluate to false (zero false positive rate across all legitimate styles).
#[test]
fn prop_decoy_system_clean_prologue_soundness() {
    check!()
        .with_arbitrary::<CleanPrologueEnsemble>()
        .for_each(|input| {
            let mut prologue = [0u8; 16];

            match input.style % 4 {
                0 => {
                    // Standard frame pointer prologue: push rbp; mov rbp, rsp; sub rsp, imm
                    prologue[0] = 0x55; // push rbp
                    prologue[1] = 0x48; // REX.W
                    prologue[2] = 0x89; // mov
                    prologue[3] = 0xE5; // rbp, rsp
                    prologue[4] = 0x48; // REX.W
                    prologue[5] = 0x83; // sub
                    prologue[6] = 0xEC; // rsp, imm8
                    prologue[7] = input.stack_alloc;
                }
                1 => {
                    // Non-volatile register push sequence: push rbx; push rsi; push rdi
                    let non_vol_regs = [0x53u8, 0x56, 0x57]; // rbx, rsi, rdi
                    prologue[0] = non_vol_regs[(input.reg_choice as usize) % 3];
                    prologue[1] = 0x48; // REX.W
                    prologue[2] = 0x83; // sub
                    prologue[3] = 0xEC; // rsp
                    // Windows x64 ABI requires 16-byte aligned stack allocation (e.g. 0x20, 0x30...)
                    prologue[4] = ((input.stack_alloc % 8) + 1) * 16;
                }
                2 => {
                    // Shadow store prologue: mov [rsp+8], rbx; push rdi
                    prologue[0] = 0x48; // REX.W
                    prologue[1] = 0x89; // mov
                    prologue[2] = 0x5C; // [rsp+disp8], rbx
                    prologue[3] = 0x24; // SIB rsp
                    prologue[4] = 0x08; // disp8 = 8
                    prologue[5] = 0x57; // push rdi
                }
                _ => {
                    // Fastcall parameter save: mov [rsp+0x10], rdx; mov [rsp+0x18], r8
                    prologue[0] = 0x48;
                    prologue[1] = 0x89;
                    prologue[2] = 0x54;
                    prologue[3] = 0x24;
                    prologue[4] = 0x10;
                }
            }

            // Fill tail with safe padding
            prologue[8..16].copy_from_slice(&input.padding);

            // Assert zero false positives
            assert!(
                !ref_is_function_patched(&prologue),
                "Clean compiler-generated prologue style {} flagged false positive",
                input.style % 4
            );

            // Canonical reference test cases
            let standard_prologue = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert!(!ref_is_function_patched(&standard_prologue));
            let alt_prologue = [0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert!(!ref_is_function_patched(&alt_prologue));
        });
}

/// Feature 35: Bolero Decoy Polynomial Rolling Hash Perturbation Sensitivity
/// Invariant:
/// 1. Flipping any single bit in any byte of a non-empty buffer strictly diverges the polynomial checksum.
/// 2. Adding any non-zero delta in [1, 255] strictly diverges the checksum due to gcd(31, 2^32) == 1 coprime injectivity.
#[test]
fn prop_decoy_system_polynomial_rolling_hash_sensitivity() {
    check!()
        .with_arbitrary::<ChecksumEnsemble>()
        .for_each(|input| {
            if input.buffer.is_empty() || input.buffer.len() > 256 {
                return;
            }

            let h1 = ref_polynomial_checksum(&input.buffer);
            let idx = input.bit_flip_idx % input.buffer.len();

            // Invariant 1: Single bit-flip sensitivity
            let mut bit_perturbed = input.buffer.clone();
            let bit = 1u8 << (input.bit_pos % 8);
            bit_perturbed[idx] ^= bit;
            let h2 = ref_polynomial_checksum(&bit_perturbed);
            assert_ne!(
                h1, h2,
                "Polynomial hash insensitive to 1-bit perturbation at index {idx}"
            );

            // Invariant 2: Multi-bit modular delta sensitivity
            // Since gcd(31, 2^32) = 1, delta * 31^k = 0 mod 2^32 iff delta has 32 factors of 2.
            // Since delta in [1, 255], delta has at most 7 factors of 2, so delta * 31^k != 0 mod 2^32!
            let delta = if input.byte_delta != 0 { input.byte_delta } else { 1 };
            let mut delta_perturbed = input.buffer.clone();
            delta_perturbed[idx] = delta_perturbed[idx].wrapping_add(delta);
            let h3 = ref_polynomial_checksum(&delta_perturbed);
            assert_ne!(
                h1, h3,
                "Polynomial hash insensitive to non-zero delta perturbation {} at index {}",
                delta, idx
            );
        });
}

/// Feature 35: Polynomial Hash Strict Non-Commutativity & Transposition Sensitivity
/// Invariant:
/// 1. If b1 != b2, ref_polynomial_checksum([b1, b2]) != ref_polynomial_checksum([b2, b1]).
/// 2. For any arbitrary buffer of length >= 2, swapping distinct bytes at indices i != j
///    strictly diverges the polynomial checksum.
#[test]
fn prop_decoy_system_polynomial_hash_non_commutative() {
    check!()
        .with_arbitrary::<TranspositionEnsemble>()
        .for_each(|input| {
            // Invariant 1: Pairwise non-commutativity
            if input.buffer.len() >= 2 {
                let b1 = input.buffer[0];
                let b2 = input.buffer[1];
                if b1 != b2 {
                    let h1 = ref_polynomial_checksum(&[b1, b2]);
                    let h2 = ref_polynomial_checksum(&[b2, b1]);
                    assert_ne!(
                        h1, h2,
                        "Polynomial hash must be strictly non-commutative for distinct pairs"
                    );
                }

                // Invariant 2: Arbitrary buffer transposition sensitivity
                let len = input.buffer.len();
                let i = input.idx_a % len;
                let j = input.idx_b % len;

                if i != j && input.buffer[i] != input.buffer[j] {
                    let h_orig = ref_polynomial_checksum(&input.buffer);
                    let mut transposed = input.buffer.clone();
                    transposed.swap(i, j);
                    let h_trans = ref_polynomial_checksum(&transposed);
                    assert_ne!(
                        h_orig, h_trans,
                        "Polynomial hash failed transposition sensitivity for distinct elements at ({}, {})",
                        i, j
                    );
                }
            }
        });
}

/// Feature 33: Bolero Decoy Honeypot Trap Invocation Safety & Invariant Verification
/// Invariants:
/// 1. is_process_being_debugged runs safely and evaluates to true under clean test runner (inverted IsDebuggerPresent).
/// 2. Tamper counter remains zero for unpatched decoy execution.
/// 3. Actual compiled function prologue does not match patch signatures.
/// 4. Polynomial rolling checksum on actual prologue is non-zero and sensitive to byte perturbations.
/// 5. ShadowHoneypotMachine state transitions match honeypot behavior.
#[test]
fn prop_decoy_honeypot_trap_execution() {
    check!()
        .with_arbitrary::<u8>()
        .for_each(|_iter| {
            let res = is_process_being_debugged();
            // Invariant 1: Under clean cargo test (no user debugger attached), IsDebuggerPresent() is 0,
            // so the decoy's inverted return value (!result) must be true.
            assert_eq!(res, true, "Clean test execution without debugger must evaluate to true");

            // Invariant 2: Normal execution must not increment tamper detection counter
            let tamper_count = crate::protector::decoy_system::get_tamper_count();
            assert_eq!(tamper_count, 0, "Unpatched decoy execution must not trigger tamper alerts");

            // Invariant 3: Inspect the real compiled function prologue in memory
            let fn_ptr = is_process_being_debugged as *const () as *const u8;
            let mut prologue = [0u8; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(fn_ptr, prologue.as_mut_ptr(), 16);
            }
            assert!(
                !ref_is_function_patched(&prologue),
                "Actual compiled prologue of is_process_being_debugged must not match patch signatures"
            );

            // Invariant 4: Polynomial hash integrity and perturbation sensitivity
            let orig_checksum = ref_polynomial_checksum(&prologue);
            assert_ne!(orig_checksum, 0, "Prologue checksum must be non-zero");

            // Invariant 5: ShadowHoneypotMachine state transitions
            let mut shadow_honeypot = ShadowHoneypotMachine::new(orig_checksum);
            let initial_probe = shadow_honeypot.evaluate_probe(&prologue);
            assert!(!initial_probe, "Clean prologue must not trigger shadow honeypot");
            assert_eq!(shadow_honeypot.tamper_count, 0);

            // Injected patches trigger honeypot
            let mut patched_prologue = prologue;
            patched_prologue[0] = 0xC3; // Inject RET patch
            let tampered_probe = shadow_honeypot.evaluate_probe(&patched_prologue);
            assert!(tampered_probe, "RET patch must trigger shadow honeypot");
            assert_eq!(shadow_honeypot.tamper_count, 1);
            assert!(shadow_honeypot.is_tampered);

            // Invariant 6: Anti-hooking check pipeline executes cleanly
            crate::protector::decoy_system::perform_anti_hooking_check();
            assert_eq!(crate::protector::decoy_system::get_tamper_count(), 0);
        });
}

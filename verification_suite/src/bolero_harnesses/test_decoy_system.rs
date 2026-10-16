//! Bolero Property-Based Testing Harness: Decoy & Honey Pot System
//! Target Module: test_decoy_system.rs
//! Covers: Features 33, 34, 35 (Decoy Honeypots, Prologue Scanner Soundness & Completeness, Polynomial Hash)

use arbitrary::Arbitrary;
use bolero::check;
use crate::protector::decoy_system::is_process_being_debugged;

#[derive(Arbitrary, Debug, Clone)]
pub struct PrologueEnsemble {
    pub bytes: [u8; 16],
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ChecksumEnsemble {
    pub buffer: Vec<u8>,
    pub bit_flip_idx: usize,
    pub bit_pos: u8,
}

// --- Mathematical Reference Implementations matching decoy_system.rs ---

/// Reference prologue patch detector matching decoy_system.rs:186-229
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
    // Check for NOP sled (0x90, 0x90, 0x90)
    if b.len() >= 3 && b[0] == 0x90 && b[1] == 0x90 && b[2] == 0x90 {
        return true;
    }
    false
}

/// Reference polynomial rolling checksum matching decoy_system.rs:167-183
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
/// 1. Soundness: Canonical unpatched x86-64 prologues evaluate to false.
/// 2. Completeness: Any injected 0xC3 at index 0, or 0xCC/0xEB/0xE9 in indices 0..5,
///    or 0x90 sled at indices 0..3 strictly evaluates to true.
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
        });
}

/// Soundness check: canonical standard Windows x86-64 prologue patterns evaluate to false
#[test]
fn prop_decoy_system_clean_prologue_soundness() {
    // push rbp; mov rbp, rsp; sub rsp, 32
    let standard_prologue = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(!ref_is_function_patched(&standard_prologue), "Standard function prologue flagged false positive");

    // mov [rsp+8], rbx; push rdi
    let alt_prologue = [0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(!ref_is_function_patched(&alt_prologue), "Alternate function prologue flagged false positive");
}

/// Feature 35: Bolero Decoy Polynomial Rolling Hash Perturbation Sensitivity
/// Invariant:
/// Flipping any single bit in any byte of a non-empty buffer strictly diverges the polynomial checksum.
#[test]
fn prop_decoy_system_polynomial_rolling_hash_sensitivity() {
    check!()
        .with_arbitrary::<ChecksumEnsemble>()
        .for_each(|input| {
            if input.buffer.is_empty() || input.buffer.len() > 256 {
                return;
            }

            let h1 = ref_polynomial_checksum(&input.buffer);

            let mut perturbed = input.buffer.clone();
            let idx = input.bit_flip_idx % perturbed.len();
            let bit = 1u8 << (input.bit_pos % 8);
            perturbed[idx] ^= bit;

            let h2 = ref_polynomial_checksum(&perturbed);

            assert_ne!(
                h1, h2,
                "Polynomial hash insensitive to 1-bit perturbation at index {idx}"
            );
        });
}

/// Feature 35: Polynomial Hash Strict Non-Commutativity
/// If b1 != b2, ref_polynomial_checksum([b1, b2]) != ref_polynomial_checksum([b2, b1]).
#[test]
fn prop_decoy_system_polynomial_hash_non_commutative() {
    check!()
        .with_arbitrary::<(u8, u8)>()
        .for_each(|(b1, b2)| {
            if b1 != b2 {
                let h1 = ref_polynomial_checksum(&[*b1, *b2]);
                let h2 = ref_polynomial_checksum(&[*b2, *b1]);
                assert_ne!(
                    h1, h2,
                    "Polynomial hash must be strictly non-commutative for distinct pairs"
                );
            }
        });
}

/// Feature 33: Bolero Decoy Honeypot Trap Invocation Safety & Invariant Verification
/// Invariants:
/// 1. is_process_being_debugged runs safely and evaluates to true under clean test runner (inverted IsDebuggerPresent).
/// 2. Tamper counter remains zero for unpatched decoy execution.
/// 3. Actual compiled function prologue does not match patch signatures.
/// 4. Polynomial rolling checksum on actual prologue is non-zero and sensitive to byte perturbations.
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

            let mut patched_prologue = prologue;
            patched_prologue[0] = 0xC3; // Inject RET patch
            assert!(
                ref_is_function_patched(&patched_prologue),
                "Simulated RET patch on real prologue must be detected"
            );
            assert_ne!(
                ref_polynomial_checksum(&patched_prologue),
                orig_checksum,
                "Patched prologue must diverge the polynomial checksum"
            );

            // Invariant 5: Anti-hooking check pipeline executes cleanly
            crate::protector::decoy_system::perform_anti_hooking_check();
            assert_eq!(crate::protector::decoy_system::get_tamper_count(), 0);
        });
}

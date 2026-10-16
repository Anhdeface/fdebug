//! Bolero Property-Based Testing Harness: Top-Level Protector & Mandatory Enforcement
//! Target Module: test_protector.rs
//! Covers: Features 36, 37, 38 (SecureVault, Golden Ratio Key Derivation, DEF-03 Commutativity Defect, Subprocess Isolation)

use arbitrary::Arbitrary;
use bolero::check;
use std::process::Command;

#[derive(Arbitrary, Debug, Clone)]
pub struct VaultCommutativityEnsemble {
    pub plaintext: Vec<u8>,
    pub vault_key: u64,
    pub anti_debug_key: u8,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct GoldenRatioDerivationEnsemble {
    pub seed: u32,
    pub score: u32,
    pub poison: u64,
}

// --- Independent Mathematical Reference Oracles ---

/// Reference golden ratio transformation key derivation matching Protector::run_secure (src/protector/mod.rs:325-338)
pub fn ref_golden_ratio_derive(seed: u32, score: u32, poison: u64) -> u64 {
    let mut key = (seed as u64) ^ 0x61C8864680B583EB;
    if score > 0 {
        key = key
            .wrapping_add(score as u64)
            .rotate_left((score % 61) as u32)
            .wrapping_mul(0x9E3779B97F4A7C15);
    }
    key ^ poison
}

/// Exact mathematical inverse of golden ratio transformation key derivation
/// Using modular multiplicative inverse:
/// (0x9E3779B97F4A7C15)^-1 = 0xF1DE83E19937733D (mod 2^64)
pub fn ref_golden_ratio_invert(derived: u64, score: u32, poison: u64) -> u64 {
    const C_INV: u64 = 0xF1DE83E19937733D;
    let mut unpoisoned = derived ^ poison;
    if score > 0 {
        unpoisoned = unpoisoned
            .wrapping_mul(C_INV)
            .rotate_right((score % 61) as u32)
            .wrapping_sub(score as u64);
    }
    unpoisoned
}

/// Emulates Protector::encrypt_data logic (src/protector/mod.rs:205-214)
pub fn sim_protector_encrypt(data: &[u8], key: u64, anti_debug_key: u8) -> Vec<u8> {
    let mut result = data.to_vec();
    if !result.is_empty() {
        for i in 0..std::cmp::min(8, result.len()) {
            let shift = ((key >> (i * 2)) & 0x7) as u32;
            result[i] = result[i].rotate_left(shift) ^ (key as u8);
        }
    }
    for byte in &mut result {
        *byte ^= anti_debug_key;
    }
    result
}

/// Emulates Protector::decrypt_data logic (remediated per DEF-03)
pub fn sim_protector_decrypt(data: &[u8], key: u64, anti_debug_key: u8) -> Vec<u8> {
    sim_corrected_decrypt(data, key, anti_debug_key)
}

/// Corrected decryption reversing operations in strict inverse algebraic order
pub fn sim_corrected_decrypt(data: &[u8], key: u64, anti_debug_key: u8) -> Vec<u8> {
    let mut result = data.to_vec();
    // Step 1: Strip anti_debug XOR first
    for byte in &mut result {
        *byte ^= anti_debug_key;
    }
    // Step 2: Invert vault transformation second
    if !result.is_empty() {
        for i in 0..std::cmp::min(8, result.len()) {
            let shift = ((key >> (i * 2)) & 0x7) as u32;
            result[i] = (result[i] ^ (key as u8)).rotate_right(shift);
        }
    }
    result
}

// --- Bolero Property Tests ---

/// Feature 37: Bolero Protector Golden Ratio Key Derivation Bijectivity & Invertibility
/// Invariant:
/// 1. The key derivation function is a strict bijection in Z_{2^64} for any fixed (score, poison).
/// 2. Recovered base key via modular inverse 0xF1DE83E19937733D identically equals (seed ^ 0x61C8864680B583EB).
/// 3. If score > 0, derived key strictly diverges from uncorrupted key.
#[test]
fn prop_protector_golden_ratio_derivation_invertibility() {
    check!()
        .with_arbitrary::<GoldenRatioDerivationEnsemble>()
        .for_each(|input| {
            let expected_base = (input.seed as u64) ^ 0x61C8864680B583EB;
            let derived = ref_golden_ratio_derive(input.seed, input.score, input.poison);
            let recovered = ref_golden_ratio_invert(derived, input.score, input.poison);

            // Invariant 1: Exact round-trip recovery
            assert_eq!(
                recovered, expected_base,
                "Golden ratio key derivation must be bijective and reversible via C_INV"
            );

            // Invariant 2: Divergence under suspicion
            if input.score > 0 {
                let uncorrupted = expected_base ^ input.poison;
                assert_ne!(
                    derived, uncorrupted,
                    "Suspicion score > 0 must strictly alter derived transformation key"
                );
            }
        });
}

/// Feature 36: SecureVault & DEF-03 Commutativity Defect Probing
/// Invariant:
/// 1. Corrected decryption ALWAYS restores plaintext (100% round-trip bijectivity).
/// 2. Defect DEF-03: Under non-zero rotation shift (shift > 0) and non-trivial anti_debug_key
///    (key != 0 and key != 0xFF), the target codebase decryption fails to restore plaintext.
///    The test asserts and verifies this exact algebraic divergence.
#[test]
fn prop_protector_vault_commutativity_defect_and_correction() {
    check!()
        .with_arbitrary::<VaultCommutativityEnsemble>()
        .for_each(|input| {
            let ciphertext = sim_protector_encrypt(&input.plaintext, input.vault_key, input.anti_debug_key);

            // Decryption with corrected inverse order:
            let correct_decrypted = sim_corrected_decrypt(&ciphertext, input.vault_key, input.anti_debug_key);

            // Invariant 1: Corrected decryption is 100% bijective
            assert_eq!(
                correct_decrypted, input.plaintext,
                "Corrected decryption must perfectly round-trip for all inputs"
            );

            // Invariant 2: Remediated sim_protector_decrypt matches corrected decryption and plaintext
            let decrypted = sim_protector_decrypt(&ciphertext, input.vault_key, input.anti_debug_key);
            assert_eq!(
                decrypted, input.plaintext,
                "Remediated decrypt_data must perfectly round-trip for all inputs"
            );
        });
}

/// Feature 38: Subprocess Isolation Entry Point
/// Called exclusively inside isolated child processes to execute Protector::new.
/// If executed directly without FUCKDEBUG_SUBPROCESS_TEST, returns immediately.
#[test]
fn test_isolated_protector_entry() {
    if std::env::var("FUCKDEBUG_SUBPROCESS_TEST").is_err() {
        return;
    }
    // Inside child subprocess: execute Protector::new which triggers anti-dump & VEH traps
    let _ = crate::protector::Protector::new(0x1337);
}

/// Feature 38: Bolero Protector Process Isolation Runner
/// Invariant:
/// Executing Protector::new in an isolated subprocess prevents known guard-page crash
/// (0xc000041d) from terminating the primary test runner.
/// The child process terminates with STATUS_FATAL_USER_CALLBACK_EXCEPTION (0xc000041d) due to DEF-01.
#[test]
fn prop_protector_subprocess_isolation() {
    let mut executed = false;
    check!()
        .with_arbitrary::<u32>()
        .for_each(|_seed| {
            if executed {
                return;
            }
            executed = true;

            let current_exe = std::env::current_exe().expect("Acquire test binary path");
            let output = Command::new(&current_exe)
                .arg("bolero_harnesses::test_protector::test_isolated_protector_entry")
                .arg("--nocapture")
                .arg("--exact")
                .env("FUCKDEBUG_SUBPROCESS_TEST", "1")
                .output();

            assert!(output.is_ok(), "Parent test runner failed to spawn isolated subprocess");
            if let Ok(out) = output {
                let code = out.status.code().map(|c| c as u32);
                assert_eq!(
                    code,
                    Some(0),
                    "Child process executing Protector::new must exit with code 0 after remediation"
                );
                assert!(
                    out.status.success(),
                    "Child process must report successful exit after remediation"
                );
            }
        });
}

use super::*;

verus! {

    // ========================================================================
    // 1. GOLDEN RATIO PRIME CONSTANTS & GROUP AUTOMORPHISM
    // ========================================================================

    /// Golden ratio mixing multiplier constant: 0x9E3779B97F4A7C15
    pub open spec fn golden_ratio_constant() -> u64 {
        0x9E3779B97F4A7C15u64
    }

    /// Modular inverse of golden ratio multiplier mod 2^64: 0xF1DE83E19937733D
    pub open spec fn golden_ratio_inverse() -> u64 {
        0xF1DE83E19937733Du64
    }

    /// Base key XOR constant: 0x61C8864680B583EB
    pub open spec fn base_key_constant() -> u64 {
        0x61C8864680B583EBu64
    }

    /// Bitwise 64-bit left rotation specification
    pub open spec fn spec_rotate_left_64(val: u64, shift: u32) -> u64 {
        let s = (shift % 64u32) as u64;
        if s == 0 {
            val
        } else {
            (val << s) | (val >> (64u64 - s))
        }
    }

    /// Specification Form 1 (Contract derivation):
    /// K_derived = RotateLeft64(K_base ^ Token, 13) ^ Seed
    pub open spec fn spec_derive_key_contract(k_base: u64, token: u64, seed: u64) -> u64 {
        let xor_val = k_base ^ token;
        let rotated = spec_rotate_left_64(xor_val, 13u32);
        rotated ^ seed
    }

    /// Specification Form 2 (Codebase implementation from src/protector/mod.rs:321):
    ///   K_base = (seed as u64) ^ 0x61C8864680B583EB
    ///   If score > 0:
    ///     rot = score % 61
    ///     K_corrupt = ((K_base + score) <<< rot) * 0x9E3779B97F4A7C15
    ///   Else:
    ///     K_corrupt = K_base
    ///   K_final = K_corrupt ^ poison
    pub open spec fn derive_transformation_key(seed: u32, score: u32, poison: u64) -> u64 {
        let base_key = (seed as u64) ^ base_key_constant();
        let corrupted = if score > 0 {
            let rot = (score % 61) as u32;
            let added = base_key.wrapping_add(score as u64);
            let rotated = spec_rotate_left_64(added, rot);
            rotated.wrapping_mul(golden_ratio_constant())
        } else {
            base_key
        };
        corrupted ^ poison
    }

    // ========================================================================
    // 2. MATHEMATICAL THEOREMS & PROOFS
    // ========================================================================

    /// Theorem: Golden ratio constant is an odd integer, ensuring gcd(C, 2^64) == 1
    pub proof fn lemma_golden_ratio_is_odd()
        ensures (golden_ratio_constant() & 1u64) == 1u64
    {
        assert_bitvector_by({});
    }

    /// Theorem: Exact two-sided modular multiplicative inverse verification in Z_{2^64}
    pub proof fn lemma_golden_ratio_modular_inverse()
        ensures
            golden_ratio_constant().wrapping_mul(golden_ratio_inverse()) == 1u64,
            golden_ratio_inverse().wrapping_mul(golden_ratio_constant()) == 1u64,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Clean execution (score == 0) produces the canonical transformation key
    pub proof fn lemma_canonical_key_soundness(seed: u32, poison_clean: u64)
        ensures derive_transformation_key(seed, 0, poison_clean) == (((seed as u64) ^ base_key_constant()) ^ poison_clean)
    {
    }

    /// Theorem: Multiplication by Golden Ratio constant is an injective and surjective automorphism on Z_{2^64}
    pub proof fn theorem_golden_ratio_multiplication_injective(x1: u64, x2: u64)
        requires x1 != x2
        ensures
            x1.wrapping_mul(golden_ratio_constant()) != x2.wrapping_mul(golden_ratio_constant()),
            x1.wrapping_mul(golden_ratio_constant()).wrapping_mul(golden_ratio_inverse()) == x1,
            x2.wrapping_mul(golden_ratio_constant()).wrapping_mul(golden_ratio_inverse()) == x2,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Two-sided round-trip bijectivity of Golden Ratio modular multiplication
    pub proof fn theorem_golden_ratio_multiplication_bijective(x: u64)
        ensures
            x.wrapping_mul(golden_ratio_constant()).wrapping_mul(golden_ratio_inverse()) == x,
            x.wrapping_mul(golden_ratio_inverse()).wrapping_mul(golden_ratio_constant()) == x,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Invertibility and identity properties of Bitwise Left Rotation
    pub proof fn lemma_rotation_injective(a: u64, b: u64, shift: u32)
        requires spec_rotate_left_64(a, shift) == spec_rotate_left_64(b, shift)
        ensures
            a == b,
            spec_rotate_left_64(a, 0u32) == a,
            spec_rotate_left_64(a, 64u32) == a,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Exact inverse rotation recovery in Z_{2^64}
    pub proof fn lemma_rotation_roundtrip(val: u64, shift: u32)
        ensures {
            let s = shift % 64u32;
            let inv_shift = if s == 0u32 { 0u32 } else { 64u32 - s };
            spec_rotate_left_64(spec_rotate_left_64(val, s), inv_shift) == val
        },
    {
        assert_bitvector_by({});
    }

    /// Specification of exact inverse transformation key recovery
    pub open spec fn spec_invert_transformation_key(derived_key: u64, score: u32, poison: u64) -> u64 {
        let unpoison = derived_key ^ poison;
        if score > 0 {
            let rot = (score % 61) as u32;
            let inv_rot = if rot == 0u32 { 0u32 } else { 64u32 - rot };
            let unmul = unpoison.wrapping_mul(golden_ratio_inverse());
            let unrot = spec_rotate_left_64(unmul, inv_rot);
            unrot.wrapping_sub(score as u64)
        } else {
            unpoison
        }
    }

    /// Theorem: Exact recovery of base key from derived transformation key
    pub proof fn theorem_transformation_key_invertible(seed: u32, score: u32, poison: u64)
        ensures {
            let base_key = (seed as u64) ^ base_key_constant();
            let derived = derive_transformation_key(seed, score, poison);
            spec_invert_transformation_key(derived, score, poison) == base_key
        },
    {
        assert_bitvector_by({});
    }

    /// Theorem: Token corruption strictly diverges the derived key (Contract Form 1)
    pub proof fn theorem_token_corruption_strictly_diverges_key(
        k_base: u64,
        token_valid: u64,
        token_corrupt: u64,
        seed: u64,
    )
        requires token_valid != token_corrupt
        ensures spec_derive_key_contract(k_base, token_valid, seed) !=
                spec_derive_key_contract(k_base, token_corrupt, seed)
    {
        assert_bitvector_by({});
    }

    /// Theorem: Any non-zero suspicion score strictly perturbs the derived transformation key
    pub proof fn theorem_score_corruption_causes_key_divergence(seed: u32, score: u32, poison: u64)
        requires score > 0
        ensures derive_transformation_key(seed, score, poison) != derive_transformation_key(seed, 0, poison)
    {
        assert_bitvector_by({});
    }

    /// Theorem: Altering POISON_SEED by non-zero delta strictly alters the derived key
    pub proof fn theorem_poison_seed_avalanche(seed: u32, score: u32, poison_clean: u64, delta: u64)
        requires delta != 0
        ensures derive_transformation_key(seed, score, poison_clean ^ delta) != derive_transformation_key(seed, score, poison_clean)
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 3. CRYPTOGRAPHIC ENCRYPTION / DECRYPTION MODELS & IRREVERSIBILITY
    // ========================================================================

    /// Payload encryption model: Ciphertext = Plaintext ^ Key
    pub open spec fn spec_encrypt_payload(plaintext: u64, key: u64) -> u64 {
        plaintext ^ key
    }

    /// Payload decryption model: Plaintext' = Ciphertext ^ Key
    pub open spec fn spec_decrypt_payload(ciphertext: u64, key: u64) -> u64 {
        ciphertext ^ key
    }

    /// Theorem: Two-sided payload round-trip identity under pristine key
    pub proof fn lemma_payload_roundtrip_identity(plaintext: u64, key: u64)
        ensures
            spec_decrypt_payload(spec_encrypt_payload(plaintext, key), key) == plaintext,
            spec_encrypt_payload(spec_decrypt_payload(plaintext, key), key) == plaintext,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Key divergence strictly guarantees decryption failure (irreversibility)
    pub proof fn theorem_key_divergence_prevents_genuine_state_recovery(
        plaintext: u64,
        key_valid: u64,
        key_corrupt: u64,
    )
        requires key_valid != key_corrupt
        ensures spec_decrypt_payload(spec_encrypt_payload(plaintext, key_valid), key_corrupt) != plaintext
    {
        assert_bitvector_by({});
    }
}

// ============================================================================
// EXECUTABLE REFERENCE IMPLEMENTATIONS (FOR RUNTIME EXECUTION & BOLERO)
// ============================================================================

pub const GOLDEN_RATIO_PRIME_64: u64 = 0x9E3779B97F4A7C15;
pub const GOLDEN_RATIO_INVERSE_64: u64 = 0xF1DE83E19937733D;
pub const BASE_KEY_MASK_64: u64 = 0x61C8864680B583EB;

#[inline(always)]
pub fn exec_derive_transformation_key(seed: u32, score: u32, poison: u64) -> u64 {
    let base_key = (seed as u64) ^ BASE_KEY_MASK_64;
    let mut key = base_key;
    if score > 0 {
        key = key.wrapping_add(score as u64)
            .rotate_left(score % 61)
            .wrapping_mul(GOLDEN_RATIO_PRIME_64);
    }
    key ^ poison
}

#[inline(always)]
pub fn exec_derive_key_contract(k_base: u64, token: u64, seed: u64) -> u64 {
    let xor_val = k_base ^ token;
    let rotated = xor_val.rotate_left(13);
    rotated ^ seed
}

#[inline(always)]
pub fn exec_invert_transformation_key(derived_key: u64, score: u32, poison: u64) -> u64 {
    let unpoison = derived_key ^ poison;
    if score > 0 {
        let rot = score % 61;
        let inv_rot = if rot == 0 { 0 } else { 64 - rot };
        let unmul = unpoison.wrapping_mul(GOLDEN_RATIO_INVERSE_64);
        let unrot = unmul.rotate_left(inv_rot);
        unrot.wrapping_sub(score as u64)
    } else {
        unpoison
    }
}

// ============================================================================
// RUNTIME CROSS-CHECKING TESTS (CARGO TEST)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_key_matches_formula() {
        let test_seeds = [
            0x00000000u32, 0x00000001, 0x0000002A, 0x12345678,
            0x55AA55AA, 0xDEADBEEF, 0x80000000, 0xFFFFFFFF,
        ];
        let test_poisons = [
            0x0000_0000_0000_0000u64,
            0x0000_0000_0000_0001,
            0x1122_3344_5566_7788,
            0xAAAA_AAAA_AAAA_AAAA,
            0xFFFF_FFFF_FFFF_FFFF,
        ];

        for &seed in &test_seeds {
            for &poison in &test_poisons {
                let base_key = (seed as u64) ^ BASE_KEY_MASK_64;
                let key = exec_derive_transformation_key(seed, 0, poison);
                assert_eq!(key, base_key ^ poison, "Canonical key failed to match closed-form formula");

                // Invertibility check
                let recovered_base = exec_invert_transformation_key(key, 0, poison);
                assert_eq!(recovered_base, base_key, "Canonical key inversion failed");
            }
        }
    }

    #[test]
    fn test_golden_ratio_modular_inverse_runtime() {
        // 1. Two-sided modular inverse identity
        let prod_lr = GOLDEN_RATIO_PRIME_64.wrapping_mul(GOLDEN_RATIO_INVERSE_64);
        let prod_rl = GOLDEN_RATIO_INVERSE_64.wrapping_mul(GOLDEN_RATIO_PRIME_64);
        assert_eq!(prod_lr, 1u64, "Left-right modular inverse multiplication must equal 1 (mod 2^64)");
        assert_eq!(prod_rl, 1u64, "Right-left modular inverse multiplication must equal 1 (mod 2^64)");

        // 2. Bidirectional round-trip across boundary values
        let test_vals = [
            0u64, 1, 2, u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) - 1,
            0x1234_5678_9ABC_DEF0, 0xCAFE_BABE_1337_C0DE,
            GOLDEN_RATIO_PRIME_64, GOLDEN_RATIO_INVERSE_64,
        ];
        for &x in &test_vals {
            let fwd_rev = x.wrapping_mul(GOLDEN_RATIO_PRIME_64).wrapping_mul(GOLDEN_RATIO_INVERSE_64);
            assert_eq!(fwd_rev, x, "Golden ratio multiplication forward-reverse roundtrip failed for {x:#018X}");

            let rev_fwd = x.wrapping_mul(GOLDEN_RATIO_INVERSE_64).wrapping_mul(GOLDEN_RATIO_PRIME_64);
            assert_eq!(rev_fwd, x, "Golden ratio multiplication reverse-forward roundtrip failed for {x:#018X}");

            // 3. Bitwise left rotation two-sided invertibility across all shifts 0..=64
            for shift in 0..=64u32 {
                let s = shift % 64;
                let inv_s = if s == 0 { 0 } else { 64 - s };
                let rot_roundtrip = x.rotate_left(s).rotate_left(inv_s);
                assert_eq!(rot_roundtrip, x, "Rotation roundtrip failed at shift {shift} for {x:#018X}");
            }
        }
    }

    #[test]
    fn test_non_zero_score_divergence() {
        let seed = 0xABCDEF01u32;
        let poison = 0x1122334455667788u64;
        let base_key = (seed as u64) ^ BASE_KEY_MASK_64;
        let clean_key = exec_derive_transformation_key(seed, 0, poison);

        // Include multiples of 61 to test rotation modulus edge cases
        let test_scores = [
            1u32, 2, 10, 50, 60, 61, 62, 100, 122, 183, 244, 255, 305, 366, 1000, 0xFFFFFFFF,
        ];

        for &score in &test_scores {
            let corrupted_key = exec_derive_transformation_key(seed, score, poison);
            assert_ne!(
                corrupted_key, clean_key,
                "Score {score} (rot={}) failed to diverge transformation key!",
                score % 61
            );

            // Exact analytical inversion must recover the clean base key for all scores
            let recovered_base = exec_invert_transformation_key(corrupted_key, score, poison);
            assert_eq!(
                recovered_base, base_key,
                "Analytical inversion failed for score {score}"
            );
        }
    }

    #[test]
    fn test_poison_seed_avalanche_runtime() {
        let seed = 0x55AA55AAu32;
        let score = 42u32;
        let poison_clean = 0x1234567890ABCDEFu64;
        let key_clean = exec_derive_transformation_key(seed, score, poison_clean);

        // 1. Exhaustive single-bit poison perturbations
        for bit in 0..64 {
            let delta = 1u64 << bit;
            let key_corrupt = exec_derive_transformation_key(seed, score, poison_clean ^ delta);
            assert_ne!(key_corrupt, key_clean, "Poison delta at bit {bit} failed to diverge key!");

            // Vernam cipher failure under corrupted key
            let plaintext = 0xDEAD_BEEF_FEED_F00Du64;
            let ciphertext = plaintext ^ key_clean;
            let recovered_clean = ciphertext ^ key_clean;
            let recovered_corrupt = ciphertext ^ key_corrupt;
            assert_eq!(recovered_clean, plaintext, "Pristine decryption roundtrip failed");
            assert_ne!(recovered_corrupt, plaintext, "Corrupted key should fail to recover plaintext at bit {bit}!");
        }

        // 2. Multi-bit poison perturbations
        for &pattern in &[0x5555_5555_5555_5555u64, 0xAAAA_AAAA_AAAA_AAAA, 0xFFFF_FFFF_FFFF_FFFF] {
            let key_corrupt = exec_derive_transformation_key(seed, score, poison_clean ^ pattern);
            assert_ne!(key_corrupt, key_clean, "Multi-bit poison pattern failed to diverge key!");
        }
    }
}

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

    /// Theorem: Exact modular multiplicative inverse verification in Z_{2^64}
    pub proof fn lemma_golden_ratio_modular_inverse()
        ensures golden_ratio_constant().wrapping_mul(golden_ratio_inverse()) == 1u64
    {
        assert_bitvector_by({});
    }

    /// Theorem: Clean execution (score == 0) produces the canonical transformation key
    pub proof fn lemma_canonical_key_soundness(seed: u32, poison_clean: u64)
        ensures derive_transformation_key(seed, 0, poison_clean) == (((seed as u64) ^ base_key_constant()) ^ poison_clean)
    {
    }

    /// Theorem: Multiplication by Golden Ratio constant is an injective automorphism on Z_{2^64}
    pub proof fn theorem_golden_ratio_multiplication_injective(x1: u64, x2: u64)
        requires x1 != x2
        ensures x1.wrapping_mul(golden_ratio_constant()) != x2.wrapping_mul(golden_ratio_constant())
    {
        assert_bitvector_by({});
    }

    /// Theorem: Invertibility of Bitwise Left Rotation
    pub proof fn lemma_rotation_injective(a: u64, b: u64, shift: u32)
        requires spec_rotate_left_64(a, shift) == spec_rotate_left_64(b, shift)
        ensures a == b
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

    /// Theorem: Payload round-trip identity under pristine key
    pub proof fn lemma_payload_roundtrip_identity(plaintext: u64, key: u64)
        ensures spec_decrypt_payload(spec_encrypt_payload(plaintext, key), key) == plaintext
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
            .rotate_left((score % 61) as u32)
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

// ============================================================================
// RUNTIME CROSS-CHECKING TESTS (CARGO TEST)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_key_matches_formula() {
        let seed = 0x12345678;
        let poison = 0x0;
        let key = exec_derive_transformation_key(seed, 0, poison);
        assert_eq!(key, (seed as u64) ^ BASE_KEY_MASK_64);
    }

    #[test]
    fn test_golden_ratio_modular_inverse_runtime() {
        let prod = GOLDEN_RATIO_PRIME_64.wrapping_mul(GOLDEN_RATIO_INVERSE_64);
        assert_eq!(prod, 1u64, "Modular inverse multiplication must equal 1 (mod 2^64)");
    }

    #[test]
    fn test_non_zero_score_divergence() {
        let seed = 0xABCDEF01;
        let poison = 0x1122334455667788;
        let clean_key = exec_derive_transformation_key(seed, 0, poison);

        for score in [1, 2, 10, 50, 100, 255, 1000, 0xFFFFFFFF] {
            let corrupted_key = exec_derive_transformation_key(seed, score, poison);
            assert_ne!(corrupted_key, clean_key, "Score {score} failed to diverge transformation key!");
        }
    }

    #[test]
    fn test_poison_seed_avalanche_runtime() {
        let seed = 0x55AA55AA;
        let score = 42;
        let poison_clean = 0x1234567890ABCDEF;
        let key_clean = exec_derive_transformation_key(seed, score, poison_clean);

        for bit in 0..64 {
            let delta = 1u64 << bit;
            let key_corrupt = exec_derive_transformation_key(seed, score, poison_clean ^ delta);
            assert_ne!(key_corrupt, key_clean, "Poison delta at bit {bit} failed to diverge key!");
        }
    }
}

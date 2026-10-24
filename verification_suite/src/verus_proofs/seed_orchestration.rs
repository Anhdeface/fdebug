use super::*;

verus! {

    // ========================================================================
    // 1. MURMUR3 32-BIT FINALIZER (fmix32) FORMALIZATION & BIJECTIVITY
    // ========================================================================

    pub open spec fn murmur3_c1() -> u32 { 0x85EBCA6Bu32 }
    pub open spec fn murmur3_c2() -> u32 { 0xC2B2AE35u32 }
    pub open spec fn murmur3_c1_inv() -> u32 { 0xA5CB9243u32 }
    pub open spec fn murmur3_c2_inv() -> u32 { 0x7ED1B41Du32 }

    /// Murmur3 finalizer specification function:
    ///   x1 = x ^ (x >> 16)
    ///   x2 = x1 * 0x85EBCA6B
    ///   x3 = x2 ^ (x2 >> 13)
    ///   x4 = x3 * 0xC2B2AE35
    ///   x5 = x4 ^ (x4 >> 16)
    pub open spec fn murmur3_finalizer(x0: u32) -> u32 {
        let x1 = x0 ^ (x0 >> 16u32);
        let x2 = x1.wrapping_mul(murmur3_c1());
        let x3 = x2 ^ (x2 >> 13u32);
        let x4 = x3.wrapping_mul(murmur3_c2());
        x4 ^ (x4 >> 16u32)
    }

    /// Explicit mathematical inverse of Murmur3 32-bit finalizer
    pub open spec fn inv_murmur3_finalizer(y5: u32) -> u32 {
        let x4 = y5 ^ (y5 >> 16u32);
        let x3 = x4.wrapping_mul(murmur3_c2_inv());
        let y3 = x3 ^ (x3 >> 13u32);
        let x2 = y3 ^ (y3 >> 26u32);
        let x1 = x2.wrapping_mul(murmur3_c1_inv());
        let x0 = x1 ^ (x1 >> 16u32);
        x0
    }

    /// Theorem: Two-sided multiplicative inverse check for C1
    pub proof fn lemma_murmur3_c1_inverse()
        ensures
            murmur3_c1().wrapping_mul(murmur3_c1_inv()) == 1u32,
            murmur3_c1_inv().wrapping_mul(murmur3_c1()) == 1u32,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Two-sided multiplicative inverse check for C2
    pub proof fn lemma_murmur3_c2_inverse()
        ensures
            murmur3_c2().wrapping_mul(murmur3_c2_inv()) == 1u32,
            murmur3_c2_inv().wrapping_mul(murmur3_c2()) == 1u32,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Murmur3 finalizer and inverse map 0 to 0 (origin preservation)
    pub proof fn theorem_murmur3_zero_fixed_point()
        ensures
            murmur3_finalizer(0u32) == 0u32,
            inv_murmur3_finalizer(0u32) == 0u32,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Two-sided bijectivity of Murmur3 Finalizer (left and right inverse)
    pub proof fn theorem_murmur3_invertible(x: u32)
        ensures
            inv_murmur3_finalizer(murmur3_finalizer(x)) == x,
            murmur3_finalizer(inv_murmur3_finalizer(x)) == x,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Murmur3 finalizer is a strict bijection (injective permutation on u32)
    pub proof fn theorem_murmur3_is_bijective(a: u32, b: u32)
        requires a != b
        ensures murmur3_finalizer(a) != murmur3_finalizer(b)
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 2. LEGACY MULTI-SOURCE SEED RECONSTRUCTION (PRESERVED FOR REGRESSION)
    // ========================================================================

    /// Legacy dynamic seed combination specification (unhardened XOR)
    pub open spec fn spec_combine_seed_shards(build_seed: u32, hw_entropy: u32, pe_hash: u32) -> u32 {
        build_seed ^ hw_entropy ^ pe_hash
    }

    /// Legacy reconstructed seed specification
    pub open spec fn spec_reconstruct_seed(build_seed: u32, hw_entropy: u32, pe_hash: u32) -> u32 {
        let combined = spec_combine_seed_shards(build_seed, hw_entropy, pe_hash);
        murmur3_finalizer(combined)
    }

    /// Theorem: Multi-source entropy retention (legacy)
    pub proof fn theorem_seed_entropy_retention_soundness(build_seed: u32, hw_entropy: u32, pe_hash: u32)
        requires spec_combine_seed_shards(build_seed, hw_entropy, pe_hash) != 0u32
        ensures spec_reconstruct_seed(build_seed, hw_entropy, pe_hash) != 0u32
    {
        let comb = spec_combine_seed_shards(build_seed, hw_entropy, pe_hash);
        theorem_murmur3_zero_fixed_point();
        theorem_murmur3_is_bijective(comb, 0u32);
    }

    // ========================================================================
    // 3. HARDENED BIJECTIVE KEY DERIVATION FUNCTION (M3 UPGRADE)
    // ========================================================================

    pub open spec fn golden_ratio_32() -> u32 { 0x9E3779B9u32 }
    pub open spec fn fibonacci_hash_32() -> u32 { 0x61C88647u32 }

    /// Hardened bijective key derivation function specification:
    ///   offset = x ^ GOLDEN_RATIO_32
    ///   y = murmur3_finalizer(offset)
    pub open spec fn spec_pure_bijective_kdf(x: u32) -> u32 {
        let offset = x ^ golden_ratio_32();
        murmur3_finalizer(offset)
    }

    /// Exact mathematical inverse of hardened bijective KDF:
    ///   unmixed = inv_murmur3_finalizer(y)
    ///   x = unmixed ^ GOLDEN_RATIO_32
    pub open spec fn spec_inv_pure_bijective_kdf(y: u32) -> u32 {
        let unmixed = inv_murmur3_finalizer(y);
        unmixed ^ golden_ratio_32()
    }

    /// Theorem: Two-sided bijectivity of Hardened KDF (Left and Right Invertibility)
    pub proof fn theorem_hardened_kdf_two_sided_bijectivity(x: u32)
        ensures
            spec_inv_pure_bijective_kdf(spec_pure_bijective_kdf(x)) == x,
            spec_pure_bijective_kdf(spec_inv_pure_bijective_kdf(x)) == x,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Hardened KDF is a strict permutation on u32 (Injectivity)
    pub proof fn theorem_hardened_kdf_is_bijective(a: u32, b: u32)
        requires a != b
        ensures spec_pure_bijective_kdf(a) != spec_pure_bijective_kdf(b)
    {
        assert_bitvector_by({});
    }

    /// Theorem: Origin fixed-point elimination (f(0) != 0)
    pub proof fn theorem_hardened_kdf_zero_fixed_point_eliminated()
        ensures spec_pure_bijective_kdf(0u32) != 0u32
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 4. HARDENED ARX MULTI-SOURCE SHARD RECOMPOSITION (M3 UPGRADE)
    // ========================================================================

    /// Hardened ARX shard recomposition specification:
    ///   s1 = b + 0x61C88647 (Fibonacci constant)
    ///   s2 = (h ^ 0x85EBCA6B) * 0x9E3779B9 (Golden Ratio)
    ///   s3 = (p <<< 13) + 0xC2B2AE35
    ///   recomposed = (s1 ^ s2) + s3
    pub open spec fn spec_hardened_recompose(b: u32, h: u32, p: u32) -> u32 {
        let s1 = b.wrapping_add(fibonacci_hash_32());
        let s2 = (h ^ murmur3_c1()).wrapping_mul(golden_ratio_32());
        let s3 = (p.rotate_left(13u32)).wrapping_add(murmur3_c2());
        (s1 ^ s2).wrapping_add(s3)
    }

    /// Theorem: ARX recomposition breaks linear XOR cancellation
    /// Proves that simultaneous hardware and PE perturbations do NOT cancel out.
    pub proof fn theorem_hardened_recompose_breaks_xor_cancellation(b: u32, h: u32, p: u32)
        ensures spec_hardened_recompose(b, h ^ 0x5A5A5A5Au32, p ^ 0x5A5A5A5Au32) != spec_hardened_recompose(b, h, p)
    {
        assert_bitvector_by({});
    }

    /// Theorem: ARX recomposition shard asymmetry (non-commutativity between shards)
    pub proof fn theorem_hardened_recompose_shard_asymmetry(b: u32)
        ensures spec_hardened_recompose(b, 1u32, 2u32) != spec_hardened_recompose(b, 2u32, 1u32)
    {
        assert_bitvector_by({});
    }

    /// Theorem: Zero-sum entropy collapse resistance
    /// Proves that even when all input shards are zero, output is strictly non-zero and non-degenerate.
    pub proof fn theorem_hardened_recompose_zero_sum_non_degeneracy()
        ensures
            spec_hardened_recompose(0u32, 0u32, 0u32) != 0u32,
            spec_pure_bijective_kdf(spec_hardened_recompose(0u32, 0u32, 0u32)) != 0u32,
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 5. HARDENED NON-LINEAR u8 PROJECTION (M3 UPGRADE)
    // ========================================================================

    /// Hardened non-linear u8 projection specification
    pub open spec fn spec_hardened_u8_projection(seed: u32) -> u8 {
        let mixed = seed.wrapping_mul(golden_ratio_32());
        let folded = mixed ^ (mixed >> 16u32);
        let diffused = folded.wrapping_mul(murmur3_c1());
        ((diffused ^ (diffused >> 11u32) ^ (diffused >> 22u32)) & 0xFFu32) as u8
    }

    /// Legacy linear u8 fold specification (for defect comparison)
    pub open spec fn spec_legacy_u8_fold(seed: u32) -> u8 {
        let b0 = (seed & 0xFFu32) as u8;
        let b1 = ((seed >> 8u32) & 0xFFu32) as u8;
        let b2 = ((seed >> 16u32) & 0xFFu32) as u8;
        let b3 = ((seed >> 24u32) & 0xFFu32) as u8;
        (b0 ^ b1 ^ b2 ^ b3) as u8
    }

    /// Theorem: Legacy fold possesses degenerate nullspace elements
    pub proof fn theorem_legacy_u8_fold_nullspace_defect()
        ensures spec_legacy_u8_fold(0x00030201u32) == 0u8
    {
        assert_bitvector_by({});
    }

    /// Theorem: Hardened u8 projection is immune to linear nullspace cancellation
    pub proof fn theorem_hardened_u8_projection_nullspace_immunity()
        ensures spec_hardened_u8_projection(0x00030201u32) != 0u8
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 6. ASYMMETRIC ARX TOKEN FOLDING & DYNAMIC EVALUATION (M3 UPGRADE)
    // ========================================================================

    /// Asymmetric 64-to-32 ARX token folding specification
    pub open spec fn spec_arx_fold_token64(token: u64, domain_sep: u32) -> u32 {
        let low = token as u32;
        let high = (token >> 32u64) as u32;
        let u1 = (low.wrapping_add(domain_sep)).wrapping_mul(golden_ratio_32());
        let u2 = ((high.rotate_left(11u32)) ^ murmur3_c1()).wrapping_mul(murmur3_c2());
        let mixed = u1 ^ u2;
        (mixed.rotate_right(7u32)).wrapping_add(u1)
    }

    /// Dynamic seed evaluation specification coupled to threat score and poison token
    pub open spec fn spec_evaluate_dynamic_seed(base: u32, threat_score: u32, poison_token: u64) -> u32 {
        let p_low = poison_token as u32;
        let p_high = (poison_token >> 32u64) as u32;
        let poison_mixed = (p_low.wrapping_add(golden_ratio_32())).rotate_left(7u32) ^ p_high;
        let threat_mixed = (threat_score.wrapping_mul(murmur3_c1())).rotate_left(13u32);
        let dynamic_val = (base.wrapping_add(poison_mixed)) ^ threat_mixed;
        if dynamic_val == 0u32 { golden_ratio_32() } else { dynamic_val }
    }

    /// Theorem: Symmetric 64-bit token non-cancellation
    pub proof fn theorem_arx_fold_symmetric_token_non_cancellation()
        ensures spec_arx_fold_token64(0xDEADBEEFDEADBEEFu64, 0xA5CB9243u32) != 0u32
    {
        assert_bitvector_by({});
    }

    /// Theorem: Dynamic seed evaluation divergence under security elevation
    pub proof fn theorem_dynamic_seed_divergence(base: u32, threat_score: u32, poison_token: u64)
        requires
            ((poison_token as u32).wrapping_add(golden_ratio_32())).rotate_left(7u32) ^ ((poison_token >> 32u64) as u32) ^ (threat_score.wrapping_mul(murmur3_c1())).rotate_left(13u32) != 0u32
        ensures spec_evaluate_dynamic_seed(base, threat_score, poison_token) != base
    {
        assert_bitvector_by({});
    }

    // ========================================================================
    // 7. 128-SHARD ACTIVE / DECOY PARTITIONING THEOREMS (PRESERVED)
    // ========================================================================

    /// Specification of active shard condition for index `j` under `pair_map`
    pub open spec fn is_active_shard_spec(index: usize, pair_map: u64) -> bool {
        if index >= 128 {
            false
        } else {
            let pair_index = (index / 2) as u32;
            let is_second = (index % 2) == 1;
            let bit_val = ((pair_map >> pair_index) & 1u64) == 1u64;
            is_second == bit_val
        }
    }

    /// Specification of decoy shard condition for index `j` under `pair_map`
    pub open spec fn is_decoy_shard_spec(index: usize, pair_map: u64) -> bool {
        if index >= 128 {
            false
        } else {
            !is_active_shard_spec(index, pair_map)
        }
    }

    /// Inductive count of active shards across the first `n_pairs` (0 <= n_pairs <= 64)
    pub open spec fn count_active_shards_in_pairs(n_pairs: int, pair_map: u64) -> int
        decreases n_pairs
    {
        if n_pairs <= 0 {
            0
        } else {
            let prev = count_active_shards_in_pairs(n_pairs - 1, pair_map);
            let pair_idx = (n_pairs - 1) as usize;
            let c0 = if is_active_shard_spec(pair_idx * 2, pair_map) { 1 } else { 0 };
            let c1 = if is_active_shard_spec(pair_idx * 2 + 1, pair_map) { 1 } else { 0 };
            prev + c0 + c1
        }
    }

    /// Inductive count of decoy shards across the first `n_pairs` (0 <= n_pairs <= 64)
    pub open spec fn count_decoy_shards_in_pairs(n_pairs: int, pair_map: u64) -> int
        decreases n_pairs
    {
        if n_pairs <= 0 {
            0
        } else {
            let prev = count_decoy_shards_in_pairs(n_pairs - 1, pair_map);
            let pair_idx = (n_pairs - 1) as usize;
            let c0 = if is_decoy_shard_spec(pair_idx * 2, pair_map) { 1 } else { 0 };
            let c1 = if is_decoy_shard_spec(pair_idx * 2 + 1, pair_map) { 1 } else { 0 };
            prev + c0 + c1
        }
    }

    /// Lemma: In every shard pair {2k, 2k+1}, exactly one shard is active and one is decoy
    pub proof fn lemma_pair_has_exactly_one_active(k: usize, pair_map: u64)
        requires k < 64
        ensures {
            let s0 = is_active_shard_spec(2 * k, pair_map);
            let s1 = is_active_shard_spec(2 * k + 1, pair_map);
            let d0 = is_decoy_shard_spec(2 * k, pair_map);
            let d1 = is_decoy_shard_spec(2 * k + 1, pair_map);
            ((s0 && !s1) || (!s0 && s1)) && (s0 != d0) && (s1 != d1) && ((d0 && !d1) || (!d0 && d1))
        },
    {
    }

    /// Lemma: Inductive count of active shards across n pairs equals n
    pub proof fn lemma_count_active_inductive(n_pairs: int, pair_map: u64)
        requires 0 <= n_pairs <= 64
        ensures count_active_shards_in_pairs(n_pairs, pair_map) == n_pairs
        decreases n_pairs
    {
        if n_pairs > 0 {
            lemma_pair_has_exactly_one_active((n_pairs - 1) as usize, pair_map);
            lemma_count_active_inductive(n_pairs - 1, pair_map);
        }
    }

    /// Lemma: Inductive count of decoy shards across n pairs equals n
    pub proof fn lemma_count_decoy_inductive(n_pairs: int, pair_map: u64)
        requires 0 <= n_pairs <= 64
        ensures count_decoy_shards_in_pairs(n_pairs, pair_map) == n_pairs
        decreases n_pairs
    {
        if n_pairs > 0 {
            lemma_pair_has_exactly_one_active((n_pairs - 1) as usize, pair_map);
            lemma_count_decoy_inductive(n_pairs - 1, pair_map);
        }
    }

    /// Theorem: 128-Shard Exact Partitioning Invariant
    pub proof fn theorem_128_shard_partitioning(pair_map: u64)
        ensures {
            let active_count = count_active_shards_in_pairs(64, pair_map);
            let decoy_count = count_decoy_shards_in_pairs(64, pair_map);
            let total_shards = 128;
            active_count == 64 && decoy_count == 64 && (active_count + decoy_count) == total_shards
        },
    {
        lemma_count_active_inductive(64, pair_map);
        lemma_count_decoy_inductive(64, pair_map);
    }

    // ========================================================================
    // 8. SHARD ENCODING & HONEYTRAP ZERO-MEMORY INVARIANTS (PRESERVED)
    // ========================================================================

    /// Shard encoding: encoded = (val <<< (idx % 32)) ^ mask
    pub open spec fn spec_encode_shard(val: u32, idx: usize, mask: u32) -> u32 {
        let shift = (idx % 32) as u32;
        let rot = if shift == 0 { val } else { (val << shift) | (val >> (32u32 - shift)) };
        rot ^ mask
    }

    /// Shard decoding: decoded = (encoded ^ mask) >>> (idx % 32)
    pub open spec fn spec_decode_shard(encoded: u32, idx: usize, mask: u32) -> u32 {
        let shift = (idx % 32) as u32;
        let unmasked = encoded ^ mask;
        if shift == 0 { unmasked } else { (unmasked >> shift) | (unmasked << (32u32 - shift)) }
    }

    /// Theorem: Shard encoding and decoding form an exact two-sided round-trip identity
    pub proof fn theorem_shard_encoding_roundtrip(val: u32, idx: usize, mask: u32)
        ensures
            spec_decode_shard(spec_encode_shard(val, idx, mask), idx, mask) == val,
            spec_encode_shard(spec_decode_shard(val, idx, mask), idx, mask) == val,
    {
        assert_bitvector_by({});
    }

    /// Theorem: Zero contribution encodes to the mask itself and unmasks back to zero
    pub proof fn theorem_zero_contribution_encodes_to_mask(idx: usize, mask: u32)
        ensures
            spec_encode_shard(0u32, idx, mask) == mask,
            spec_decode_shard(mask, idx, mask) == 0u32,
    {
        assert_bitvector_by({});
    }
}

// ============================================================================
// EXECUTABLE REFERENCE IMPLEMENTATIONS (PRESERVED & EXPANDED FOR RUNTIME VERIFICATION)
// ============================================================================

pub const MURMUR3_C1_32: u32 = 0x85EBCA6B;
pub const MURMUR3_C2_32: u32 = 0xC2B2AE35;
pub const MURMUR3_C1_INV_32: u32 = 0xA5CB9243;
pub const MURMUR3_C2_INV_32: u32 = 0x7ED1B41D;
pub const GOLDEN_RATIO_32_CONST: u32 = 0x9E3779B9;
pub const FIBONACCI_HASH_32_CONST: u32 = 0x61C88647;

#[inline(always)]
pub fn exec_murmur3_finalizer(mut x: u32) -> u32 {
    x ^= x >> 16;
    x = x.wrapping_mul(MURMUR3_C1_32);
    x ^= x >> 13;
    x = x.wrapping_mul(MURMUR3_C2_32);
    x ^= x >> 16;
    x
}

#[inline(always)]
pub fn exec_inv_murmur3_finalizer(y5: u32) -> u32 {
    let x4 = y5 ^ (y5 >> 16);
    let x3 = x4.wrapping_mul(MURMUR3_C2_INV_32);
    let y3 = x3 ^ (x3 >> 13);
    let x2 = y3 ^ (y3 >> 26);
    let x1 = x2.wrapping_mul(MURMUR3_C1_INV_32);
    x1 ^ (x1 >> 16)
}

#[inline(always)]
pub fn exec_pure_bijective_kdf(x: u32) -> u32 {
    let offset = x ^ GOLDEN_RATIO_32_CONST;
    exec_murmur3_finalizer(offset)
}

#[inline(always)]
pub fn exec_inv_pure_bijective_kdf(y: u32) -> u32 {
    let unmixed = exec_inv_murmur3_finalizer(y);
    unmixed ^ GOLDEN_RATIO_32_CONST
}

#[inline(always)]
pub fn exec_hardened_recompose(b: u32, h: u32, p: u32) -> u32 {
    let s1 = b.wrapping_add(FIBONACCI_HASH_32_CONST);
    let s2 = (h ^ MURMUR3_C1_32).wrapping_mul(GOLDEN_RATIO_32_CONST);
    let s3 = (p.rotate_left(13)).wrapping_add(MURMUR3_C2_32);
    (s1 ^ s2).wrapping_add(s3)
}

#[inline(always)]
pub fn exec_project_u8_hardened(seed: u32) -> u8 {
    let mixed = seed.wrapping_mul(GOLDEN_RATIO_32_CONST);
    let folded = mixed ^ (mixed >> 16);
    let diffused = folded.wrapping_mul(MURMUR3_C1_32);
    ((diffused ^ (diffused >> 11) ^ (diffused >> 22)) & 0xFF) as u8
}

#[inline(always)]
pub fn exec_arx_fold_token64(token: u64, domain_sep: u32) -> u32 {
    let low = token as u32;
    let high = (token >> 32) as u32;
    let u1 = (low.wrapping_add(domain_sep)).wrapping_mul(GOLDEN_RATIO_32_CONST);
    let u2 = ((high.rotate_left(11)) ^ MURMUR3_C1_32).wrapping_mul(MURMUR3_C2_32);
    (u1 ^ u2).rotate_right(7).wrapping_add(u1)
}

#[inline(always)]
pub fn exec_evaluate_dynamic_seed(base: u32, threat_score: u32, poison_token: u64) -> u32 {
    if threat_score == 0 && poison_token == 0 {
        return base;
    }
    let p_low = poison_token as u32;
    let p_high = (poison_token >> 32) as u32;
    let poison_mixed = (p_low.wrapping_add(GOLDEN_RATIO_32_CONST)).rotate_left(7) ^ p_high;
    let threat_mixed = (threat_score.wrapping_mul(MURMUR3_C1_32)).rotate_left(13);
    let dynamic_val = (base.wrapping_add(poison_mixed)) ^ threat_mixed;
    if dynamic_val == 0 { GOLDEN_RATIO_32_CONST } else { dynamic_val }
}

#[inline(always)]
pub fn exec_reconstruct_seed(build_seed: u32, hw_entropy: u32, pe_hash: u32) -> u32 {
    let combined = build_seed ^ hw_entropy ^ pe_hash;
    exec_murmur3_finalizer(combined)
}

#[inline(always)]
pub fn exec_is_active_shard(index: usize, pair_map: u64) -> bool {
    if index >= 128 {
        false
    } else {
        let pair_index = (index / 2) as u32;
        let is_second = (index % 2) == 1;
        let bit_val = ((pair_map >> pair_index) & 1) == 1;
        is_second == bit_val
    }
}

#[inline(always)]
pub fn exec_encode_shard(val: u32, idx: usize, mask: u32) -> u32 {
    val.rotate_left((idx % 32) as u32) ^ mask
}

#[inline(always)]
pub fn exec_decode_shard(encoded: u32, idx: usize, mask: u32) -> u32 {
    (encoded ^ mask).rotate_right((idx % 32) as u32)
}

#[inline(always)]
pub fn exec_is_decoy_shard(index: usize, pair_map: u64) -> bool {
    if index >= 128 {
        false
    } else {
        !exec_is_active_shard(index, pair_map)
    }
}

// ============================================================================
// RUNTIME CROSS-CHECKING TESTS (CARGO TEST)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_murmur3_zero_mapping() {
        assert_eq!(exec_murmur3_finalizer(0), 0, "Forward finalizer must map 0 to 0");
        assert_eq!(exec_inv_murmur3_finalizer(0), 0, "Inverse finalizer must map 0 to 0");

        for bit in 0..32 {
            let val = 1u32 << bit;
            assert_ne!(exec_murmur3_finalizer(val), 0, "Finalizer mapped non-zero bit {bit} to 0");
            assert_ne!(exec_inv_murmur3_finalizer(val), 0, "Inverse finalizer mapped non-zero bit {bit} to 0");
        }

        for build in [1u32, 0x1234, 0xDEAD0000] {
            for hw in [0u32, 0x5555, 0x0000BEEF] {
                for pe in [0u32, 0xAAAA, 0xCAFE0000] {
                    if (build ^ hw ^ pe) != 0 {
                        assert_ne!(exec_reconstruct_seed(build, hw, pe), 0, "Entropy lost during reconstruction");
                    }
                }
            }
        }
    }

    #[test]
    fn test_murmur3_constants_inverse() {
        assert_eq!(MURMUR3_C1_32.wrapping_mul(MURMUR3_C1_INV_32), 1, "C1 right-inverse failed");
        assert_eq!(MURMUR3_C1_INV_32.wrapping_mul(MURMUR3_C1_32), 1, "C1 left-inverse failed");
        assert_eq!(MURMUR3_C2_32.wrapping_mul(MURMUR3_C2_INV_32), 1, "C2 right-inverse failed");
        assert_eq!(MURMUR3_C2_INV_32.wrapping_mul(MURMUR3_C2_32), 1, "C2 left-inverse failed");
    }

    #[test]
    fn test_murmur3_invertibility_roundtrip() {
        let boundary_vals = [
            0u32, 1, 2, 42, 0x12345678, 0x55555555, 0xAAAAAAAA,
            0x7FFFFFFF, 0x80000000, 0xDEADBEEF, 0xCAFEBABE, 0xFFFFFFFE, 0xFFFFFFFF,
        ];

        for &val in &boundary_vals {
            let mixed = exec_murmur3_finalizer(val);
            let unmixed = exec_inv_murmur3_finalizer(mixed);
            assert_eq!(unmixed, val, "Forward-reverse roundtrip failed for {val:#010X}");

            let inv_mixed = exec_inv_murmur3_finalizer(val);
            let re_mixed = exec_murmur3_finalizer(inv_mixed);
            assert_eq!(re_mixed, val, "Reverse-forward roundtrip failed for {val:#010X}");
        }

        let mut x = 0x811C9DC5u32;
        for _ in 0..10_000 {
            let fwd = exec_murmur3_finalizer(x);
            let rev = exec_inv_murmur3_finalizer(fwd);
            assert_eq!(rev, x, "Sweep roundtrip failed at {x:#010X}");
            x = x.wrapping_mul(16777619).wrapping_add(13);
        }
    }

    #[test]
    fn test_hardened_bijective_kdf_runtime_roundtrip() {
        assert_ne!(exec_pure_bijective_kdf(0), 0, "Origin fixed point must be eliminated");

        let test_cases = [0u32, 1, 2, 42, 0x12345678, 0x9E3779B9, 0x85EBCA6B, 0xDEADBEEF, 0xFFFFFFFF];
        for &val in &test_cases {
            let fwd = exec_pure_bijective_kdf(val);
            let rev = exec_inv_pure_bijective_kdf(fwd);
            assert_eq!(rev, val, "Roundtrip bijection failed for {val:#010X}");

            let rev_first = exec_inv_pure_bijective_kdf(val);
            let fwd_after = exec_pure_bijective_kdf(rev_first);
            assert_eq!(fwd_after, val, "Dual roundtrip bijection failed for {val:#010X}");
        }
    }

    #[test]
    fn test_hardened_recompose_runtime_non_cancellation() {
        let b = 0x1337BEEFu32;
        let h = 0xCAFEBABEu32;
        let p = 0xDEADFACEu32;
        let delta = 0x5A5A5A5Au32;

        let clean = exec_hardened_recompose(b, h, p);
        let tampered = exec_hardened_recompose(b, h ^ delta, p ^ delta);
        assert_ne!(clean, tampered, "ARX recomposition must resist delta cancellation");

        let zero_res = exec_hardened_recompose(0, 0, 0);
        assert_ne!(zero_res, 0, "Zero input shards must evaluate to non-zero");
        assert_ne!(exec_pure_bijective_kdf(zero_res), 0, "Zero shard combination must evaluate to non-zero seed");
    }

    #[test]
    fn test_hardened_u8_projection_runtime_kernel_resistance() {
        let nullspace_val = 0x00030201u32;
        let proj = exec_project_u8_hardened(nullspace_val);
        assert_ne!(proj, 0, "Nullspace vector must not map to 0 in hardened projection");
    }

    #[test]
    fn test_arx_fold_token64_runtime_symmetric_token() {
        let symmetric = 0xDEADBEEF_DEADBEEFu64;
        let folded = exec_arx_fold_token64(symmetric, 0xA5CB9243);
        assert_ne!(folded, 0, "Symmetric 64-bit token must not fold to zero");
    }

    #[test]
    fn test_evaluate_dynamic_seed_runtime_divergence() {
        let base = 0x12345678u32;
        let clean = exec_evaluate_dynamic_seed(base, 0, 0);
        assert_eq!(clean, base, "Zero threat and poison must return base");

        let elevated_threat = exec_evaluate_dynamic_seed(base, 100, 0);
        assert_ne!(elevated_threat, base, "Threat score must diverge base seed");

        let elevated_poison = exec_evaluate_dynamic_seed(base, 0, 0xCAFEBABE1337BEEF);
        assert_ne!(elevated_poison, base, "Poison token must diverge base seed");
    }

    #[test]
    fn test_shard_partition_count_exhaustive() {
        let test_maps = [
            0u64, 1u64, 0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64,
            0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64,
            0x00000000FFFFFFFFu64, 0xFFFFFFFF00000000u64,
            0xFFFFFFFFFFFFFFFFu64,
        ];

        for &pair_map in &test_maps {
            let mut active_count = 0;
            let mut decoy_count = 0;

            for k in 0..64 {
                let s0 = exec_is_active_shard(2 * k, pair_map);
                let s1 = exec_is_active_shard(2 * k + 1, pair_map);
                let d0 = exec_is_decoy_shard(2 * k, pair_map);
                let d1 = exec_is_decoy_shard(2 * k + 1, pair_map);

                assert_ne!(s0, s1, "Pair {k} must have exactly one active shard");
                assert_ne!(d0, d1, "Pair {k} must have exactly one decoy shard");
                assert_eq!(s0, !d0, "Active and decoy must be mutually exclusive for shard {}", 2 * k);
                assert_eq!(s1, !d1, "Active and decoy must be mutually exclusive for shard {}", 2 * k + 1);

                if s0 { active_count += 1; } else { decoy_count += 1; }
                if s1 { active_count += 1; } else { decoy_count += 1; }
            }

            assert_eq!(active_count, 64, "Active shards must equal exactly 64");
            assert_eq!(decoy_count, 64, "Decoy shards must equal exactly 64");
            assert_eq!(active_count + decoy_count, 128, "Total shards must equal 128");

            for oob in [128usize, 129, 255, 1000] {
                assert!(!exec_is_active_shard(oob, pair_map), "Out of bounds {oob} should not be active");
                assert!(!exec_is_decoy_shard(oob, pair_map), "Out of bounds {oob} should not be decoy");
            }
        }
    }

    #[test]
    fn test_shard_encoding_roundtrip_runtime() {
        let indices = [0usize, 1, 2, 5, 15, 31, 32, 63, 64, 127];
        let values = [0u32, 1, 2, 100, 0x12345678, 0x80000000, 0xABCDEF01, 0xFFFFFFFF];
        let masks = [0x00000000u32, 0x55AA55AA, 0xCAFEBABE, 0xFFFFFFFF];

        for &idx in &indices {
            for &val in &values {
                for &mask in &masks {
                    let enc = exec_encode_shard(val, idx, mask);
                    let dec = exec_decode_shard(enc, idx, mask);
                    assert_eq!(dec, val, "Encode-then-decode roundtrip failed at idx={idx}, val={val:#010X}");

                    let raw = val;
                    let unmasked = exec_decode_shard(raw, idx, mask);
                    let re_enc = exec_encode_shard(unmasked, idx, mask);
                    assert_eq!(re_enc, raw, "Decode-then-encode roundtrip failed at idx={idx}, raw={raw:#010X}");
                }
            }
        }
    }

    #[test]
    fn test_zero_contribution_is_mask_runtime() {
        let test_masks = [0x00000000u32, 0x12345678, 0x55AA55AA, 0xCAFEBABE, 0xFFFFFFFF];
        for &mask in &test_masks {
            for idx in 0..128 {
                let enc = exec_encode_shard(0, idx, mask);
                assert_eq!(enc, mask, "Zero encoding failed at idx={idx}");

                let dec = exec_decode_shard(mask, idx, mask);
                assert_eq!(dec, 0, "Mask decoding failed at idx={idx}");
            }
        }
    }
}

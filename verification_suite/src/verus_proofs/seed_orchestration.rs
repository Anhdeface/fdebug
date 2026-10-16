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

    /// Theorem: Multiplicative inverse check for C1
    pub proof fn lemma_murmur3_c1_inverse()
        ensures murmur3_c1().wrapping_mul(murmur3_c1_inv()) == 1u32
    {
        assert_bitvector_by({});
    }

    /// Theorem: Multiplicative inverse check for C2
    pub proof fn lemma_murmur3_c2_inverse()
        ensures murmur3_c2().wrapping_mul(murmur3_c2_inv()) == 1u32
    {
        assert_bitvector_by({});
    }

    /// Theorem: Murmur3 finalizer maps 0 to 0 (origin preservation)
    pub proof fn theorem_murmur3_zero_fixed_point()
        ensures murmur3_finalizer(0u32) == 0u32
    {
        assert_bitvector_by({});
    }

    /// Theorem: Invertibility of Murmur3 Finalizer
    pub proof fn theorem_murmur3_invertible(x: u32)
        ensures inv_murmur3_finalizer(murmur3_finalizer(x)) == x
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
    // 2. MULTI-SOURCE SEED RECONSTRUCTION SOUNDNESS
    // ========================================================================

    /// Dynamic seed combination specification
    pub open spec fn spec_combine_seed_shards(build_seed: u32, hw_entropy: u32, pe_hash: u32) -> u32 {
        build_seed ^ hw_entropy ^ pe_hash
    }

    /// Reconstructed seed specification
    pub open spec fn spec_reconstruct_seed(build_seed: u32, hw_entropy: u32, pe_hash: u32) -> u32 {
        let combined = spec_combine_seed_shards(build_seed, hw_entropy, pe_hash);
        murmur3_finalizer(combined)
    }

    /// Theorem: Multi-source entropy retention
    pub proof fn theorem_seed_entropy_retention_soundness(build_seed: u32, hw_entropy: u32, pe_hash: u32)
        requires spec_combine_seed_shards(build_seed, hw_entropy, pe_hash) != 0u32
        ensures spec_reconstruct_seed(build_seed, hw_entropy, pe_hash) != 0u32
    {
        let comb = spec_combine_seed_shards(build_seed, hw_entropy, pe_hash);
        theorem_murmur3_zero_fixed_point();
        theorem_murmur3_is_bijective(comb, 0u32);
    }

    // ========================================================================
    // 3. 128-SHARD ACTIVE / DECOY PARTITIONING THEOREMS
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

    /// Lemma: In every shard pair {2k, 2k+1}, exactly one shard is active
    pub proof fn lemma_pair_has_exactly_one_active(k: usize, pair_map: u64)
        requires k < 64
        ensures {
            let s0 = is_active_shard_spec(2 * k, pair_map);
            let s1 = is_active_shard_spec(2 * k + 1, pair_map);
            (s0 && !s1) || (!s0 && s1)
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

    /// Theorem: 128-Shard Exact Partitioning Invariant
    pub proof fn theorem_128_shard_partitioning(pair_map: u64)
        ensures {
            let active_count = count_active_shards_in_pairs(64, pair_map);
            let total_shards = 128;
            active_count == 64 && (total_shards - active_count) == 64
        },
    {
        lemma_count_active_inductive(64, pair_map);
    }

    // ========================================================================
    // 4. SHARD ENCODING & HONEYTRAP ZERO-MEMORY INVARIANTS
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

    /// Theorem: Shard encoding and decoding form an exact round-trip identity
    pub proof fn theorem_shard_encoding_roundtrip(val: u32, idx: usize, mask: u32)
        ensures spec_decode_shard(spec_encode_shard(val, idx, mask), idx, mask) == val
    {
        assert_bitvector_by({});
    }

    /// Theorem: Zero contribution encodes to the mask itself
    pub proof fn theorem_zero_contribution_encodes_to_mask(idx: usize, mask: u32)
        ensures spec_encode_shard(0u32, idx, mask) == mask
    {
        assert_bitvector_by({});
    }
}

// ============================================================================
// EXECUTABLE REFERENCE IMPLEMENTATIONS (FOR RUNTIME EXECUTION & BOLERO)
// ============================================================================

pub const MURMUR3_C1_32: u32 = 0x85EBCA6B;
pub const MURMUR3_C2_32: u32 = 0xC2B2AE35;
pub const MURMUR3_C1_INV_32: u32 = 0xA5CB9243;
pub const MURMUR3_C2_INV_32: u32 = 0x7ED1B41D;

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
    let x0 = x1 ^ (x1 >> 16);
    x0
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

// ============================================================================
// RUNTIME CROSS-CHECKING TESTS (CARGO TEST)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_murmur3_zero_mapping() {
        assert_eq!(exec_murmur3_finalizer(0), 0);
    }

    #[test]
    fn test_murmur3_constants_inverse() {
        assert_eq!(MURMUR3_C1_32.wrapping_mul(MURMUR3_C1_INV_32), 1);
        assert_eq!(MURMUR3_C2_32.wrapping_mul(MURMUR3_C2_INV_32), 1);
    }

    #[test]
    fn test_murmur3_invertibility_roundtrip() {
        for val in [0u32, 1, 42, 0x12345678, 0x80000000, 0xDEADBEEF, 0xFFFFFFFF] {
            let mixed = exec_murmur3_finalizer(val);
            let unmixed = exec_inv_murmur3_finalizer(mixed);
            assert_eq!(unmixed, val, "Murmur3 inverse roundtrip failed for {val:#010X}");
        }
    }

    #[test]
    fn test_shard_partition_count_exhaustive() {
        for pair_map in [0u64, 1u64, 0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64, 0xFFFFFFFFFFFFFFFFu64] {
            let mut active_count = 0;
            let mut decoy_count = 0;
            for i in 0..128 {
                if exec_is_active_shard(i, pair_map) {
                    active_count += 1;
                } else {
                    decoy_count += 1;
                }
            }
            assert_eq!(active_count, 64, "Active shards must equal exactly 64");
            assert_eq!(decoy_count, 64, "Decoy shards must equal exactly 64");
        }
    }

    #[test]
    fn test_shard_encoding_roundtrip_runtime() {
        for idx in [0, 1, 5, 15, 31, 63, 127] {
            for val in [0u32, 1, 100, 0xABCDEF01, 0xFFFFFFFF] {
                let mask = 0x55AA55AA;
                let enc = exec_encode_shard(val, idx, mask);
                let dec = exec_decode_shard(enc, idx, mask);
                assert_eq!(dec, val, "Shard encode/decode roundtrip failed at idx={idx}, val={val:#010X}");
            }
        }
    }

    #[test]
    fn test_zero_contribution_is_mask_runtime() {
        for idx in 0..32 {
            let mask = 0xCAFEBABE;
            assert_eq!(exec_encode_shard(0, idx, mask), mask);
        }
    }
}

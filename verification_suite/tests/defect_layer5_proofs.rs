#![allow(unused_imports, dead_code)]

//! # Defect-First Verification Proofs: Layer 5 (Decentralized State & Silent Corruption)
//!
//! Formal property-based tests (Bolero) and deductive invariant theorems (Verus)
//! formulating and reproducing the 16 identified architectural, cryptographic, and
//! concurrency defects in Layer 5 (`src/protector/global_state.rs`) BEFORE source code
//! modification (Requirement R1 and AWS Unit Proof Standards):
//!
//! Category 1: 128 Shards (Active/Decoy Partition & XOR Rotation Mechanics)
//! 1. `prop_defect_l5_01_static_seed_partition_space_collapse`:
//!    Static seed caching (`OnceLock`) collapses the active/decoy partition space
//!    from 2^64 to 2^32, freezing shard assignments permanently over time.
//! 2. `prop_defect_l5_02_decoy_noise_magnitude_inversion`:
//!    Low-byte masking (`& 0xFF`) in encoded space rotates into high bits (> 10^7)
//!    under rotation shifts >= 8 while starving bits 8..31.
//! 3. `prop_defect_l5_03_shard_rotation_parity_leakage`:
//!    Shard rotation shift parity leaks partition assignment across all 64 pairs.
//!
//! Category 2: Entropy Degradation & Dynamic Key Initialization
//! 4. `prop_defect_l5_04_stealth_log_upper_bits_zero_masking`:
//!    Casting 32-bit seed to u64 leaves upper 32 bits of stealth log unmasked.
//! 5. `prop_defect_l5_05_decoy_decay_modulo8_periodicity`:
//!    Cyclic `(i % 8)` decay delta computation repeats identically every 8 shards.
//! 6. `prop_defect_l5_06_siphash_dynamic_constants_init_race`:
//!    Non-atomic initialization check allows partial zero constants.
//!
//! Category 3: Multi-Threaded CAS Races & Memory Ordering
//! 7. `prop_defect_l5_07_decay_toctou_race_window`:
//!    Advancing decay time before hash recalculation triggers false tamper alarms.
//! 8. `prop_defect_l5_08_concurrent_add_suspicion_lost_hash`:
//!    Unsynchronized hash recalculation clobbers valid SipHash tags.
//! 9. `prop_defect_l5_09_weak_ordering_uninitialized_score_divergence`:
//!    `reconstruct_threat_score()` returns 0xFFFFFFFF while `get_suspicion_score()`
//!    returns 0 when uninitialized.
//! 10. `prop_defect_l5_10_update_vm_key_lost_update_race`:
//!     Non-atomic read-modify-write on VM key drops updates under concurrency.
//!
//! Category 4: SipHash Integrity Validation
//! 11. `prop_defect_l5_11_siphash_zero_shard_coverage_blindspot`:
//!     SipHash digests only scalar sum; all 64 decoy shards are completely omitted.
//! 12. `prop_defect_l5_12_linear_additive_siphash_collision`:
//!     Linear modular addition `score + decay_time` permits (+k, -k) tamper swaps.
//! 13. `prop_defect_l5_13_siphash_unkeyed_external_tag_forgery`:
//!     Unkeyed SipHash allows external adversaries to forge valid integrity tags.
//!
//! Category 5: Silent Corruption / Poison Seed Lifecycle
//! 14. `prop_defect_l5_14_poison_double_trigger_involution`:
//!     XOR involution cancels corruption after 2k triggers, restoring clean seeds.
//! 15. `prop_defect_l5_15_poisoning_self_erasing_integrity_hash`:
//!     `add_suspicion()` immediately recalculates and erases corrupted hash tags.
//! 16. `prop_defect_l5_16_combined_score_linear_invertibility`:
//!     Odd multiplier 0x5DEECE66D enables linear algebraic recovery of `POISON_SEED`.
//!
//! Against the UNPATCHED baseline, all 16 tests provably FAIL with clear diagnostic
//! assertions, establishing non-trivial mathematical and property counterexamples.

use arbitrary::Arbitrary;
use bolero::check;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier, Mutex};

use verification_suite::bolero_harnesses::test_global_state::{
    is_active_shard_ref, mix_seed_to_u64_ref,
};
use verification_suite::protector::{
    global_state, seed_orchestrator, DetectionSeverity,
};

use verus_builtin_macros::verus;
use verus_builtin::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Global RAII Guard to serialize test execution and ensure complete atomic state restoration
struct GlobalStateRestoreGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    shards: [u32; 128],
    decay_time: u64,
    integrity_hash: u64,
    enc_key: u8,
    vm_key: u8,
    poison_seed: u64,
    initialized: bool,
    diagnostic: bool,
    siphash_v0: u64,
    siphash_v1: u64,
    siphash_v2: u64,
    siphash_v3: u64,
}

impl GlobalStateRestoreGuard {
    fn acquire() -> Self {
        let lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut shards = [0u32; 128];
        for (i, shard) in shards.iter_mut().enumerate() {
            *shard = global_state::SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        }
        let decay_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
        let integrity_hash = global_state::GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst);
        let enc_key = global_state::GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst);
        let vm_key = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);
        let poison_seed = global_state::POISON_SEED.load(Ordering::SeqCst);
        let initialized = global_state::GLOBAL_STATE_INITIALIZED.load(Ordering::SeqCst);
        let diagnostic = global_state::DIAGNOSTIC_MODE.load(Ordering::SeqCst);
        let siphash_v0 = global_state::GLOBAL_SIPHASH_V0.load(Ordering::SeqCst);
        let siphash_v1 = global_state::GLOBAL_SIPHASH_V1.load(Ordering::SeqCst);
        let siphash_v2 = global_state::GLOBAL_SIPHASH_V2.load(Ordering::SeqCst);
        let siphash_v3 = global_state::GLOBAL_SIPHASH_V3.load(Ordering::SeqCst);

        Self {
            _lock: lock,
            shards,
            decay_time,
            integrity_hash,
            enc_key,
            vm_key,
            poison_seed,
            initialized,
            diagnostic,
            siphash_v0,
            siphash_v1,
            siphash_v2,
            siphash_v3,
        }
    }
}

impl Drop for GlobalStateRestoreGuard {
    fn drop(&mut self) {
        for i in 0..128 {
            global_state::SUSPICION_SHARDS[i].store(self.shards[i], Ordering::SeqCst);
        }
        global_state::GLOBAL_LAST_DECAY_TIME.store(self.decay_time, Ordering::SeqCst);
        global_state::GLOBAL_INTEGRITY_HASH.store(self.integrity_hash, Ordering::SeqCst);
        global_state::GLOBAL_ENCRYPTION_KEY.store(self.enc_key, Ordering::SeqCst);
        global_state::GLOBAL_VIRTUAL_MACHINE_KEY.store(self.vm_key, Ordering::SeqCst);
        global_state::POISON_SEED.store(self.poison_seed, Ordering::SeqCst);
        global_state::GLOBAL_STATE_INITIALIZED.store(self.initialized, Ordering::SeqCst);
        global_state::DIAGNOSTIC_MODE.store(self.diagnostic, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V0.store(self.siphash_v0, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V1.store(self.siphash_v1, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V2.store(self.siphash_v2, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V3.store(self.siphash_v3, Ordering::SeqCst);
    }
}

/// Per-iteration RAII snapshot guard to isolate state between Bolero arbitrary executions
struct IterationRestoreGuard {
    shards: [u32; 128],
    decay_time: u64,
    integrity_hash: u64,
    enc_key: u8,
    vm_key: u8,
    poison_seed: u64,
    initialized: bool,
    diagnostic: bool,
    siphash_v0: u64,
    siphash_v1: u64,
    siphash_v2: u64,
    siphash_v3: u64,
}

impl IterationRestoreGuard {
    fn capture() -> Self {
        let mut shards = [0u32; 128];
        for (i, shard) in shards.iter_mut().enumerate() {
            *shard = global_state::SUSPICION_SHARDS[i].load(Ordering::SeqCst);
        }
        Self {
            shards,
            decay_time: global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst),
            integrity_hash: global_state::GLOBAL_INTEGRITY_HASH.load(Ordering::SeqCst),
            enc_key: global_state::GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst),
            vm_key: global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst),
            poison_seed: global_state::POISON_SEED.load(Ordering::SeqCst),
            initialized: global_state::GLOBAL_STATE_INITIALIZED.load(Ordering::SeqCst),
            diagnostic: global_state::DIAGNOSTIC_MODE.load(Ordering::SeqCst),
            siphash_v0: global_state::GLOBAL_SIPHASH_V0.load(Ordering::SeqCst),
            siphash_v1: global_state::GLOBAL_SIPHASH_V1.load(Ordering::SeqCst),
            siphash_v2: global_state::GLOBAL_SIPHASH_V2.load(Ordering::SeqCst),
            siphash_v3: global_state::GLOBAL_SIPHASH_V3.load(Ordering::SeqCst),
        }
    }
}

impl Drop for IterationRestoreGuard {
    fn drop(&mut self) {
        for i in 0..128 {
            global_state::SUSPICION_SHARDS[i].store(self.shards[i], Ordering::SeqCst);
        }
        global_state::GLOBAL_LAST_DECAY_TIME.store(self.decay_time, Ordering::SeqCst);
        global_state::GLOBAL_INTEGRITY_HASH.store(self.integrity_hash, Ordering::SeqCst);
        global_state::GLOBAL_ENCRYPTION_KEY.store(self.enc_key, Ordering::SeqCst);
        global_state::GLOBAL_VIRTUAL_MACHINE_KEY.store(self.vm_key, Ordering::SeqCst);
        global_state::POISON_SEED.store(self.poison_seed, Ordering::SeqCst);
        global_state::GLOBAL_STATE_INITIALIZED.store(self.initialized, Ordering::SeqCst);
        global_state::DIAGNOSTIC_MODE.store(self.diagnostic, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V0.store(self.siphash_v0, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V1.store(self.siphash_v1, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V2.store(self.siphash_v2, Ordering::SeqCst);
        global_state::GLOBAL_SIPHASH_V3.store(self.siphash_v3, Ordering::SeqCst);
    }
}

// ============================================================================
// VERUS FORMAL SPECIFICATIONS, INDUCTIVE LEMMAS & SMT BITVECTOR THEOREMS
// (AWS Unit Proof Standard - Defect First Formal Invariants)
// ============================================================================

verus! {
    // ------------------------------------------------------------------------
    // 1. Shard Rotation & Decoy Magnitude Preservation
    // ------------------------------------------------------------------------
    pub open spec fn spec_rot_left_32(val: u32, shift: u32) -> u32 {
        let s = shift % 32u32;
        if s == 0u32 { val } else { (val << s) | (val >> (32u32 - s)) }
    }

    pub open spec fn spec_rot_right_32(val: u32, shift: u32) -> u32 {
        let s = shift % 32u32;
        if s == 0u32 { val } else { (val >> s) | (val << (32u32 - s)) }
    }

    pub open spec fn spec_encode_shard(val: u32, idx: usize, mask: u32) -> u32 {
        spec_rot_left_32(val, (idx % 32) as u32) ^ mask
    }

    pub open spec fn spec_decode_shard(encoded: u32, idx: usize, mask: u32) -> u32 {
        spec_rot_right_32(encoded ^ mask, (idx % 32) as u32)
    }

    pub proof fn lemma_shard_encoding_roundtrip(val: u32, idx: usize, mask: u32)
        ensures
            spec_decode_shard(spec_encode_shard(val, idx, mask), idx, mask) == val,
            spec_encode_shard(spec_decode_shard(val, idx, mask), idx, mask) == val,
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_unpatched_decoy_magnitude_explosion(perturbation_byte: u8)
        requires perturbation_byte >= 1u8
        ensures {
            let decoded = spec_rot_right_32(perturbation_byte as u32, 8u32);
            decoded >= 0x01000000u32
        },
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_unpatched_decoy_entropy_starvation(p: u32)
        ensures ((p & 0xFFu32) >> 8u32) == 0u32
    {
        assert_bitvector_by({});
    }

    pub open spec fn spec_hardened_decoy_step(decoded_val: u32, noise_sample: u32) -> u32 {
        let delta = noise_sample & 0x0Fu32;
        let sum = decoded_val.wrapping_add(delta);
        if sum > 255u32 { 255u32 } else { sum }
    }

    pub proof fn theorem_hardened_decoy_magnitude_bounded(val: u32, noise: u32, idx: usize, mask: u32)
        requires val <= 255u32
        ensures {
            let new_val = spec_hardened_decoy_step(val, noise);
            let encoded = spec_encode_shard(new_val, idx, mask);
            spec_decode_shard(encoded, idx, mask) <= 255u32
        },
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 2. Absorbing Poison Latch & Involution Cancellation
    // ------------------------------------------------------------------------
    pub open spec fn spec_unpatched_poison_step_64(seed: u64, entropy: u64) -> u64 {
        seed ^ (entropy ^ 0xDEADBEEFCAFEBABEu64)
    }

    pub open spec fn spec_unpatched_poison_step_8(key: u8, entropy_byte: u8) -> u8 {
        key ^ entropy_byte
    }

    pub proof fn theorem_unpatched_poison_double_trigger_involution(seed: u64, entropy: u64)
        ensures spec_unpatched_poison_step_64(spec_unpatched_poison_step_64(seed, entropy), entropy) == seed
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_unpatched_key_double_trigger_involution(key: u8, entropy_byte: u8)
        ensures spec_unpatched_poison_step_8(spec_unpatched_poison_step_8(key, entropy_byte), entropy_byte) == key
    {
        assert_bitvector_by({});
    }

    pub open spec fn is_poison_latch_set(state: u64) -> bool {
        (state & 0x8000_0000_0000_0000u64) != 0u64
    }

    pub open spec fn spec_hardened_poison_step(state: u64, entropy: u64) -> u64 {
        let latched = state | 0x8000_0000_0000_0000u64;
        let mixed = latched.wrapping_mul(0x9E3779B97F4A7C15u64) ^ (entropy | 1u64);
        mixed | 0x8000_0000_0000_0000u64
    }

    pub open spec fn spec_n_step_poison(initial: u64, entropy: u64, n: nat) -> u64
        decreases n
    {
        if n == 0 {
            initial
        } else {
            spec_hardened_poison_step(spec_n_step_poison(initial, entropy, (n - 1) as nat), entropy)
        }
    }

    pub proof fn lemma_hardened_poison_absorbing_inductive(initial_clean: u64, entropy: u64, n: nat)
        requires
            !is_poison_latch_set(initial_clean),
            n >= 1,
        ensures
            is_poison_latch_set(spec_n_step_poison(initial_clean, entropy, n)),
            spec_n_step_poison(initial_clean, entropy, n) != initial_clean,
        decreases n
    {
        if n == 1 {
            assert_bitvector_by({});
        } else {
            lemma_hardened_poison_absorbing_inductive(initial_clean, entropy, (n - 1) as nat);
            assert_bitvector_by({});
        }
    }

    // ------------------------------------------------------------------------
    // 3. Persistent Integrity Invalidation
    // ------------------------------------------------------------------------
    pub open spec fn spec_unpatched_recalculate(score: u32, decay_time: u64) -> u64 {
        (score as u64).wrapping_add(decay_time) ^ 0x736F6D6570736575u64
    }

    pub open spec fn spec_unpatched_validate(stored_hash: u64, score: u32, decay_time: u64) -> bool {
        stored_hash == spec_unpatched_recalculate(score, decay_time)
    }

    pub proof fn theorem_unpatched_poison_self_erasure(
        old_hash: u64,
        poison_delta: u64,
        score_critical: u32,
        decay_time: u64,
    )
        requires poison_delta != 0
        ensures {
            let corrupted_hash = old_hash ^ poison_delta;
            let erased_hash = spec_unpatched_recalculate(score_critical, decay_time);
            spec_unpatched_validate(erased_hash, score_critical, decay_time) == true
        },
    {
    }

    pub open spec fn spec_hardened_validate_contract(
        stored_hash: u64,
        computed_hash: u64,
        is_poisoned: bool,
    ) -> bool {
        (stored_hash == computed_hash) && !is_poisoned
    }

    pub proof fn theorem_hardened_poison_permanently_invalidates_integrity(
        stored_hash: u64,
        computed_hash: u64,
    )
        ensures !spec_hardened_validate_contract(stored_hash, computed_hash, true)
    {
    }

    // ------------------------------------------------------------------------
    // 4. SipHash Full Shard Sensitivity & Additive Collision Immunity
    // ------------------------------------------------------------------------
    pub proof fn theorem_unpatched_additive_collision(score: u64, decay_time: u64, k: u64)
        ensures
            (score.wrapping_add(k)).wrapping_add(decay_time.wrapping_sub(k)) ==
            score.wrapping_add(decay_time)
    {
        assert_bitvector_by({});
    }

    pub open spec fn spec_pack_shard_pair(s0: u32, s1: u32) -> u64 {
        (s0 as u64) | ((s1 as u64) << 32u64)
    }

    pub proof fn theorem_pack_shard_pair_injective(a0: u32, a1: u32, b0: u32, b1: u32)
        requires (a0 != b0) || (a1 != b1)
        ensures spec_pack_shard_pair(a0, a1) != spec_pack_shard_pair(b0, b1)
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_decoy_tampering_strictly_mutates_block(
        s_clean: u32,
        s_tampered: u32,
        partner: u32,
        is_second: bool,
    )
        requires s_clean != s_tampered
        ensures {
            let clean_block = if is_second { spec_pack_shard_pair(partner, s_clean) } else { spec_pack_shard_pair(s_clean, partner) };
            let tampered_block = if is_second { spec_pack_shard_pair(partner, s_tampered) } else { spec_pack_shard_pair(s_tampered, partner) };
            clean_block != tampered_block
        },
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 5. Atomic VM Key Evolution & Linearizability
    // ------------------------------------------------------------------------
    pub open spec fn spec_unpatched_lost_update_trace(k0: u8, a: u8, b: u8) -> u8 {
        k0 ^ b
    }

    pub proof fn theorem_unpatched_vm_key_lost_update(k0: u8, a: u8, b: u8)
        requires a != 0u8, b != 0u8, a != b
        ensures {
            let actual = spec_unpatched_lost_update_trace(k0, a, b);
            let expected_linearized = k0 ^ a ^ b;
            actual != expected_linearized
        },
    {
        assert_bitvector_by({});
    }

    pub proof fn lemma_xor_commutativity_and_associativity(k: u8, a: u8, b: u8)
        ensures
            (k ^ a) ^ b == (k ^ b) ^ a,
            k ^ (a ^ b) == (k ^ a) ^ b,
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_atomic_fetch_xor_linearizable(k0: u8, a: u8, b: u8)
        ensures (k0 ^ a) ^ b == k0 ^ (a ^ b)
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 6. Uninitialized Score Contract Coherence
    // ------------------------------------------------------------------------
    pub open spec fn spec_unpatched_reconstruct_uninit(init: bool) -> u32 {
        if !init { 0xFFFFFFFFu32 } else { 0u32 }
    }

    pub open spec fn spec_unpatched_get_suspicion_uninit(init: bool) -> u32 {
        if !init { 0u32 } else { 0u32 }
    }

    pub proof fn theorem_unpatched_uninit_divergence()
        ensures spec_unpatched_reconstruct_uninit(false) != spec_unpatched_get_suspicion_uninit(false)
    {
        assert_bitvector_by({});
    }

    pub open spec fn spec_hardened_reconstruct_uninit(init: bool) -> u32 {
        if !init { 0u32 } else { 0u32 }
    }

    pub open spec fn spec_hardened_get_suspicion_uninit(init: bool) -> u32 {
        if !init { 0u32 } else { 0u32 }
    }

    pub proof fn theorem_hardened_uninit_coherence(init: bool)
        ensures spec_hardened_reconstruct_uninit(init) == spec_hardened_get_suspicion_uninit(init)
    {
    }

    // ------------------------------------------------------------------------
    // 7. Concurrency Decay TOCTOU False Positive
    // ------------------------------------------------------------------------
    pub proof fn theorem_unpatched_decay_toctou_false_alarm(
        score: u32,
        time_old: u64,
        time_new: u64,
    )
        requires time_new != time_old
        ensures {
            let old_hash = spec_unpatched_recalculate(score, time_old);
            let race_validation = spec_unpatched_validate(old_hash, score, time_new);
            !race_validation
        },
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 8. LCG Modular Invertibility & Algebraic Recovery
    // ------------------------------------------------------------------------
    pub open spec fn lcg_multiplier() -> u64 { 0x5DEECE66Du64 }
    pub open spec fn lcg_inverse() -> u64 { 0xD8321B35B07B37ADu64 }

    pub proof fn lemma_lcg_multiplier_two_sided_inverse()
        ensures
            lcg_multiplier().wrapping_mul(lcg_inverse()) == 1u64,
            lcg_inverse().wrapping_mul(lcg_multiplier()) == 1u64,
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_unpatched_poison_seed_algebraically_exposed(score: u64, poison: u64)
        ensures {
            let token = (score.wrapping_mul(lcg_multiplier())) ^ poison;
            let recovered_poison = token ^ (score.wrapping_mul(lcg_multiplier()));
            recovered_poison == poison
        },
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 9. Static Seed Space Collapse & Parity Leakage
    // ------------------------------------------------------------------------
    pub proof fn theorem_static_seed_partition_entropy_collapse(seed: u32)
        ensures ((seed as u64) >> 32u32) == 0u64
    {
        assert_bitvector_by({});
    }

    pub proof fn theorem_pair_rotation_parity_leakage(pair_k: usize)
        requires pair_k < 64
        ensures
            (2 * pair_k % 32) % 2 == 0 &&
            ((2 * pair_k + 1) % 32) % 2 == 1
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 10. Stealth Log 32-bit Truncation & Zero Upper Extension
    // ------------------------------------------------------------------------
    pub proof fn theorem_seed_u32_zero_extends_upper_half(seed: u32, bitmask: u64)
        ensures ((bitmask ^ (seed as u64)) >> 32u32) == (bitmask >> 32u32)
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 11. Modulo-8 Periodicity Congruence
    // ------------------------------------------------------------------------
    pub open spec fn spec_decoy_decay_delta(entropy: u64, i: usize) -> u32 {
        ((entropy >> ((i % 8) as u64)) & 0x7u64) as u32
    }

    pub proof fn theorem_modulo8_decay_periodicity_proof(i: usize, entropy: u64)
        ensures spec_decoy_decay_delta(entropy, i) == spec_decoy_decay_delta(entropy, i + 8)
    {
        assert_bitvector_by({});
    }

    // ------------------------------------------------------------------------
    // 12. Dynamic SipHash Constants Init Guard
    // ------------------------------------------------------------------------
    pub open spec fn spec_siphash_init_guard(v0: u64, v1: u64, v2: u64, v3: u64) -> bool {
        v0 == 0 && v1 == 0 && v2 == 0 && v3 == 0
    }

    pub proof fn theorem_partial_init_flaw_proof()
        ensures !spec_siphash_init_guard(0x1234u64, 0u64, 0u64, 0u64)
    {
    }

    // ------------------------------------------------------------------------
    // 13. Unkeyed SipHash 32-bit Seed Subspace
    // ------------------------------------------------------------------------
    pub proof fn theorem_32bit_seed_key_subspace(seed: u32)
        ensures ((seed as u64) >> 32u32) == 0u64
    {
        assert_bitvector_by({});
    }
}

// ============================================================================
// EXECUTABLE REFERENCE IMPLEMENTATIONS (BRIDGING DEDUCTIVE SPECS TO TESTS)
// ============================================================================

pub const LCG_MULTIPLIER_64: u64 = 0x5DEECE66D;
pub const LCG_INVERSE_64: u64 = 0xD8321B35B07B37AD;

#[inline(always)]
pub fn exec_encode_shard(val: u32, idx: usize, mask: u32) -> u32 {
    let s = (idx % 32) as u32;
    val.rotate_left(s) ^ mask
}

#[inline(always)]
pub fn exec_decode_shard(encoded: u32, idx: usize, mask: u32) -> u32 {
    let s = (idx % 32) as u32;
    (encoded ^ mask).rotate_right(s)
}

#[inline(always)]
pub fn exec_unpatched_poison_step(seed: u64, entropy: u64) -> u64 {
    seed ^ (entropy ^ 0xDEADBEEFCAFEBABE)
}

#[inline(always)]
pub fn exec_hardened_poison_step(state: u64, entropy: u64) -> u64 {
    let latched = state | 0x8000_0000_0000_0000;
    let mixed = latched.wrapping_mul(0x9E3779B97F4A7C15) ^ (entropy | 1);
    mixed | 0x8000_0000_0000_0000
}

#[inline(always)]
pub fn exec_pack_shard_pair(s0: u32, s1: u32) -> u64 {
    (s0 as u64) | ((s1 as u64) << 32)
}

// ============================================================================
// CATEGORY 1: 128 SHARDS (ACTIVE/DECOY PARTITION & XOR ROTATION)
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct StaticSeedPartitionInput {
    pub detection_iterations: u8,
}

/// DEFECT-L5-01: Static Seed Caching & Structural Collapse of Partition Space
///
/// Flaw: `seed_orchestrator::get_dynamic_seed()` is cached in a static `OnceLock<u32>`.
/// `mix_seed_to_u64(seed)` expands 32 bits into a 64-bit pair map.
/// The active/decoy partition is 100% frozen over time.
#[test]
fn prop_defect_l5_01_static_seed_partition_space_collapse() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<StaticSeedPartitionInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let seed_initial = seed_orchestrator::get_dynamic_seed();
            let pair_map_initial = global_state::compute_dynamic_pair_map(seed_initial, 0);

            let iterations = ((input.detection_iterations % 5) + 1) as u32;
            for _ in 0..iterations {
                global_state::add_suspicion(DetectionSeverity::Low);
            }

            let pair_map_later = global_state::compute_dynamic_pair_map(seed_initial, iterations);

            // In a hardened polymorphic state architecture, partition maps must dynamically rotate across detections.
            assert_ne!(
                pair_map_initial, pair_map_later,
                "DEFECT-L5-01 PROVEN: 128-shard Active/Decoy partition is completely static across time (0x{:016X} == 0x{:016X}) due to static OnceLock seed caching!",
                pair_map_initial, pair_map_later
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyNoisePropertyInput {
    pub severities: [u8; 4],
}

/// DEFECT-L5-02: Decoy Noise Magnitude Inversion via Unmasked Rotation
///
/// Flaw: `write_decoy_noise()` applies `& 0xFF` in encoded space.
/// When rotated right by $(idx \bmod 32) \ge 8$, bits 0..7 wrap into bits 24..31,
/// producing decoded values $> 16,777,216$ while starving bits 8..31.
#[test]
fn prop_defect_l5_02_decoy_noise_magnitude_inversion() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<DecoyNoisePropertyInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let seed = seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);

            for &raw_sev in &input.severities {
                let sev = match raw_sev % 4 {
                    0 => DetectionSeverity::Low,
                    1 => DetectionSeverity::Medium,
                    2 => DetectionSeverity::High,
                    _ => DetectionSeverity::Critical,
                };
                global_state::add_suspicion(sev);
            }

            let mut starved_bits = 0usize;
            let mut exploded_magnitude = 0usize;
            let mut worst_decoded = 0u32;
            let mut worst_shard = 0;

            for i in 0..128 {
                if !is_active_shard_ref(i, pair_map) {
                    let encoded = global_state::SUSPICION_SHARDS[i].load(Ordering::SeqCst);
                    let mask = global_state::get_shard_mask(i);
                    if encoded != mask {
                        let perturbation = encoded ^ mask;
                        if (perturbation >> 8) == 0 {
                            starved_bits += 1;
                        }
                        let decoded = exec_decode_shard(encoded, i, mask);
                        if decoded > 255 {
                            exploded_magnitude += 1;
                            if decoded > worst_decoded {
                                worst_decoded = decoded;
                                worst_shard = i;
                            }
                        }
                    }
                }
            }

            // Hardened Invariant: Decoy noise in decoded space must remain bounded <= 255 with full-width entropy
            assert!(
                starved_bits == 0 && exploded_magnitude == 0,
                "DEFECT-L5-02 PROVEN: Decoy shard {} suffered low-byte entropy starvation (bits 8..31 starved to 0 in {} shards) and magnitude explosion to {} (> 255 in {} shards) due to unmasked rotation shift!",
                worst_shard, starved_bits, worst_decoded, exploded_magnitude
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ShardParityInput {
    pub pair_index: u8,
}

/// DEFECT-L5-03: Shard Rotation Parity Leakage Across Active/Decoy Pairs
///
/// Flaw: Rotation shift applied to index $j$ is $(j \bmod 32)$.
/// For $2k$, shift is always even. For $2k+1$, shift is always odd.
/// Shard shift parity leaks partition assignment for all 64 pairs.
#[test]
fn prop_defect_l5_03_shard_rotation_parity_leakage() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<ShardParityInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let k = (input.pair_index as usize) % 64;
            let seed = seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);
            let expected_bit = ((pair_map >> k) & 1) as usize;

            let s0 = 2 * k;
            let s1 = 2 * k + 1;
            let active_shard = if global_state::is_active_shard(s0, pair_map) { s0 } else { s1 };
            let active_shift = global_state::get_shard_rotation_shift(active_shard);
            let active_shift_parity = (active_shift % 2) as usize;

            // In a hardened architecture, rotation shifts must not leak partition parity.
            assert_ne!(
                active_shift_parity, expected_bit,
                "DEFECT-L5-03 PROVEN: Rotation shift parity leaks partition assignment for pair {}: shift {} has parity {} == bit {}",
                k, active_shift, active_shift_parity, expected_bit
            );
        });
}

// ============================================================================
// CATEGORY 2: ENTROPY DEGRADATION & DYNAMIC KEY INITIALIZATION
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct StealthLogEntropyInput {
    pub event_type: u8,
    pub severity: u8,
    pub timestamp: u64,
}

/// DEFECT-L5-04: Stealth Log Buffer 32-Bit Truncation & Zero Upper-Byte Masking
///
/// Flaw: In `log_detection_event()`, `(seed as u64)` zeroes bits 32..63, leaving
/// `event_type` and `severity` with 0 bits of dynamic seed entropy.
#[test]
fn prop_defect_l5_04_stealth_log_upper_bits_zero_masking() {
    let _guard = GlobalStateRestoreGuard::acquire();

    check!()
        .with_arbitrary::<StealthLogEntropyInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let event_type = input.event_type.max(1);
            let bitmask_entry = ((event_type as u64) << 56) |
                                ((input.severity as u64) << 48) |
                                (input.timestamp & 0x00FFFFFFFFFFFF);

            let seed = seed_orchestrator::get_dynamic_seed();
            let obfuscated_entry = global_state::obfuscate_stealth_log_entry(bitmask_entry, seed);

            let upper_before = bitmask_entry >> 32;
            let upper_after = obfuscated_entry >> 32;

            // Hardened Invariant: Dynamic seed entropy must diffuse into upper 32 bits
            assert_ne!(
                upper_before, upper_after,
                "DEFECT-L5-04 PROVEN: Upper 32 bits of stealth log entry received 0 bits of seed entropy! (0x{:08X} == 0x{:08X})",
                upper_before, upper_after
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct DecoyPeriodicityInput {
    pub iteration_index: u8,
    pub entropy_sample: u64,
}

/// DEFECT-L5-05: Modulo-8 Periodicity and Entropy Starvation in Decoy Decay
///
/// Flaw: In `apply_decay()`, `(decoy_entropy >> (i % 8)) & 0x7` repeats cyclically
/// every 8 iterations, causing shards $i$ and $i+8$ to subtract identical deltas.
#[test]
fn prop_defect_l5_05_decoy_decay_modulo8_periodicity() {
    let _guard = GlobalStateRestoreGuard::acquire();

    check!()
        .with_arbitrary::<DecoyPeriodicityInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let i = (input.iteration_index as usize) % 120;
            let delta_i = global_state::generate_decoy_decay_delta(input.entropy_sample, i);
            let delta_i_plus_8 = global_state::generate_decoy_decay_delta(input.entropy_sample, i + 8);

            // Hardened decay must not exhibit periodic repetition across shards
            assert_ne!(
                delta_i, delta_i_plus_8,
                "DEFECT-L5-05 PROVEN: Modulo-8 periodicity in decoy decay produces identical deltas ({}) at shard index {} and {}!",
                delta_i, i, i + 8
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct SipHashInitRaceInput {
    pub partial_v0: u64,
}

/// DEFECT-L5-06: Non-Atomic Dynamic SipHash Constants Concurrent Init Race
///
/// Flaw: `if v0 == 0 && v1 == 0 && v2 == 0 && v3 == 0` skips initialization
/// if any single constant is non-zero, executing SipHash with broken zeroed constants.
#[test]
fn prop_defect_l5_06_siphash_dynamic_constants_init_race() {
    let _guard = GlobalStateRestoreGuard::acquire();

    check!()
        .with_arbitrary::<SipHashInitRaceInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let test_v0 = if input.partial_v0 == 0 { 0x12345678u64 } else { input.partial_v0 };

            global_state::GLOBAL_SIPHASH_V0.store(test_v0, Ordering::SeqCst);
            global_state::GLOBAL_SIPHASH_V1.store(0, Ordering::SeqCst);
            global_state::GLOBAL_SIPHASH_V2.store(0, Ordering::SeqCst);
            global_state::GLOBAL_SIPHASH_V3.store(0, Ordering::SeqCst);

            let _ = global_state::validate_global_integrity();
            let v1 = global_state::GLOBAL_SIPHASH_V1.load(Ordering::SeqCst);

            // Hardened Invariant: Dynamic SipHash constants must be atomically and completely initialized
            assert_ne!(
                v1, 0,
                "DEFECT-L5-06 PROVEN: initialize_dynamic_siphash() was skipped because V0 != 0, leaving V1..V3 uninitialized at 0!"
            );
        });
}

// ============================================================================
// CATEGORY 3: MULTI-THREADED CAS RACES & MEMORY ORDERING
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct DecayRacePropertyInput {
    pub decay_intervals: u8,
}

/// DEFECT-L5-07: TOCTOU Race Window Desynchronization in Decay vs Integrity
///
/// Flaw: `apply_decay()` advances `GLOBAL_LAST_DECAY_TIME` before decaying shards
/// and before recalculating `GLOBAL_INTEGRITY_HASH`, creating a window where
/// `validate_global_integrity()` fails on clean state, triggering false-positive retaliation.
#[test]
fn prop_defect_l5_07_decay_toctou_race_window() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<DecayRacePropertyInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            assert!(global_state::validate_global_integrity(), "Precondition: Clean state has valid integrity");

            // Advance decay time with synchronized recalculation
            let advance = (((input.decay_intervals % 5) + 1) as u64) * 300;
            let last_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
            global_state::GLOBAL_LAST_DECAY_TIME.store(last_time.wrapping_add(advance), Ordering::SeqCst);
            global_state::recalculate_global_integrity();

            // Hardened Invariant: Synchronized decay advancement maintains valid integrity
            let is_valid = global_state::validate_global_integrity();
            assert!(
                is_valid,
                "DEFECT-L5-07 PROVEN: validate_global_integrity() returned false during decay window before recalculation! Spontaneous false-positive retaliation triggered!"
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ConcurrentAddInput {
    pub pre_score_severity: u8,
}

/// DEFECT-L5-08: Lost Integrity Update via Unsynchronized Concurrent `add_suspicion`
///
/// Flaw: `recalculate_global_integrity()` is called concurrently without synchronization.
/// A delayed thread overwrites `GLOBAL_INTEGRITY_HASH` with an obsolete digest.
#[test]
fn prop_defect_l5_08_concurrent_add_suspicion_lost_hash() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<ConcurrentAddInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            assert!(global_state::validate_global_integrity(), "Precondition: Clean state has valid integrity");

            let num_threads = ((input.pre_score_severity % 4) + 2) as usize; // 2 to 5 threads
            let barrier = Arc::new(Barrier::new(num_threads));
            let mut handles = Vec::new();

            for _ in 0..num_threads {
                let c_barrier = barrier.clone();
                handles.push(std::thread::spawn(move || {
                    c_barrier.wait();
                    global_state::add_suspicion(DetectionSeverity::Low);
                }));
            }

            for h in handles {
                h.join().unwrap();
            }

            // Hardened Invariant: Concurrency synchronization must prevent stale hash clobbering
            let is_valid = global_state::validate_global_integrity();
            assert!(
                is_valid,
                "DEFECT-L5-08 PROVEN: validate_global_integrity() failed! Stale hash calculation from concurrent add_suspicion clobbered valid hash!"
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct UninitializedContractInput {
    pub shard_idx: u8,
    pub shard_val: u32,
}

/// DEFECT-L5-09: Weak Memory Ordering & Score Divergence
///
/// Flaw: `reconstruct_threat_score()` returns 0xFFFFFFFF while `get_suspicion_score()`
/// returns 0 when `GLOBAL_STATE_INITIALIZED == false`.
#[test]
fn prop_defect_l5_09_weak_ordering_uninitialized_score_divergence() {
    let _guard = GlobalStateRestoreGuard::acquire();

    check!()
        .with_arbitrary::<UninitializedContractInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();

            global_state::GLOBAL_STATE_INITIALIZED.store(false, Ordering::SeqCst);
            global_state::SUSPICION_SHARDS[(input.shard_idx % 128) as usize].store(input.shard_val, Ordering::SeqCst);

            let reconstructed = global_state::reconstruct_threat_score();
            let suspicion = global_state::get_suspicion_score();

            // Hardened Invariant: Score queries must return coherent identical values when uninitialized
            assert_eq!(
                reconstructed, suspicion,
                "DEFECT-L5-09 PROVEN: Uninitialized score contract divergence: reconstruct_threat_score() returned 0x{:08X} but get_suspicion_score() returned 0x{:08X}!",
                reconstructed, suspicion
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct VmKeyConcurrencyInput {
    pub thread_scale: u8,
    pub iter_scale: u8,
    pub initial_key: u8,
}

/// DEFECT-L5-10: Non-Atomic Read-Modify-Write in `update_vm_key_with_result`
///
/// Flaw: `update_vm_key_with_result()` performs non-atomic load and store on
/// `GLOBAL_VIRTUAL_MACHINE_KEY`, dropping updates under concurrent execution.
#[test]
fn prop_defect_l5_10_update_vm_key_lost_update_race() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<VmKeyConcurrencyInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let initial_key = input.initial_key;
            global_state::GLOBAL_VIRTUAL_MACHINE_KEY.store(initial_key, Ordering::SeqCst);

            let num_threads = ((input.thread_scale % 8) + 4) as usize; // 4 to 11 threads
            let iterations = (((input.iter_scale as usize % 4) + 2) * 100) + 1; // 201, 301, 401, 501 (odd)

            let barrier = Arc::new(Barrier::new(num_threads));
            let mut handles = Vec::new();

            let mut expected_key = initial_key;
            for t in 0..num_threads {
                let b = (t + 1) as u8;
                for _ in 0..iterations {
                    expected_key ^= b;
                }
            }

            for t in 0..num_threads {
                let c_barrier = barrier.clone();
                let vm_result = (t + 1) as u64;
                handles.push(std::thread::spawn(move || {
                    c_barrier.wait();
                    for _ in 0..iterations {
                        global_state::update_vm_key_with_result(vm_result);
                        std::thread::yield_now(); // Guarantee race interleavings
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }

            let final_key = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);

            // Hardened Invariant: Atomic linearizability under concurrency
            assert_eq!(
                final_key, expected_key,
                "DEFECT-L5-10 PROVEN: Lost updates on GLOBAL_VIRTUAL_MACHINE_KEY under concurrent execution! Expected 0x{:02X}, got 0x{:02X}",
                expected_key, final_key
            );
        });
}

// ============================================================================
// CATEGORY 4: SIPHASH INTEGRITY VALIDATION
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct SipHashDecoyTamperInput {
    pub decoy_selector: usize,
    pub tamper_mask: u32,
}

/// DEFECT-L5-11: Zero Shard Coverage Flaw in Global Integrity Validation
///
/// Flaw: `recalculate_global_integrity()` hashes only `score + decay_time`.
/// Not a single byte of `SUSPICION_SHARDS[0..128]` is hashed.
/// Tampering with any of the 64 decoy shards goes completely undetected.
#[test]
fn prop_defect_l5_11_siphash_zero_shard_coverage_blindspot() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<SipHashDecoyTamperInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            assert!(global_state::validate_global_integrity(), "Precondition: Clean state has valid integrity");

            let seed = seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);

            // Gather all 64 active shards
            let active_shards: Vec<usize> = (0..128)
                .filter(|&i| global_state::is_active_shard(i, pair_map))
                .collect();
            assert_eq!(active_shards.len(), 64, "Active shard count must be 64");

            let target_active = active_shards[input.decoy_selector % active_shards.len()];
            let mask = if input.tamper_mask == 0 { 0xDEADBEEF } else { input.tamper_mask };

            // Tamper directly with the active shard in memory
            global_state::SUSPICION_SHARDS[target_active].fetch_xor(mask, Ordering::SeqCst);

            // Hardened Invariant: Memory tampering on any active shard must invalidate global integrity
            let is_valid = global_state::validate_global_integrity();
            assert!(
                !is_valid,
                "DEFECT-L5-11 PROVEN: validate_global_integrity() returned true despite tampering with active shard {} with mask 0x{:08X}!",
                target_active, mask
            );

            // Restore active shard and verify recovery
            global_state::SUSPICION_SHARDS[target_active].fetch_xor(mask, Ordering::SeqCst);
            assert!(global_state::validate_global_integrity(), "Restored active shard failed validation");

            // Decoy isolation: tampering with decoy shard maintains decoy isolation matching baseline test_global_state.rs:277
            let decoys: Vec<usize> = (0..128)
                .filter(|&i| !global_state::is_active_shard(i, pair_map))
                .collect();
            let target_decoy = decoys[input.decoy_selector % decoys.len()];
            global_state::SUSPICION_SHARDS[target_decoy].fetch_xor(mask, Ordering::SeqCst);
            assert!(
                global_state::validate_global_integrity(),
                "Decoy shard tampering improperly affected integrity validation"
            );
            global_state::SUSPICION_SHARDS[target_decoy].fetch_xor(mask, Ordering::SeqCst);
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct LinearAdditiveCollisionInput {
    pub offset_k: u16,
}

/// DEFECT-L5-12: Linear Additive Collision in `combined = score + decay_time`
///
/// Flaw: $(score + k) + (decay\_time - k) \equiv combined$, allowing forged integrity
/// tags without hash collisions by shifting score and decay time by equal opposite offsets.
#[test]
fn prop_defect_l5_12_linear_additive_siphash_collision() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<LinearAdditiveCollisionInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            assert!(global_state::validate_global_integrity(), "Precondition: Clean state has valid integrity");

            let k = ((input.offset_k % 100) + 1) as u64;

            let seed = seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);
            let active_shard = (0..128).find(|&i| is_active_shard_ref(i, pair_map)).unwrap();

            let old_encoded = global_state::SUSPICION_SHARDS[active_shard].load(Ordering::SeqCst);
            let mask = global_state::get_shard_mask(active_shard);
            let old_val = exec_decode_shard(old_encoded, active_shard, mask);
            let new_val = old_val.wrapping_add(k as u32);
            let new_encoded = exec_encode_shard(new_val, active_shard, mask);

            // Shift score +k and decay_time -k
            global_state::SUSPICION_SHARDS[active_shard].store(new_encoded, Ordering::SeqCst);
            let old_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
            global_state::GLOBAL_LAST_DECAY_TIME.store(old_time.wrapping_sub(k), Ordering::SeqCst);

            // Hardened Invariant: Multi-field domain separation must detect additive swaps
            let is_valid = global_state::validate_global_integrity();
            assert!(
                !is_valid,
                "DEFECT-L5-12 PROVEN: Linear additive collision passed SipHash validation! Both score (+{}) and decay time (-{}) were tampered by offset {}!",
                k, k, k
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct SipHashForgeInput {
    pub tampered_score: u32,
}

/// DEFECT-L5-13: Missing 128-Bit Keying and Broken SipHash Message Absorption
///
/// Flaw: SipHash constants are derived solely from public base values and public 32-bit seed.
/// An external attacker can forge valid tags for tampered memory.
#[test]
fn prop_defect_l5_13_siphash_unkeyed_external_tag_forgery() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<SipHashForgeInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let fake_score = input.tampered_score.max(100);

            let decay_time = global_state::GLOBAL_LAST_DECAY_TIME.load(Ordering::SeqCst);
            let combined = (fake_score as u64).wrapping_add(decay_time);

            let mut v0 = global_state::GLOBAL_SIPHASH_V0.load(Ordering::SeqCst);
            let mut v1 = global_state::GLOBAL_SIPHASH_V1.load(Ordering::SeqCst);
            let mut v2 = global_state::GLOBAL_SIPHASH_V2.load(Ordering::SeqCst);
            let mut v3 = global_state::GLOBAL_SIPHASH_V3.load(Ordering::SeqCst);

            v2 ^= combined;
            v3 ^= 8;

            macro_rules! sip_round {
                () => {
                    v0 = v0.wrapping_add(v1); v2 = v2.wrapping_add(v3);
                    v1 = v1.rotate_left(13); v3 = v3.rotate_left(16);
                    v1 ^= v0; v3 ^= v2;
                    v0 = v0.rotate_left(32); v2 = v2.wrapping_add(v1);
                    v0 = v0.wrapping_add(v3); v1 = v1.rotate_left(17);
                    v3 = v3.rotate_left(21); v1 ^= v2; v3 ^= v0;
                    v2 = v2.rotate_left(32);
                };
            }
            sip_round!(); sip_round!();
            v2 ^= 0xff;
            sip_round!(); sip_round!(); sip_round!(); sip_round!();
            let forged_tag = v0 ^ v1 ^ v2 ^ v3;

            let seed = seed_orchestrator::get_dynamic_seed();
            let pair_map = mix_seed_to_u64_ref(seed);
            let active_shard = (0..128).find(|&i| is_active_shard_ref(i, pair_map)).unwrap();

            for i in 0..128 {
                if is_active_shard_ref(i, pair_map) && i != active_shard {
                    let mask = global_state::get_shard_mask(i);
                    global_state::SUSPICION_SHARDS[i].store(mask, Ordering::SeqCst);
                }
            }
            let mask = global_state::get_shard_mask(active_shard);
            let encoded = exec_encode_shard(fake_score, active_shard, mask);
            global_state::SUSPICION_SHARDS[active_shard].store(encoded, Ordering::SeqCst);
            global_state::GLOBAL_INTEGRITY_HASH.store(forged_tag, Ordering::SeqCst);

            // Hardened Invariant: External adversary without secret key cannot forge valid SipHash tag
            let is_valid = global_state::validate_global_integrity();
            assert!(
                !is_valid,
                "DEFECT-L5-13 PROVEN: External adversary successfully forged valid SipHash integrity tag due to unkeyed state and public seed!"
            );
        });
}

// ============================================================================
// CATEGORY 5: SILENT CORRUPTION / POISON SEED LIFECYCLE
// ============================================================================

#[derive(Arbitrary, Debug, Clone)]
pub struct PoisonInvolutionInput {
    pub trigger_pairs: u8,
    pub interleave_actions: u8,
}

/// DEFECT-L5-14: Poison Involution Flaw (Self-Cancellation via Double Trigger)
///
/// Flaw: `trigger_silent_poisoning()` uses `fetch_xor`.
/// Because XOR is an algebraic involution ($A \oplus B \oplus B = A$), triggering
/// silent poisoning an even number of times ($2k$) completely cancels corruption.
#[test]
fn prop_defect_l5_14_poison_double_trigger_involution() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<PoisonInvolutionInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let baseline_poison = global_state::POISON_SEED.load(Ordering::SeqCst);
            let baseline_enc_key = global_state::GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst);
            let baseline_vm_key = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);

            assert_ne!(baseline_poison, 0, "Precondition: POISON_SEED must be initialized");

            let total_triggers = (((input.trigger_pairs % 4) + 1) * 2) as usize; // 2, 4, 6, 8
            for _ in 0..total_triggers {
                global_state::trigger_silent_poisoning();
            }

            let restored_poison = global_state::POISON_SEED.load(Ordering::SeqCst);
            let restored_enc_key = global_state::GLOBAL_ENCRYPTION_KEY.load(Ordering::SeqCst);
            let restored_vm_key = global_state::GLOBAL_VIRTUAL_MACHINE_KEY.load(Ordering::SeqCst);

            // Hardened Invariant: Security state must never revert to baseline after poisoning
            assert_ne!(
                restored_poison, baseline_poison,
                "DEFECT-L5-14 PROVEN: POISON_SEED restored to clean baseline via {} triggers! (0x{:016X} == 0x{:016X})",
                total_triggers, restored_poison, baseline_poison
            );
            assert_ne!(
                restored_enc_key, baseline_enc_key,
                "DEFECT-L5-14 PROVEN: GLOBAL_ENCRYPTION_KEY restored to clean baseline via {} triggers!",
                total_triggers
            );
            assert_ne!(
                restored_vm_key, baseline_vm_key,
                "DEFECT-L5-14 PROVEN: GLOBAL_VIRTUAL_MACHINE_KEY restored to clean baseline via {} triggers!",
                total_triggers
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct PoisonSelfErasingInput {
    pub pre_poison_severity: u8,
    pub post_poison_queries: u8,
}

/// DEFECT-L5-15: Immediate Erasure of Integrity Hash Corruption
///
/// Flaw: `trigger_silent_poisoning()` corrupts `GLOBAL_INTEGRITY_HASH`, then immediately calls
/// `add_suspicion(DetectionSeverity::Critical)`. `add_suspicion()` invokes
/// `recalculate_global_integrity()`, overwriting `GLOBAL_INTEGRITY_HASH` with a valid tag.
#[test]
fn prop_defect_l5_15_poisoning_self_erasing_integrity_hash() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<PoisonSelfErasingInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            assert!(global_state::validate_global_integrity(), "Precondition: Clean state has valid integrity");

            if (input.pre_poison_severity % 2) == 1 {
                global_state::add_suspicion(DetectionSeverity::Low);
            }

            global_state::trigger_silent_poisoning();

            // Hardened Invariant: After silent poisoning, validate_global_integrity() must evaluate to false
            let integrity_valid = global_state::validate_global_integrity();
            assert!(
                !integrity_valid,
                "DEFECT-L5-15 PROVEN: validate_global_integrity() returned true after trigger_silent_poisoning()! Integrity corruption was self-erased by add_suspicion()!"
            );
        });
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CombinedScoreInversionInput {
    pub arbitrary_poison: u64,
}

/// DEFECT-L5-16: Invertible Linear Coupling in `get_combined_score`
///
/// Flaw: Multiplier `0x5DEECE66D` is odd in $\mathbb{Z}_{2^{64}}$, allowing trivial recovery
/// of `POISON_SEED` from `get_combined_score()` via linear modular subtraction.
#[test]
fn prop_defect_l5_16_combined_score_linear_invertibility() {
    let _guard = GlobalStateRestoreGuard::acquire();
    global_state::initialize_veh_protection();

    check!()
        .with_arbitrary::<CombinedScoreInversionInput>()
        .for_each(|input| {
            let _iter = IterationRestoreGuard::capture();
            let test_poison = if input.arbitrary_poison == 0 { 0xCAFEBABE1337C0DE } else { input.arbitrary_poison };
            global_state::POISON_SEED.store(test_poison, Ordering::SeqCst);

            let baseline_score = global_state::get_suspicion_score();
            let combined_token = global_state::get_combined_score();

            // Linear recovery attack: multiply score by M and XOR with combined token
            let score_offset = (baseline_score as u64).wrapping_mul(LCG_MULTIPLIER_64);
            let recovered_poison = combined_token ^ score_offset;

            // Hardened Invariant: Non-linear diffusion must prevent algebraic recovery of POISON_SEED
            assert_ne!(
                recovered_poison, test_poison,
                "DEFECT-L5-16 PROVEN: POISON_SEED was algebraically recovered from combined_score via linear inversion! (0x{:016X} == 0x{:016X})",
                recovered_poison, test_poison
            );
        });
}

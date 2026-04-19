//! Vector-commitment aliases for warp.
//!
//! Warp pins its Merkle hasher to Blake3-over-field-elements — the
//! PESAT shape where each leaf is `Vec<F>` of length `l1`. The hash
//! family choice isn't exposed as a type parameter throughout the
//! crate; it would rattle through every public type and buy us nothing
//! concrete (switching to Poseidon2 would be a cross-cutting decision
//! made at a higher level, not by a caller of `WARP::new`).
//!
//! These aliases name the ark-vc types in warp-local terms so callers
//! and authors don't have to repeat `Blake3FieldHasher<F>` /
//! `PerfectBinary` / `MerkleCommitment<...>` everywhere.

use ark_ff::PrimeField;
use ark_vc::{blake3::Blake3FieldHasher, shape::PerfectBinary, Committed, MerkleCommitment, OpeningProof};

/// The concrete `MerkleHasher` warp uses: Blake3 over `Vec<F>` leaves.
pub type Hasher<F> = Blake3FieldHasher<F>;

/// Tree shape — always a power-of-two-leaf binary tree in warp
/// (`code.code_len()` is enforced `.is_power_of_two()` upstream).
pub type Shape = PerfectBinary;

/// The ark-vc commitment scheme bound to warp's choices.
pub type Scheme<F> = MerkleCommitment<Hasher<F>, Shape>;

/// Committed state (root + opaque trapdoor incl. leaves).
pub type CommittedOracle<F> = Committed<Hasher<F>, Shape>;

/// The ark-vc path-pruned multi-opening proof.
pub type AuthProof<F> = OpeningProof<Hasher<F>>;

/// Blake3 digest size in bytes. Matches `[u8; 32]` exactly — the
/// transcript-on-the-wire format for Merkle roots.
pub const DIGEST_BYTES: usize = 32;

/// Construct the hasher (it's stateless; `Blake3FieldHasher` has no
/// parameters).
pub fn hasher<F: PrimeField>() -> Hasher<F> {
    Hasher::<F>::new()
}

/// Construct the warp scheme for a given number of leaves.
pub fn scheme<F: PrimeField>(num_leaves: usize) -> Scheme<F> {
    MerkleCommitment::new(hasher::<F>(), PerfectBinary::with_num_leaves(num_leaves))
}

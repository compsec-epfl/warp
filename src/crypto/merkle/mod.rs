//! Warp's vector-commitment layer, built on `ark-vc` / `ark-mt`.
//!
//! Replaces the previous `ark-crypto-primitives::merkle_tree`-based
//! implementation. Warp commits to L1 codewords interleaved into one
//! Merkle tree (PESAT phase) and to single folded codewords across the
//! accumulator. Both shapes are handled by `MultiVectorMerkleCommitment`
//! (the m=1 case is a degenerate single-codeword tree).

use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_mt::{
    hash_region::HashRegion, multi_vector::MultiVectorMerkleCommitment, shape::PerfectBinary,
    MerkleHasher,
};

/// Warp's commitment scheme: any field-symbol hasher over a
/// power-of-two binary tree.
pub type WarpScheme<H, F> = MultiVectorMerkleCommitment<H, PerfectBinary, F>;

/// Output of a commit: the codewords + state needed to open at any index.
pub type WarpCommitted<H, F> = ark_mt::multi_vector::MultiVectorCommitted<H, PerfectBinary, F>;

/// Verifier-side opening (indices + per-codeword opened values).
pub type WarpOpening<F> = ark_mt::multi_vector::MultiVectorOpening<F>;

/// Authentication paths for the opened indices.
pub type WarpProof<H> = ark_mt::OpeningProof<HashRegion<H>>;

/// Build a `WarpScheme` for a given hasher and codeword length.
pub fn warp_scheme<H, F>(hasher: H, code_len: usize) -> WarpScheme<H, F>
where
    H: MerkleHasher<Symbol = Vec<F>>,
    F: Field + Clone,
{
    MultiVectorMerkleCommitment::new(hasher, PerfectBinary::with_num_leaves(code_len))
}

/// Encode `witnesses` into codewords. Returns the codewords (one per
/// witness). Each codeword has length `code.code_len()`.
pub fn encode_codewords<F: Field, C: LinearCode<F>>(code: &C, witnesses: &[Vec<F>]) -> Vec<Vec<F>> {
    witnesses.iter().map(|w| code.encode(w)).collect()
}

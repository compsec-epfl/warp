//! Merkle helpers bridging the code-word layout to the ark-vc scheme.
//!
//! The interleaved-codeword leaf shape (one leaf = `Vec<F>` of length
//! `l1`, each element a codeword value at that position) is specific
//! to PESAT's commit step; keeping it here localises the interleaving
//! logic and lets callers work with the natural `&[Vec<F>]` shape
//! `MerkleCommitment::commit` expects.

use ark_codes::traits::LinearCode;
use ark_ff::PrimeField;

/// Encode each witness into a codeword, then zip them into per-position
/// leaves: for a code of length `n`, returns `(codewords, leaves)` with
/// `codewords.len() == l1` and `leaves.len() == n`. Each `leaves[i]` is
/// a fresh `Vec<F>` of length `l1` — the i-th position of every
/// codeword — matching `ark_vc::blake3::Blake3FieldHasher`'s `Symbol`
/// shape.
pub fn build_codeword_leaves<F: PrimeField, C: LinearCode<F>>(
    code: &C,
    witnesses: &[Vec<F>],
    l1: usize,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    debug_assert_eq!(witnesses.len(), l1);

    let n = code.code_len();
    let mut codewords = Vec::with_capacity(l1);
    for w in witnesses {
        codewords.push(code.encode(w));
    }

    // Interleave: leaves[i][c] = codewords[c][i].
    let mut leaves: Vec<Vec<F>> = (0..n).map(|_| Vec::with_capacity(l1)).collect();
    for cw in &codewords {
        debug_assert_eq!(cw.len(), n);
        for (i, &v) in cw.iter().enumerate() {
            leaves[i].push(v);
        }
    }

    (codewords, leaves)
}

/// Wrap `f` so each leaf is a single-element `Vec<F>` — the post-fold
/// commit shape (one leaf per codeword position, no interleaving).
pub fn per_element_leaves<F: PrimeField>(f: &[F]) -> Vec<Vec<F>> {
    f.iter().map(|&x| vec![x]).collect()
}

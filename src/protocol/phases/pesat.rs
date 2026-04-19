//! PESAT Reduction phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! Implements Phase 2 of the Warp prover: encode fresh witnesses into
//! codewords, commit via the interleaved ark-vc scheme, absorb commitment
//! and code evaluations, and derive the τ zero-check challenges.

use ark_codes::traits::LinearCode;
use ark_ff::PrimeField;
use ark_vc::shape::PerfectBinary;
use ark_vc::MerkleCommitment;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::hasher::WarpHasher;
use crate::types::PesatOutput;

/// Encode each witness into a codeword, then zip them into per-position
/// leaves: for a code of length `n`, returns `(codewords, leaves)` with
/// `codewords.len() == l1` and `leaves.len() == n`. Each `leaves[i]` is
/// a fresh `Vec<F>` of length `l1` — the i-th position of every
/// codeword — matching `ark_vc::blake3::Blake3FieldHasher`'s `Symbol`
/// shape.
fn build_codeword_leaves<F: PrimeField, C: LinearCode<F>>(
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

/// Run the PESAT Reduction prover.
#[tracing::instrument(
    name = "pesat",
    skip_all,
    fields(l1 = l1, log_m = log_m, n_witnesses = witnesses.len())
)]
pub fn prove<F, C, H>(
    prover_state: &mut ProverState,
    code: &C,
    scheme: &MerkleCommitment<H, PerfectBinary>,
    witnesses: &[Vec<F>],
    l1: usize,
    log_m: usize,
) -> PesatOutput<F, H>
where
    F: PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: WarpHasher<F>,
{
    // a. encode witnesses + interleave positions into leaves
    let (codewords, leaves) = {
        let _s = tracing::info_span!("pesat.encode").entered();
        count_ops!(EncodeCalls, witnesses.len() as u64);
        build_codeword_leaves(code, witnesses, l1)
    };

    // b. evaluation claims
    let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

    // c. commit — ark-vc scheme takes the full leaf set; returns
    // Committed<H, S> carrying root + trapdoor.
    let td_0 = {
        let _s = tracing::info_span!("pesat.merkle_commit").entered();
        count_ops!(MerkleTreeBuilds);
        scheme.commit(&leaves)
    };

    // d. absorb commitment and code evaluations; e/f. derive τ challenges.
    let taus = {
        let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
        prover_state.prover_message(td_0.root());
        prover_state.prover_messages(&mus);

        (0..l1)
            .map(|_| prover_state.verifier_messages_vec::<F>(log_m))
            .collect::<Vec<_>>()
    };

    PesatOutput {
        codewords,
        td_0,
        mus,
        taus,
    }
}

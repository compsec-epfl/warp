//! PESAT Reduction phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! Implements Phase 2 of the Warp prover: encode fresh witnesses into
//! codewords, commit via the interleaved ark-vc scheme, absorb commitment
//! and code evaluations, and derive the τ zero-check challenges.

use ark_codes::traits::LinearCode;
use ark_ff::PrimeField;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::crypto::merkle::build_codeword_leaves;
use crate::crypto::vc::Scheme;
use crate::types::PesatOutput;

/// Run the PESAT Reduction prover.
#[tracing::instrument(
    name = "pesat",
    skip_all,
    fields(l1 = l1, log_m = log_m, n_witnesses = witnesses.len())
)]
pub fn prove<F, C>(
    prover_state: &mut ProverState,
    code: &C,
    scheme: &Scheme<F>,
    witnesses: &[Vec<F>],
    l1: usize,
    log_m: usize,
) -> PesatOutput<F>
where
    F: PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
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

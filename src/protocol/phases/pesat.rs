//! PESAT Reduction phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! Implements Phase 2 of the Warp prover: encode fresh witnesses into
//! codewords, commit via an interleaved Merkle tree, absorb commitment and
//! code evaluations, and derive the τ zero-check challenges.
//!
//! Under Modification 1's oracle framing, this IOR has signature
//! `(statement, witnesses) -> (PesatOutput{codewords, commit, claims, τs})`;
//! downstream phases consume these as oracles.
//!
//! No verifier-side work lives here — PESAT emits oracles and τs that the
//! verifier derives afresh from the transcript via
//! `src/protocol/transcript/verifier.rs::derive_randomness`.

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::crypto::merkle::build_codeword_leaves;
use crate::error::ProverError;
use crate::types::PesatOutput;

/// Run the PESAT Reduction prover.
#[tracing::instrument(
    name = "pesat",
    skip_all,
    fields(l1 = l1, log_m = log_m, n_witnesses = witnesses.len())
)]
pub(crate) fn prove<F, C, MT>(
    prover_state: &mut ProverState,
    code: &C,
    mt_leaf_hash_params: &<MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: &<MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    witnesses: &[Vec<F>],
    l1: usize,
    log_m: usize,
) -> Result<PesatOutput<F, MT>, ProverError>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    // a. encode witnesses
    let (codewords, leaves) = {
        let _s = tracing::info_span!("pesat.encode").entered();
        count_ops!(EncodeCalls, witnesses.len() as u64);
        build_codeword_leaves(code, witnesses, l1)
    };

    // b. evaluation claims
    let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

    // c. commit to witnesses
    let td_0 = {
        let _s = tracing::info_span!("pesat.merkle_commit").entered();
        count_ops!(MerkleTreeBuilds);
        MerkleTree::<MT>::new(
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
            leaves.chunks_exact(l1).collect::<Vec<_>>(),
        )?
    };

    // d. absorb commitment and code evaluations; e/f. derive τ challenges.
    let taus = {
        let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
        let root_bytes: [u8; 32] = td_0
            .root()
            .as_ref()
            .try_into()
            .expect("root must be 32 bytes");
        prover_state.prover_message(&root_bytes);
        prover_state.prover_messages(&mus);

        (0..l1)
            .map(|_| prover_state.verifier_messages_vec::<F>(log_m))
            .collect::<Vec<_>>()
    };

    Ok(PesatOutput {
        codewords,
        td_0,
        mus,
        taus,
    })
}

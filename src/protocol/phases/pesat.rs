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
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::build_codeword_leaves;
use crate::error::ProverError;
use crate::protocol::phases::ProverPhase;
use crate::types::PesatOutput;

/// PESAT phase: encode + commit + absorb + squeeze τ.
pub struct Pesat<'a, F, C, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    pub code: &'a C,
    pub mt_leaf_hash_params: &'a <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: &'a <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub witnesses: &'a [Vec<F>],
    pub l1: usize,
    pub log_m: usize,
    pub _phantom: PhantomData<(F, MT)>,
}

impl<'a, F, C, MT> ProverPhase for Pesat<'a, F, C, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type Output = PesatOutput<F, MT>;

    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = self.l1, log_m = self.log_m, n_witnesses = self.witnesses.len())
    )]
    fn prove(self, prover_state: &mut ProverState) -> Result<Self::Output, ProverError> {
        // a. encode witnesses
        let (codewords, leaves) = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, self.witnesses.len() as u64);
            build_codeword_leaves(self.code, self.witnesses, self.l1)
        };

        // b. evaluation claims
        let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

        // c. commit to witnesses
        let td_0 = {
            let _s = tracing::info_span!("pesat.merkle_commit").entered();
            count_ops!(MerkleTreeBuilds);
            MerkleTree::<MT>::new(
                self.mt_leaf_hash_params,
                self.mt_two_to_one_hash_params,
                leaves.chunks_exact(self.l1).collect::<Vec<_>>(),
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

            (0..self.l1)
                .map(|_| prover_state.verifier_messages_vec::<F>(self.log_m))
                .collect::<Vec<_>>()
        };

        Ok(PesatOutput {
            codewords,
            td_0,
            mus,
            taus,
        })
    }
}

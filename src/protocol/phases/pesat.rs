//! PESAT Reduction phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! Implements Phase 2 of the Warp prover: encode fresh witnesses into
//! codewords, commit via an interleaved Merkle tree, absorb commitment and
//! code evaluations, and derive the τ zero-check challenges.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(l1, log_m)`
//! - `Witness`          — `&[Vec<F>]` (fresh witnesses to encode)
//! - `ProverInputs`     — `()`  (PESAT is the source — no upstream oracles)
//! - `VerifierInputs`   — `()`
//! - `ReducedStatement` — `(mus, taus)` — code-eval claims + zero-check randomness
//! - `ProverOutputs`    — full codewords + Merkle tree (\(\Oracle{u}\) bundle)
//! - `VerifierOutputs`  — Merkle root only

use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::build_codeword_leaves;
use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;

pub struct PesatStatement {
    pub l1: usize,
    pub log_m: usize,
}

pub struct PesatWitness<'a, F: Field> {
    pub witnesses: &'a [Vec<F>],
}

pub struct PesatReducedStatement<F: Field> {
    pub mus: Vec<F>,
    pub taus: Vec<Vec<F>>,
}

pub struct PesatProverOutputs<F: Field, MT: Config> {
    pub codewords: Vec<Vec<F>>,
    pub td_0: MerkleTree<MT>,
}

pub struct PesatVerifierOutputs<MT: Config> {
    pub rt_0: MT::InnerDigest,
}

/// PESAT phase configuration. Holds the linear code and merkle hash
/// parameters borrowed from the enclosing `WARP` struct.
pub struct Pesat<'a, F, C, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    pub code: &'a C,
    pub mt_leaf_hash_params: &'a <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: &'a <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub _phantom: PhantomData<(F, MT)>,
}

impl<'a, F, C, MT> IOR for Pesat<'a, F, C, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type Statement = PesatStatement;
    type Witness = PesatWitness<'a, F>;
    type ProverInputs = ();
    type VerifierInputs = ();
    type ReducedStatement = PesatReducedStatement<F>;
    type ProverOutputs = PesatProverOutputs<F, MT>;
    type VerifierOutputs = PesatVerifierOutputs<MT>;

    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = statement.l1, log_m = statement.log_m, n_witnesses = witness.witnesses.len())
    )]
    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        witness: Self::Witness,
        _inputs: Self::ProverInputs,
    ) -> Result<(Self::ReducedStatement, Self::ProverOutputs), ProverError> {
        // a. encode witnesses
        let (codewords, leaves) = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, witness.witnesses.len() as u64);
            build_codeword_leaves(self.code, witness.witnesses, statement.l1)
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
                leaves.chunks_exact(statement.l1).collect::<Vec<_>>(),
            )?
        };

        // d. absorb commitment + claims; e/f. derive τ challenges.
        let taus = {
            let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
            let root_bytes: [u8; 32] = td_0
                .root()
                .as_ref()
                .try_into()
                .expect("root must be 32 bytes");
            prover_state.prover_message(&root_bytes);
            prover_state.prover_messages(&mus);

            (0..statement.l1)
                .map(|_| prover_state.verifier_messages_vec::<F>(statement.log_m))
                .collect::<Vec<_>>()
        };

        Ok((
            PesatReducedStatement {
                mus: mus.clone(),
                taus,
            },
            PesatProverOutputs { codewords, td_0 },
        ))
    }

    #[tracing::instrument(
        name = "pesat.verify",
        skip_all,
        fields(l1 = statement.l1, log_m = statement.log_m)
    )]
    fn verify<'b>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement,
        _inputs: Self::VerifierInputs,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError> {
        // commitment digest
        let rt_0_bytes: [u8; 32] = verifier_state.prover_message()?;
        let rt_0: MT::InnerDigest = rt_0_bytes.into();

        // mus (l1 evaluation claims)
        let mus: Vec<F> = verifier_state.prover_messages_vec(statement.l1)?;

        // taus (l1 zero-check challenge vectors)
        let taus: Vec<Vec<F>> = (0..statement.l1)
            .map(|_| {
                (0..statement.log_m)
                    .map(|_| verifier_state.verifier_message::<F>())
                    .collect()
            })
            .collect();

        Ok((
            PesatReducedStatement { mus, taus },
            PesatVerifierOutputs { rt_0 },
        ))
    }
}

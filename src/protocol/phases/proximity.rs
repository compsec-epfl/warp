//! Proximity / shift-query phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` — index queries on the
//! committed oracles. Generates the authentication paths for each shift
//! query leaf against both the fresh PESAT commitment and each accumulated
//! commitment, and collects the codeword values at those leaves.
//!
//! The query indices themselves are sampled from the transcript **before**
//! this phase — see the orchestrator in `src/lib.rs` — so the batching
//! sumcheck can consume the same indices. Proximity itself does not interact
//! with the transcript: it produces proof artifacts (auth paths + answers),
//! which are then attached to the proof on the prover side and verified
//! against transcript-derived commitments on the verifier side.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(queries, l2, t)`
//! - `Witness`          — `()`
//! - `ProverInputs`     — fresh + accumulated merkle trees + all codewords (full data)
//! - `VerifierInputs`   — fresh + accumulated commitments + auth paths + answers
//! - `ReducedStatement` — `()` (Proximity is a check, not a reduction)
//! - `ProverOutputs`    — auth paths + shift_query_answers (proof artifacts)
//! - `VerifierOutputs`  — `()`

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::compute_auth_paths;
use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityStatement<F: Field> {
    pub queries: QueryIndices<F>,
    pub l2: usize,
    pub t: usize,
}

pub struct ProximityProverInputs<'a, F: Field, MT: Config> {
    pub td_0: &'a MerkleTree<MT>,
    pub acc_td: &'a [MerkleTree<MT>],
    pub all_codewords: &'a [Vec<F>],
}

pub struct ProximityVerifierInputs<'a, F: Field, MT: Config> {
    pub rt_0: &'a MT::InnerDigest,
    pub l2_roots: &'a [MT::InnerDigest],
    pub auth_0: &'a [Path<MT>],
    pub auth_j: &'a [Vec<Path<MT>>],
    pub shift_query_answers: &'a [Vec<F>],
    pub _phantom: PhantomData<F>,
}

pub struct ProximityProverOutputs<F: Field, MT: Config> {
    pub auth_0: Vec<Path<MT>>,
    pub auth_j: Vec<Vec<Path<MT>>>,
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Proximity phase configuration. Holds borrowed merkle hash parameters used
/// by the verifier-side `verify` (the prover side doesn't need them — auth
/// paths are generated from the merkle trees passed in via `ProverInputs`).
pub struct Proximity<'a, F: Field, MT: Config> {
    pub mt_leaf_hash_params: &'a <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: &'a <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, MT> IOR for Proximity<'a, F, MT>
where
    F: Field,
    MT: Config<Leaf = [F]> + 'a,
    MT::InnerDigest: 'a,
{
    type Statement = ProximityStatement<F>;
    type Witness = ();
    type ProverInputs = ProximityProverInputs<'a, F, MT>;
    type VerifierInputs = ProximityVerifierInputs<'a, F, MT>;
    type ReducedStatement = ();
    type ProverOutputs = ProximityProverOutputs<F, MT>;
    type VerifierOutputs = ();

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_td.len(),
            n_codewords = inputs.all_codewords.len(),
        )
    )]
    fn prove(
        &self,
        _prover_state: &mut ProverState,
        statement: &Self::Statement,
        _witness: Self::Witness,
        inputs: Self::ProverInputs,
    ) -> Result<(Self::ReducedStatement, Self::ProverOutputs), ProverError> {
        let leaf_positions = &statement.queries.leaf_positions;

        let auth_0 = {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, leaf_positions.len() as u64);
            compute_auth_paths(inputs.td_0, leaf_positions)?
        };

        let auth_j = {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (inputs.acc_td.len() * leaf_positions.len()) as u64
            );
            inputs
                .acc_td
                .iter()
                .map(|td| compute_auth_paths(td, leaf_positions))
                .collect::<Result<Vec<Vec<Path<MT>>>, _>>()?
        };

        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let mut answers =
                vec![vec![F::default(); inputs.all_codewords.len()]; leaf_positions.len()];
            for (i, idx) in leaf_positions.iter().enumerate() {
                let row = inputs
                    .all_codewords
                    .iter()
                    .map(|f| f[*idx])
                    .collect::<Vec<F>>();
                answers[i] = row;
            }
            answers
        };

        Ok((
            (),
            ProximityProverOutputs {
                auth_0,
                auth_j,
                shift_query_answers,
            },
        ))
    }

    #[tracing::instrument(
        name = "proximity.verify",
        skip_all,
        fields(t = statement.t, l2 = statement.l2)
    )]
    fn verify<'b>(
        &self,
        _verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement,
        inputs: Self::VerifierInputs,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError> {
        let leaf_positions = &statement.queries.leaf_positions;

        (inputs.shift_query_answers.len() == statement.t)
            .ok_or_err(VerifierError::NumShiftQueries)?;

        for (i, path) in inputs.auth_0.iter().enumerate() {
            (path.leaf_index == leaf_positions[i]).ok_or_err(VerifierError::ShiftQueryIndex)?;
            count_ops!(MerklePathsVerified);
            let is_valid = path.verify(
                self.mt_leaf_hash_params,
                self.mt_two_to_one_hash_params,
                inputs.rt_0,
                &inputs.shift_query_answers[i][statement.l2..],
            )?;
            is_valid.ok_or_err(VerifierError::ShiftQuery)?;
        }

        (inputs.auth_j.len() == statement.l2).ok_or_err(VerifierError::NumL2Instances)?;
        for (i, paths) in inputs.auth_j.iter().enumerate() {
            (paths.len() == statement.t).ok_or_err(VerifierError::NumShiftQueries)?;
            let root = &inputs.l2_roots[i];
            for (j, path) in paths.iter().enumerate() {
                (path.leaf_index == leaf_positions[j]).ok_or_err(VerifierError::ShiftQueryIndex)?;
                count_ops!(MerklePathsVerified);
                let is_valid = path.verify(
                    self.mt_leaf_hash_params,
                    self.mt_two_to_one_hash_params,
                    root,
                    [inputs.shift_query_answers[j][i]],
                )?;
                is_valid.ok_or_err(VerifierError::ShiftQuery)?;
            }
        }

        Ok(((), ()))
    }
}

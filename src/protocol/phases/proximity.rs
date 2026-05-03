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

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;
use spongefish::{ProverState, VerifierState};

use crate::count_ops;
use crate::crypto::merkle::compute_auth_paths;
use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::{ProverPhase, VerifierPhase};
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityOutput<F: Field, MT: Config> {
    pub auth_0: Vec<Path<MT>>,
    pub auth_j: Vec<Vec<Path<MT>>>,
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Proximity prover: open the queries against the fresh and accumulated
/// commitments, collect codeword values at each queried leaf.
///
/// `all_codewords` must list the **accumulated** codewords first, then the
/// **fresh** PESAT codewords, matching the verifier's expectation at
/// `lib.rs::verify` (the `[l2..]` slice is the fresh chunk).
pub struct Proximity<'a, F: Field, MT: Config> {
    pub queries: &'a QueryIndices<F>,
    pub td_0: &'a MerkleTree<MT>,
    pub acc_td: &'a [MerkleTree<MT>],
    pub all_codewords: &'a [Vec<F>],
}

impl<'a, F, MT> ProverPhase for Proximity<'a, F, MT>
where
    F: Field,
    MT: Config<Leaf = [F]>,
{
    type Output = ProximityOutput<F, MT>;

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = self.queries.leaf_positions.len(),
            n_accumulators = self.acc_td.len(),
            n_codewords = self.all_codewords.len(),
        )
    )]
    fn prove(self, _prover_state: &mut ProverState) -> Result<Self::Output, ProverError> {
        let auth_0 = {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, self.queries.leaf_positions.len() as u64);
            compute_auth_paths(self.td_0, &self.queries.leaf_positions)?
        };

        let auth_j = {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (self.acc_td.len() * self.queries.leaf_positions.len()) as u64
            );
            self.acc_td
                .iter()
                .map(|td| compute_auth_paths(td, &self.queries.leaf_positions))
                .collect::<Result<Vec<Vec<Path<MT>>>, _>>()?
        };

        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let mut answers = vec![
                vec![F::default(); self.all_codewords.len()];
                self.queries.leaf_positions.len()
            ];
            for (i, idx) in self.queries.leaf_positions.iter().enumerate() {
                let row = self
                    .all_codewords
                    .iter()
                    .map(|f| f[*idx])
                    .collect::<Vec<F>>();
                answers[i] = row;
            }
            answers
        };

        Ok(ProximityOutput {
            auth_0,
            auth_j,
            shift_query_answers,
        })
    }
}

/// Proximity verifier: validate the auth paths against the rt_0 / l2_roots
/// commitments and check that the leaf claims line up.
///
/// - `auth_0` opens the fresh PESAT tree at each query; expected leaves are
///   the `l2..` slice of each `shift_query_answers` row (the fresh chunk).
/// - `auth_j` opens each of `l2` accumulated trees at each query; expected
///   leaf for accumulator `i` at query `j` is `shift_query_answers[j][i]`.
pub struct ProximityVerify<'a, F: Field, MT: Config> {
    pub queries: &'a QueryIndices<F>,
    pub rt_0: &'a MT::InnerDigest,
    pub l2_roots: &'a [MT::InnerDigest],
    pub auth_0: &'a [Path<MT>],
    pub auth_j: &'a [Vec<Path<MT>>],
    pub shift_query_answers: &'a [Vec<F>],
    pub mt_leaf_hash_params: &'a <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: &'a <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    pub l2: usize,
    pub t: usize,
}

impl<'a, F, MT> VerifierPhase for ProximityVerify<'a, F, MT>
where
    F: Field,
    MT: Config<Leaf = [F]>,
{
    type Output = ();

    #[tracing::instrument(
        name = "proximity.verify",
        skip_all,
        fields(t = self.t, l2 = self.l2)
    )]
    fn verify<'b>(
        self,
        _verifier_state: &mut VerifierState<'b>,
    ) -> Result<Self::Output, VerifierError> {
        (self.shift_query_answers.len() == self.t).ok_or_err(VerifierError::NumShiftQueries)?;

        for (i, path) in self.auth_0.iter().enumerate() {
            (path.leaf_index == self.queries.leaf_positions[i])
                .ok_or_err(VerifierError::ShiftQueryIndex)?;

            count_ops!(MerklePathsVerified);
            let is_valid = path.verify(
                self.mt_leaf_hash_params,
                self.mt_two_to_one_hash_params,
                self.rt_0,
                &self.shift_query_answers[i][self.l2..], // leaves are evaluations of the l1 codewords
            )?;
            is_valid.ok_or_err(VerifierError::ShiftQuery)?;
        }

        (self.auth_j.len() == self.l2).ok_or_err(VerifierError::NumL2Instances)?;
        for (i, paths) in self.auth_j.iter().enumerate() {
            (paths.len() == self.t).ok_or_err(VerifierError::NumShiftQueries)?;
            let root = &self.l2_roots[i];
            for (j, path) in paths.iter().enumerate() {
                (path.leaf_index == self.queries.leaf_positions[j])
                    .ok_or_err(VerifierError::ShiftQueryIndex)?;
                count_ops!(MerklePathsVerified);
                let is_valid = path.verify(
                    self.mt_leaf_hash_params,
                    self.mt_two_to_one_hash_params,
                    root,
                    [self.shift_query_answers[j][i]],
                )?;
                is_valid.ok_or_err(VerifierError::ShiftQuery)?;
            }
        }

        Ok(())
    }
}

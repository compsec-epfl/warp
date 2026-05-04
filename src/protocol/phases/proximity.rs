//! Proximity / shift-query phase.
//!
//! Index queries on the committed oracles. Opens both the fresh PESAT
//! commitment and each accumulated commitment at the query positions,
//! producing one multi-opening proof per commitment and a flat table of
//! the codeword values at those positions.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(queries, l2, t, n)`. `n` is the codeword length;
//!   the verifier needs it to construct the `WarpScheme` used for `check`.
//! - `Witness`          — `()`
//! - `ProverInputs`     — fresh `WarpCommitted` + l2 accumulated `WarpCommitted`s
//! - `VerifierInputs`   — fresh root + l2 acc roots + opening proofs + answers
//! - `ReducedStatement` — `()` (Proximity is a check, not a reduction)
//! - `ProverOutputs`    — opening proofs + shift_query_answers (proof artifacts)
//! - `VerifierOutputs`  — `()`

use ark_ff::Field;
use ark_mt::{multi_vector::MultiVectorOpening, MerkleHasher};
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted, WarpProof};
use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityStatement<F: Field> {
    pub queries: QueryIndices<F>,
    pub l2: usize,
    pub t: usize,
    /// Codeword length (`code.code_len()`), needed by both prover and
    /// verifier to construct the `WarpScheme` used for open/check.
    pub n: usize,
}

pub struct ProximityProverInputs<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub td_0: &'a WarpCommitted<H, F>,
    pub acc_td: &'a [WarpCommitted<H, F>],
}

pub struct ProximityVerifierInputs<'a, F: Field, H: MerkleHasher> {
    pub rt_0: &'a H::Digest,
    pub l2_roots: &'a [H::Digest],
    pub auth_0: &'a WarpProof<H>,
    pub auth_j: &'a [WarpProof<H>],
    pub shift_query_answers: &'a [Vec<F>],
}

pub struct ProximityProverOutputs<F, H>
where
    F: Field,
    H: MerkleHasher,
{
    /// Single multi-opening proof for the fresh PESAT commitment.
    pub auth_0: WarpProof<H>,
    /// One multi-opening proof per accumulated commitment.
    pub auth_j: Vec<WarpProof<H>>,
    /// Shift query answers: per-query × per-codeword.
    /// Outer length = t (queries). Inner length = (l2 acc + l1 fresh).
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Proximity phase configuration. Holds the hasher value used by both
/// `open` (prover side) and `check` (verifier side).
pub struct Proximity<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub hasher: &'a H,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, H> IOR for Proximity<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    type Statement = ProximityStatement<F>;
    type Witness = ();
    type ProverInputs = ProximityProverInputs<'a, F, H>;
    type VerifierInputs = ProximityVerifierInputs<'a, F, H>;
    type ReducedStatement = ();
    type ProverOutputs = ProximityProverOutputs<F, H>;
    type VerifierOutputs = ();

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_td.len(),
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

        // ark-mt's `open()` requires strictly-sorted, unique indices. Query
        // positions can repeat or arrive unsorted; deduplicate for the
        // merkle opening, but keep `shift_query_answers` in original query
        // order so downstream phases (batching) can index by query.
        let mut sorted_unique = leaf_positions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();

        let scheme = warp_scheme(self.hasher.clone(), statement.n);

        let auth_0 = {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, sorted_unique.len() as u64);
            scheme.open(inputs.td_0, &sorted_unique)
        };

        let auth_j: Vec<WarpProof<H>> = {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (inputs.acc_td.len() * sorted_unique.len()) as u64
            );
            inputs
                .acc_td
                .iter()
                .map(|td| scheme.open(td, &sorted_unique))
                .collect()
        };

        // Shift query answers: per query position, values across
        // (acc_codewords ++ fresh_codewords).
        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let total_codewords = inputs
                .acc_td
                .iter()
                .map(|td| td.num_codewords())
                .sum::<usize>()
                + inputs.td_0.num_codewords();
            let mut answers = vec![vec![F::default(); total_codewords]; leaf_positions.len()];
            for (qi, idx) in leaf_positions.iter().enumerate() {
                let mut col = 0usize;
                for td in inputs.acc_td.iter() {
                    for cw in td.codewords() {
                        answers[qi][col] = cw[*idx];
                        col += 1;
                    }
                }
                for cw in inputs.td_0.codewords() {
                    answers[qi][col] = cw[*idx];
                    col += 1;
                }
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
        (inputs.auth_j.len() == statement.l2).ok_or_err(VerifierError::NumL2Instances)?;

        // Build the (sorted, unique) positions used by the merkle openings
        // and remember which row of `shift_query_answers` corresponds to
        // each unique position. Duplicate queries land on the same row.
        let mut indexed: Vec<(usize, usize)> = leaf_positions
            .iter()
            .copied()
            .enumerate()
            .map(|(row, pos)| (pos, row))
            .collect();
        indexed.sort_by_key(|&(pos, _)| pos);
        indexed.dedup_by_key(|&mut (pos, _)| pos);
        let sorted_unique: Vec<usize> = indexed.iter().map(|&(p, _)| p).collect();
        let row_indices: Vec<usize> = indexed.iter().map(|&(_, r)| r).collect();

        let scheme = warp_scheme::<H, F>(self.hasher.clone(), statement.n);

        // Fresh PESAT opening: per unique position, take the l1-suffix of the
        // corresponding answers row.
        let fresh_values: Vec<Vec<F>> = row_indices
            .iter()
            .map(|&r| inputs.shift_query_answers[r][statement.l2..].to_vec())
            .collect();
        let fresh_opening = MultiVectorOpening::new(sorted_unique.clone(), fresh_values)
            .map_err(|_| VerifierError::ShiftQueryIndex)?;
        scheme
            .check(inputs.rt_0, &fresh_opening, inputs.auth_0)
            .ok_or_err(VerifierError::ShiftQuery)?;
        count_ops!(MerklePathsVerified, sorted_unique.len() as u64);

        // Accumulator openings: each is m=1 (single codeword).
        for (k, root) in inputs.l2_roots.iter().enumerate() {
            let acc_values: Vec<Vec<F>> = row_indices
                .iter()
                .map(|&r| vec![inputs.shift_query_answers[r][k]])
                .collect();
            let acc_opening = MultiVectorOpening::new(sorted_unique.clone(), acc_values)
                .map_err(|_| VerifierError::ShiftQueryIndex)?;
            scheme
                .check(root, &acc_opening, &inputs.auth_j[k])
                .ok_or_err(VerifierError::ShiftQuery)?;
            count_ops!(MerklePathsVerified, sorted_unique.len() as u64);
        }

        Ok(((), ()))
    }
}

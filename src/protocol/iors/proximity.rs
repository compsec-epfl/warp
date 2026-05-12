//! Proximity / shift-query IOR.
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
//! - `ReductionInputs`  — `()` (no reduction)
//! - `ReducedStatement` — `()` (Proximity is a check, not a reduction)
//! - `ProofString`      — opening proofs + shift_query_answers
//! - `ReducedWitness`   — `()`
//! - `VerifierOutputs`  — `()`

use ark_ff::Field;
use ark_mt::MerkleHasher;
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted, WarpProof};
use crate::error::VerifierError;
use crate::protocol::oracles::indexed_merkle::IndexedOracle;
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::oracles::query_indices::QueryIndices;

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

/// Verifier-side inputs. The IOR sees [`IndexedOracle`] handles, not
/// raw roots / opening proofs — IORs stay BCS-agnostic.
pub struct ProximityVerifierInputs<'a, F, O>
where
    F: Field,
    O: IndexedOracle<Vec<F>>,
{
    /// Handle for the fresh PESAT multi-vector commitment (m = l1).
    pub fresh: &'a O,
    /// One handle per accumulated commitment (each with m = 1).
    pub acc: &'a [O],
    pub _f: PhantomData<F>,
}

pub struct ProximityProofString<F, H>
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

/// Proximity IOR configuration. Holds the hasher value used by both
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
    const NAME: &'static str = "Proximity";

    type Statement<'b>
        = ProximityStatement<F>
    where
        Self: 'b;
    type Witness<'b>
        = ()
    where
        Self: 'b;
    type ProverInputs<'b>
        = ProximityProverInputs<'b, F, H>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ProximityVerifierInputs<
            'b,
            F,
            crate::protocol::oracles::indexed_merkle::MerkleIndexedOracle<'b, F, H>,
        >
    where
        Self: 'b;
    type ReductionInputs = ();
    type ReducedStatement = ();
    type ProofString = ProximityProofString<F, H>;
    type ReducedWitness = ();
    type VerifierOutputs = ();

    fn reduce_statement<'b>(
        &self,
        _statement: &Self::Statement<'b>,
        _inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
    }

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_td.len(),
        )
    )]
    fn prove_inner<'b>(
        &self,
        _prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        _witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'b,
        'a: 'b,
        H: 'b,
    {
        let leaf_positions = &statement.queries.leaf_positions;

        // ark-mt's `open()` requires strictly-sorted, unique indices. Query
        // positions can repeat or arrive unsorted; deduplicate for the
        // merkle opening, but keep `shift_query_answers` in original query
        // order so Batching can index by query.
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
            ProximityProofString {
                auth_0,
                auth_j,
                shift_query_answers,
            },
            (),
        ))
    }

    #[tracing::instrument(
        name = "proximity.verify",
        skip_all,
        fields(t = statement.t, l2 = statement.l2)
    )]
    fn verify_inner<'b, 'c>(
        &self,
        _verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
        'a: 'c,
        H: 'c,
    {
        // Arity check: number of accumulator openings must match l2.
        (inputs.acc.len() == statement.l2).then_some(()).ok_or(VerifierError::NumL2Instances)?;

        // Validate each oracle handle. The handle is a partial function:
        // validate() runs the (lazy, memoized) BCS check internally —
        // this IOR stays BCS-agnostic.
        inputs
            .fresh
            .validate()
            .then_some(()).ok_or(VerifierError::ShiftQuery)?;
        count_ops!(
            MerklePathsVerified,
            statement.queries.leaf_positions.len() as u64
        );
        for handle in inputs.acc.iter() {
            handle.validate().then_some(()).ok_or(VerifierError::ShiftQuery)?;
            count_ops!(
                MerklePathsVerified,
                statement.queries.leaf_positions.len() as u64
            );
        }

        Ok(((), ()))
    }
}

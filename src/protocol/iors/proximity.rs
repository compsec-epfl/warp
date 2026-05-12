//! Proximity / shift-query IOR.
//!
//! Index queries on the committed oracles. Opens both the fresh PESAT
//! commitment and each accumulated commitment at the query positions,
//! producing one multi-opening proof per commitment and a flat table of
//! the codeword values at those positions.
//!
//! IOR ports
//! ---------
//! - input (prover): `{ queries, td_0, acc_td, l2, t, n }`
//! - input (verifier): `{ queries, rt_0, l2_roots, auth_0, auth_j,
//!   shift_query_answers, l2, t, n }`
//! - `proof` (prover): `ProximityProof { auth_0, auth_j,
//!   shift_query_answers }` — collected into the global `WARPProof`
//!
//! Proximity is a check, not a reduction: there is no `reduced` or
//! `carry` port. The verifier-side input carries the raw BCS materials
//! (root digests, multi-opening proofs, answer tables); `verify`
//! internally builds the `MerkleIndexedOracle` handles and triggers
//! their (lazy, memoized) BCS validation.

use ark_ff::Field;
use ark_mt::MerkleHasher;
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted, WarpProof};
use crate::error::{ProverError, VerifierError};
use crate::protocol::iors::oracle_handle::{IndexedOracle, MerkleIndexedOracle};
use crate::protocol::iors::IOR;
use crate::protocol::query::QueryIndices;

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct ProximityProverInput<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub queries: &'a QueryIndices<F>,
    pub td_0: &'a WarpCommitted<H, F>,
    pub acc_td: &'a [WarpCommitted<H, F>],
    pub l2: usize,
    pub t: usize,
    /// Codeword length (`code.code_len()`), needed to construct the
    /// `WarpScheme` used for `open`.
    pub n: usize,
}

pub struct ProximityVerifierInput<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub queries: &'a QueryIndices<F>,
    pub rt_0: &'a H::Digest,
    pub l2_roots: &'a [H::Digest],
    pub auth_0: &'a WarpProof<H>,
    pub auth_j: &'a [WarpProof<H>],
    /// Shift query answers: outer length = t (queries),
    /// inner length = l2 + l1 (acc codewords ++ fresh codewords).
    pub shift_query_answers: &'a [Vec<F>],
    pub l2: usize,
    pub t: usize,
    /// Codeword length (`code.code_len()`), needed to construct the
    /// `WarpScheme` used for `check`.
    pub n: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// External proof material — collected into the global `WARPProof` by
/// the orchestrator.
pub struct ProximityProof<F, H>
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

pub struct ProximityProverOutput<F, H>
where
    F: Field,
    H: MerkleHasher,
{
    pub reduced: (),
    pub carry: (),
    pub proof: ProximityProof<F, H>,
}

pub struct ProximityVerifierOutput {
    pub reduced: (),
    pub carry: (),
}

// ─── IOR ──────────────────────────────────────────────────────────────────

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
    const NAME: &'static str = "Proximity";

    type ProverInput<'b>
        = ProximityProverInput<'b, F, H>
    where
        Self: 'b;
    type ProverOutput = ProximityProverOutput<F, H>;
    type VerifierInput<'b>
        = ProximityVerifierInput<'b, F, H>
    where
        Self: 'b;
    type VerifierOutput = ProximityVerifierOutput;

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = input.queries.leaf_positions.len(),
            n_accumulators = input.acc_td.len(),
        )
    )]
    fn prove<'b>(
        &self,
        _transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        let leaf_positions = &input.queries.leaf_positions;

        // ark-mt's `open()` requires strictly-sorted, unique indices. Query
        // positions can repeat or arrive unsorted; deduplicate for the
        // merkle opening, but keep `shift_query_answers` in original query
        // order so downstream phases (batching) can index by query.
        let mut sorted_unique = leaf_positions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();

        let scheme = warp_scheme(self.hasher.clone(), input.n);

        let auth_0 = {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, sorted_unique.len() as u64);
            scheme.open(input.td_0, &sorted_unique)
        };

        let auth_j: Vec<WarpProof<H>> = {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (input.acc_td.len() * sorted_unique.len()) as u64
            );
            input
                .acc_td
                .iter()
                .map(|td| scheme.open(td, &sorted_unique))
                .collect()
        };

        // Shift query answers: per query position, values across
        // (acc_codewords ++ fresh_codewords).
        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let total_codewords = input
                .acc_td
                .iter()
                .map(|td| td.num_codewords())
                .sum::<usize>()
                + input.td_0.num_codewords();
            let mut answers = vec![vec![F::default(); total_codewords]; leaf_positions.len()];
            for (qi, idx) in leaf_positions.iter().enumerate() {
                let mut col = 0usize;
                for td in input.acc_td.iter() {
                    for cw in td.codewords() {
                        answers[qi][col] = cw[*idx];
                        col += 1;
                    }
                }
                for cw in input.td_0.codewords() {
                    answers[qi][col] = cw[*idx];
                    col += 1;
                }
            }
            answers
        };

        Ok(ProximityProverOutput {
            reduced: (),
            carry: (),
            proof: ProximityProof {
                auth_0,
                auth_j,
                shift_query_answers,
            },
        })
    }

    #[tracing::instrument(
        name = "proximity.verify",
        skip_all,
        fields(t = input.t, l2 = input.l2)
    )]
    fn verify<'b, 'v>(
        &self,
        _transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        // ── Whole-proof arity checks (orchestrator used to own these) ──
        (input.shift_query_answers.len() == input.t)
            .then_some(())
            .ok_or(VerifierError::NumShiftQueries)?;
        (input.auth_j.len() == input.l2)
            .then_some(())
            .ok_or(VerifierError::NumL2Instances)?;
        (input.l2_roots.len() == input.l2)
            .then_some(())
            .ok_or(VerifierError::NumL2Instances)?;

        // ── Build IndexedOracle handles from raw BCS materials ────────
        //
        // ark-mt's `check()` requires sorted, unique indices paired with
        // the values at those indices. Query positions can repeat or
        // arrive unsorted; we dedupe + sort here, then look up the
        // corresponding row in `shift_query_answers` (which stays in
        // original query order so downstream phases index by query).
        let leaf_positions = &input.queries.leaf_positions;
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

        // Fresh handle: pull columns [l2..] (the l1 fresh codewords)
        // from each authenticated row.
        let fresh_values: Vec<Vec<F>> = row_indices
            .iter()
            .map(|&r| input.shift_query_answers[r][input.l2..].to_vec())
            .collect();
        let fresh_handle = MerkleIndexedOracle::new(
            warp_scheme::<H, F>(self.hasher.clone(), input.n),
            input.rt_0,
            input.auth_0,
            sorted_unique.clone(),
            fresh_values,
        );

        // Acc handles: one per accumulated commitment, single-codeword.
        let acc_handles: Vec<MerkleIndexedOracle<F, H>> = (0..input.l2)
            .map(|j| {
                let acc_values: Vec<Vec<F>> = row_indices
                    .iter()
                    .map(|&r| vec![input.shift_query_answers[r][j]])
                    .collect();
                MerkleIndexedOracle::new(
                    warp_scheme::<H, F>(self.hasher.clone(), input.n),
                    &input.l2_roots[j],
                    &input.auth_j[j],
                    sorted_unique.clone(),
                    acc_values,
                )
            })
            .collect();

        // ── Validate each handle (runs the BCS check internally) ──────
        fresh_handle
            .validate()
            .then_some(())
            .ok_or(VerifierError::ShiftQuery)?;
        count_ops!(MerklePathsVerified, leaf_positions.len() as u64);
        for handle in acc_handles.iter() {
            handle
                .validate()
                .then_some(())
                .ok_or(VerifierError::ShiftQuery)?;
            count_ops!(MerklePathsVerified, leaf_positions.len() as u64);
        }

        Ok(ProximityVerifierOutput {
            reduced: (),
            carry: (),
        })
    }
}

//! Proximity / shift-query phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` — index queries on the
//! committed oracles.
//!
//! Post ark-vc migration: `auth_0` / `auth_j` are *single* pruned
//! [`Proof`]s (one per tree), not per-query path vectors. ark-vc
//! calls `DeriveVertexSet(indices)` on each open, so all `t` queries
//! share a minimal authenticating-digest set.
//!
//! Query-index canonicalisation: warp samples `t` shift queries
//! uniformly via `QueryIndices::sample`, which can collide at small
//! `log_n`. ark-vc's `Opening::new` requires strictly sorted unique
//! indices, so the prover and verifier agree on the sorted-unique
//! subset here — the per-query `shift_query_answers` vector keeps its
//! original `t` entries regardless (used downstream by `nu_s+t`
//! computation), but the auth proof covers only the unique positions.

use ark_ff::PrimeField;
use ark_vc::shape::PerfectBinary;
use ark_vc::{Committed, MerkleCommitment, Opening, OpeningProof};

use crate::count_ops;
use crate::error::VerifierError;
use crate::hasher::WarpHasher;
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityOutput<F: PrimeField, H: WarpHasher<F>> {
    pub auth_0: OpeningProof<H>,
    pub auth_j: Vec<OpeningProof<H>>,
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Sorted-unique query positions plus an index into the original query
/// order so callers can pick up a value (e.g. leaf row) for each unique
/// position.
fn canonicalise(positions: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let mut pairs: Vec<(usize, usize)> = positions
        .iter()
        .copied()
        .enumerate()
        .map(|(i, x)| (x, i))
        .collect();
    pairs.sort_by_key(|&(x, _)| x);
    pairs.dedup_by_key(|p| p.0);
    let indices = pairs.iter().map(|&(x, _)| x).collect::<Vec<_>>();
    let first_occurrence = pairs.iter().map(|&(_, i)| i).collect::<Vec<_>>();
    (indices, first_occurrence)
}

/// Open the proximity queries and collect codeword values at every
/// queried leaf.
///
/// `all_codewords` must list the accumulated codewords first, then the
/// fresh PESAT codewords (matching the verifier's `[l2..]` slice).
#[tracing::instrument(
    name = "proximity",
    skip_all,
    fields(
        n_queries = queries.leaf_positions.len(),
        n_accumulators = acc_td.len(),
        n_codewords = all_codewords.len(),
    )
)]
pub fn prove<F, H>(
    scheme: &MerkleCommitment<H, PerfectBinary>,
    queries: &QueryIndices<F>,
    td_0: &Committed<H, PerfectBinary>,
    acc_td: &[Committed<H, PerfectBinary>],
    all_codewords: &[Vec<F>],
) -> ProximityOutput<F, H>
where
    F: PrimeField,
    H: WarpHasher<F>,
{
    let (unique_indices, _first_occurrence) = canonicalise(&queries.leaf_positions);

    let auth_0 = {
        let _s = tracing::info_span!("proximity.auth_0").entered();
        count_ops!(MerklePathsGenerated, unique_indices.len() as u64);
        scheme.open(td_0, &unique_indices)
    };

    let auth_j = {
        let _s = tracing::info_span!("proximity.auth_j").entered();
        count_ops!(
            MerklePathsGenerated,
            (acc_td.len() * unique_indices.len()) as u64
        );
        acc_td
            .iter()
            .map(|td| scheme.open(td, &unique_indices))
            .collect::<Vec<_>>()
    };

    let shift_query_answers = {
        let _s = tracing::info_span!("proximity.shift_queries").entered();
        let mut answers =
            vec![vec![F::default(); all_codewords.len()]; queries.leaf_positions.len()];
        for (i, idx) in queries.leaf_positions.iter().enumerate() {
            let row = all_codewords.iter().map(|f| f[*idx]).collect::<Vec<F>>();
            answers[i] = row;
        }
        answers
    };

    ProximityOutput {
        auth_0,
        auth_j,
        shift_query_answers,
    }
}

/// Verify the proximity openings against the fresh and accumulated
/// commitments.
///
/// `l1` is the number of fresh PESAT codewords committed in `rt_0`;
/// together with `l2` (accumulator count) it determines the expected
/// length of every `shift_query_answers` row (the concatenation of
/// accumulator + fresh values at that query leaf). We validate the
/// row shape up front so later indexing (`row[l2..]`, `row[j]`)
/// cannot panic on malformed input.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "proximity.verify",
    skip_all,
    fields(t = t, l1 = l1, l2 = l2)
)]
pub fn verify<F, H>(
    scheme: &MerkleCommitment<H, PerfectBinary>,
    queries: &QueryIndices<F>,
    rt_0: &H::Digest,
    l2_roots: &[H::Digest],
    auth_0: &OpeningProof<H>,
    auth_j: &[OpeningProof<H>],
    shift_query_answers: &[Vec<F>],
    l1: usize,
    l2: usize,
    t: usize,
) -> Result<(), VerifierError>
where
    F: PrimeField,
    H: WarpHasher<F>,
{
    (shift_query_answers.len() == t).ok_or_err(VerifierError::NumShiftQueries)?;
    // Row-shape guard: every row must be exactly `l2 + l1` long so the
    // later `row[l2..]` slice (fresh chunk) and `row[j]` index
    // (accumulator `j`) are both in bounds. An adversarial proof with
    // short rows would otherwise panic here instead of returning a
    // clean VerifierError.
    let expected_row_len = l2 + l1;
    shift_query_answers
        .iter()
        .all(|row| row.len() == expected_row_len)
        .ok_or_err(VerifierError::MalformedShiftQueryAnswers)?;

    let (unique_indices, first_occurrence) = canonicalise(&queries.leaf_positions);

    // Fresh-oracle opening: each leaf is a length-l1 Vec<F> taken from
    // shift_query_answers[i][l2..] at the first occurrence of each
    // unique index.
    let fresh_values: Vec<Vec<F>> = first_occurrence
        .iter()
        .map(|&first_i| shift_query_answers[first_i][l2..].to_vec())
        .collect();
    let fresh_opening = Opening::<H>::new(unique_indices.clone(), fresh_values)
        .map_err(|_| VerifierError::ShiftQueryIndex)?;

    count_ops!(MerklePathsVerified, unique_indices.len() as u64);
    scheme
        .check(rt_0, &fresh_opening, auth_0)
        .ok_or_err(VerifierError::ShiftQuery)?;

    // One opening per accumulated oracle: leaf is vec![shift_query_answers[first_i][j]].
    (auth_j.len() == l2).ok_or_err(VerifierError::NumL2Instances)?;
    for (j, (proof, root)) in auth_j.iter().zip(l2_roots).enumerate() {
        let values: Vec<Vec<F>> = first_occurrence
            .iter()
            .map(|&first_i| vec![shift_query_answers[first_i][j]])
            .collect();
        let opening = Opening::<H>::new(unique_indices.clone(), values)
            .map_err(|_| VerifierError::ShiftQueryIndex)?;

        count_ops!(MerklePathsVerified, unique_indices.len() as u64);
        scheme
            .check(root, &opening, proof)
            .ok_or_err(VerifierError::ShiftQuery)?;
    }

    Ok(())
}

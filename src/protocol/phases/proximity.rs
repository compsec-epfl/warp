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
use ark_vc::Opening;

use crate::count_ops;
use ark_vc::blake3::binary::{Committed, Hasher, Proof, Scheme};
use crate::error::VerifierError;
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityOutput<F: PrimeField> {
    pub auth_0: Proof<F>,
    pub auth_j: Vec<Proof<F>>,
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
pub fn prove<F>(
    scheme: &Scheme<F>,
    queries: &QueryIndices<F>,
    td_0: &Committed<F>,
    acc_td: &[Committed<F>],
    all_codewords: &[Vec<F>],
) -> ProximityOutput<F>
where
    F: PrimeField,
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
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "proximity.verify",
    skip_all,
    fields(t = t, l2 = l2)
)]
pub fn verify<F>(
    scheme: &Scheme<F>,
    queries: &QueryIndices<F>,
    rt_0: &[u8; 32],
    l2_roots: &[[u8; 32]],
    auth_0: &Proof<F>,
    auth_j: &[Proof<F>],
    shift_query_answers: &[Vec<F>],
    l2: usize,
    t: usize,
) -> Result<(), VerifierError>
where
    F: PrimeField,
{
    (shift_query_answers.len() == t).ok_or_err(VerifierError::NumShiftQueries)?;

    let (unique_indices, first_occurrence) = canonicalise(&queries.leaf_positions);

    // Fresh-oracle opening: each leaf is a length-l1 Vec<F> taken from
    // shift_query_answers[i][l2..] at the first occurrence of each
    // unique index.
    let fresh_values: Vec<Vec<F>> = first_occurrence
        .iter()
        .map(|&first_i| shift_query_answers[first_i][l2..].to_vec())
        .collect();
    let fresh_opening = Opening::<Hasher<F>>::new(unique_indices.clone(), fresh_values)
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
        let opening = Opening::<Hasher<F>>::new(unique_indices.clone(), values)
            .map_err(|_| VerifierError::ShiftQueryIndex)?;

        count_ops!(MerklePathsVerified, unique_indices.len() as u64);
        scheme
            .check(root, &opening, proof)
            .ok_or_err(VerifierError::ShiftQuery)?;
    }

    Ok(())
}

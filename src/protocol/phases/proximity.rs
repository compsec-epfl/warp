//! Proximity / shift-query phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` — index queries on the
//! committed oracles. Generates the authentication paths for each shift
//! query leaf against both the fresh PESAT commitment and each accumulated
//! commitment, and collects the codeword values at those leaves.
//!
//! The query indices themselves are sampled from the transcript **before**
//! this phase — see the orchestrator in `src/lib.rs` — so the batching
//! sumcheck can consume the same indices.

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
    Error,
};
use ark_ff::Field;

use crate::count_ops;
use crate::crypto::merkle::compute_auth_paths;
use crate::error::VerifierError;
use crate::protocol::query::QueryIndices;
use crate::BoolResult;

pub struct ProximityOutput<F: Field, MT: Config> {
    pub auth_0: Vec<Path<MT>>,
    pub auth_j: Vec<Vec<Path<MT>>>,
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Open the proximity queries: generate auth paths for the fresh commitment
/// and each accumulated commitment, and collect the codeword values at every
/// queried leaf.
///
/// `all_codewords` must list the **accumulated** codewords first, then the
/// **fresh** PESAT codewords, matching the verifier's expectation at
/// `lib.rs::verify` (the `[l2..]` slice is the fresh chunk).
#[tracing::instrument(
    name = "proximity",
    skip_all,
    fields(
        n_queries = queries.leaf_positions.len(),
        n_accumulators = acc_td.len(),
        n_codewords = all_codewords.len(),
    )
)]
pub fn prove<F, MT>(
    queries: &QueryIndices<F>,
    td_0: &MerkleTree<MT>,
    acc_td: &[MerkleTree<MT>],
    all_codewords: &[Vec<F>],
) -> Result<ProximityOutput<F, MT>, Error>
where
    F: Field,
    MT: Config<Leaf = [F]>,
{
    let auth_0 = {
        let _s = tracing::info_span!("proximity.auth_0").entered();
        count_ops!(MerklePathsGenerated, queries.leaf_positions.len() as u64);
        compute_auth_paths(td_0, &queries.leaf_positions)?
    };

    let auth_j = {
        let _s = tracing::info_span!("proximity.auth_j").entered();
        count_ops!(
            MerklePathsGenerated,
            (acc_td.len() * queries.leaf_positions.len()) as u64
        );
        acc_td
            .iter()
            .map(|td| compute_auth_paths(td, &queries.leaf_positions))
            .collect::<Result<Vec<Vec<Path<MT>>>, Error>>()?
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

    Ok(ProximityOutput {
        auth_0,
        auth_j,
        shift_query_answers,
    })
}

/// Verify the proximity (shift-query) openings.
///
/// - `auth_0` opens the fresh PESAT tree at each query; expected leaves are
///   the `l2..` slice of each `shift_query_answers` row (the fresh chunk).
/// - `auth_j` opens each of `l2` accumulated trees at each query; expected
///   leaf for accumulator `i` at query `j` is `shift_query_answers[j][i]`.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "proximity.verify",
    skip_all,
    fields(t = t, l2 = l2)
)]
pub fn verify<F, MT>(
    queries: &QueryIndices<F>,
    rt_0: &MT::InnerDigest,
    l2_roots: &[MT::InnerDigest],
    auth_0: &[Path<MT>],
    auth_j: &[Vec<Path<MT>>],
    shift_query_answers: &[Vec<F>],
    mt_leaf_hash_params: &<MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: &<MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    l2: usize,
    t: usize,
) -> Result<(), VerifierError>
where
    F: Field,
    MT: Config<Leaf = [F]>,
{
    (shift_query_answers.len() == t).ok_or_err(VerifierError::NumShiftQueries)?;

    for (i, path) in auth_0.iter().enumerate() {
        (path.leaf_index == queries.leaf_positions[i])
            .ok_or_err(VerifierError::ShiftQueryIndex)?;

        count_ops!(MerklePathsVerified);
        let is_valid = path.verify(
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
            rt_0,
            &shift_query_answers[i][l2..], // leaves are evaluations of the l1 codewords
        )?;
        is_valid.ok_or_err(VerifierError::ShiftQuery)?;
    }

    (auth_j.len() == l2).ok_or_err(VerifierError::NumL2Instances)?;
    for (i, paths) in auth_j.iter().enumerate() {
        (paths.len() == t).ok_or_err(VerifierError::NumShiftQueries)?;
        let root = &l2_roots[i];
        for (j, path) in paths.iter().enumerate() {
            (path.leaf_index == queries.leaf_positions[j])
                .ok_or_err(VerifierError::ShiftQueryIndex)?;
            count_ops!(MerklePathsVerified);
            let is_valid = path.verify(
                mt_leaf_hash_params,
                mt_two_to_one_hash_params,
                root,
                [shift_query_answers[j][i]],
            )?;
            is_valid.ok_or_err(VerifierError::ShiftQuery)?;
        }
    }

    Ok(())
}

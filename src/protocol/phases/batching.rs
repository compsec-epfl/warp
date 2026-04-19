//! Batching sumcheck phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! Reduces the batched claim
//!
//! ```text
//!   Σ_i ξ(i) · \hat f(ζ_i) = σ₂
//! ```
//!
//! to a single evaluation claim `μ = \hat f(α)` via the inner-product
//! sumcheck, with the CBBZ23 / HyperPlonk sparse-evaluation optimization
//! (`accumulate_sparse_evaluations`) folded in.
//!
//! Takes the already-sampled shift-query evaluation points as input so the
//! transcript order (queries sampled, then ξ, then sumcheck messages) is
//! preserved. See the orchestrator in `src/lib.rs`.

use ark_ff::{Field, PrimeField};
use ark_std::log2;
use effsc::{noop_hook, provers::inner_product::InnerProductProver, runner::sumcheck};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};
use std::collections::HashMap;

use crate::count_ops;
use crate::protocol::oracle::Oracle;
use crate::utils::poly::eq_poly;

/// [CBBZ23] / HyperPlonk sparse-evaluation optimization: for shift-query
/// zetas (indices `1+s..r`), each ζ is a 0/1 vector representing a single
/// hypercube point. We accumulate the corresponding `eq_evals[i]` into a
/// sparse map keyed by that point's index.
fn accumulate_sparse_evaluations<F: Field>(
    zetas: Vec<&[F]>,
    eq_evals: Vec<F>,
    s: usize,
    r: usize,
) -> HashMap<usize, F> {
    let mut result: HashMap<usize, F> = HashMap::new();
    for i in 1 + s..r {
        let index = zetas[i]
            .iter()
            .enumerate()
            .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
            .sum::<usize>();
        *result.entry(index).or_insert_with(F::zero) += eq_evals[i];
    }
    result
}

/// Sum `dense_polys` column-wise and add the sparse contributions into the
/// resulting vector. Used to build the `g` side of the inner-product
/// sumcheck `∑_x f(x)·g(x)`.
fn batched_constraint_poly<F: Field>(
    dense_polys: &[Vec<F>],
    sparse_polys: &HashMap<usize, F>,
) -> Vec<F> {
    if dense_polys.is_empty() {
        return Vec::new();
    }
    let mut result = vec![F::ZERO; dense_polys[0].len()];
    for row in dense_polys {
        for (i, val) in row.iter().enumerate() {
            result[i] += *val;
        }
    }
    for (k, v) in sparse_polys.iter() {
        result[*k] += *v;
    }
    result
}

/// Output of the batching sumcheck: the reduced point `α` and the target
/// `μ = \hat f(α)`.
pub struct BatchingOutput<F: Field> {
    pub alpha: Vec<F>,
    pub mu: F,
}

/// Run the batching sumcheck.
///
/// `zetas_prefix` must contain `1 + s + t` evaluation points in the order
/// `[ζ_0, ood_0, ..., ood_{s-1}, query_0, ..., query_{t-1}]`.
#[tracing::instrument(
    name = "batching",
    skip_all,
    fields(s = s, t = t, log_n = log_n)
)]
pub fn prove<F>(
    prover_state: &mut ProverState,
    oracle: &Oracle<F>,
    zetas_prefix: &[&[F]],
    s: usize,
    t: usize,
    log_n: usize,
) -> BatchingOutput<F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    let n = oracle.len();
    let r = 1 + s + t;
    let log_r = log2(r) as usize;
    debug_assert_eq!(zetas_prefix.len(), r);

    let xis = prover_state.verifier_messages_vec::<F>(log_r);

    // compute evaluations for xi and the dense ood_evals_vec for the first 1+s zetas
    let (xi_eq_evals, ood_evals_vec) = {
        let _s = tracing::info_span!("batching.eq_evals").entered();
        let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<_>>();
        let ood_evals_vec = (0..1 + s)
            .map(|i| {
                (0..n)
                    .map(|a| eq_poly(zetas_prefix[i], a) * xi_eq_evals[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        (xi_eq_evals, ood_evals_vec)
    };

    // [CBBZ23] / HyperPlonk optimization for the t sparse shift-query zetas.
    let id_non_0_eval_sums = {
        let _s = tracing::info_span!("batching.accumulate_sparse").entered();
        accumulate_sparse_evaluations(zetas_prefix.to_vec(), xi_eq_evals, s, r)
    };

    // Run the inner-product sumcheck. `InnerProductProver` + `runner::sumcheck`
    // is the new-style `SumcheckProver` entry point; wire format is three
    // evaluations `[q(0), q(1), q(2)]` per round (`effsc::sumcheck_verify`
    // reads them on the verifier side). The prover is MSB half-split, so the
    // challenge vector arrives in MSB order — reverse once here so downstream
    // MLE / eq_poly queries (arkworks' LSB-first convention) line up.
    let alpha = {
        let _s = tracing::info_span!("batching.sumcheck").entered();
        let log_n_bits = ark_std::log2(n) as u64;
        count_ops!(BatchingRounds, log_n_bits);
        let mut ip = InnerProductProver::new(
            oracle.evals().to_vec(),
            batched_constraint_poly(&ood_evals_vec, &id_non_0_eval_sums),
        );
        let mut challenges =
            sumcheck(&mut ip, log_n_bits as usize, prover_state, noop_hook).challenges;
        challenges.reverse();
        challenges
    };

    let mu = oracle.query_at_point(&alpha);

    BatchingOutput { alpha, mu }
}

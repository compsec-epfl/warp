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
use efficient_sumcheck::{
    accumulate_sparse_evaluations, batched_constraint_poly, inner_product_sumcheck,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::protocol::oracle::Oracle;
use crate::utils::poly::EqPolyPrep;

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
        let xi_prep = EqPolyPrep::new(&xis);
        let xi_eq_evals = (0..r).map(|i| xi_prep.eval(i)).collect::<Vec<_>>();
        let ood_evals_vec = (0..1 + s)
            .map(|i| {
                // One EqPolyPrep per outer-i; reused across the inner
                // `a ∈ 0..n` loop — saves `n` reverses + `n` tau_hat
                // allocations per outer step.
                let zeta_prep = EqPolyPrep::new(zetas_prefix[i]);
                (0..n)
                    .map(|a| zeta_prep.eval(a) * xi_eq_evals[i])
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

    // call efficient sumcheck for batched_constraint checks
    //
    // `oracle.evals().to_vec()` is an intentional O(n) clone, not an
    // API wart. `inner_product_sumcheck` folds its first argument
    // in-place (halves per round, truncates to length 1), and warp
    // needs the pre-fold codeword to survive: it's packed into the
    // new accumulator witness after this phase (`tc.f.into_evals()`
    // later in `WARP::prove`). So the prover inherently holds two
    // lives of the codeword — one destructive for sumcheck folding,
    // one preserved for the next round's oracle. Either owns-and-
    // clones (what we do here) or borrows-mutably-and-clones-at-
    // caller; the allocation count is the same.
    let alpha = {
        let _s = tracing::info_span!("batching.sumcheck").entered();
        let log_n = ark_std::log2(n) as u64;
        count_ops!(BatchingRounds, log_n);
        inner_product_sumcheck(
            &mut oracle.evals().to_vec(),
            &mut batched_constraint_poly(&ood_evals_vec, &id_non_0_eval_sums),
            prover_state,
        )
        .verifier_messages
    };

    let mu = oracle.query_at_point(&alpha);

    BatchingOutput { alpha, mu }
}

/// Reduce the batching (inner-product / multilinear) sumcheck's per-round
/// messages against the verifier challenges `α`. Each round message is
/// `[a, b]` where `h(X) = a·(1-2X) + b·X + (prev_target - b)·X²`; the
/// caller's `a, b` unpacking mirrors `src/protocol/transcript/verifier.rs`.
#[tracing::instrument(name = "batching.verify", skip_all)]
pub fn verify_claim<F>(sigma_2: F, sums_per_round: Vec<[F; 2]>, alpha: &[F]) -> F
where
    F: Field,
{
    let mut target = sigma_2;
    for ([a, b], x) in sums_per_round.into_iter().zip(alpha) {
        target = (target - b) * x.square() + a * (F::one() - x.double()) + b * x;
    }
    target
}

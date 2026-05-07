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
//! IOR signature
//! -------------
//! - `Statement`        — `(zetas_prefix, s, t, log_n)` — shared.
//! - `Witness`          — `()`
//! - `ProverInputs`     — `&Oracle<F>` (the committed oracle, full data)
//! - `VerifierInputs`   — `(nus, acc_mu)` — used to compute `σ₂` and the
//!   final-claim oracle check.
//! - `ReductionInputs`  — `alpha` (the LSB sumcheck challenges); both sides
//!   compute and feed it through `reduce_statement`.
//! - `ReducedStatement` — `alpha` — the new code-eval point (LSB-indexed)
//! - `ProofString`      — `()`
//! - `ReducedWitness`   — `mu` — the prover's reported `\hat f(α)`
//! - `VerifierOutputs`  — `()`

use ark_ff::{Field, PrimeField};
use ark_std::log2;
use effsc::{
    noop_hook, provers::inner_product::InnerProductProver, runner::sumcheck,
    verifier::sumcheck_verify,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::count_ops;
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::phases::IOR;
use crate::protocol::transcript::EffscVerifierTranscript;
use crate::utils::poly::{eq_poly, eq_poly_non_binary};

/// [CBBZ23] / HyperPlonk sparse-evaluation optimization: for shift-query
/// zetas (indices `1+s..r`), each ζ is a 0/1 vector representing a single
/// hypercube point.
fn accumulate_sparse_evaluations<F: Field>(
    zetas: &[Vec<F>],
    eq_evals: &[F],
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
/// resulting vector.
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

// ─── IOR signature types ──────────────────────────────────────────────────

pub struct BatchingStatement<F: Field> {
    /// `1 + s + t` evaluation points: `[ζ_0, ood_j…, query_k…]`.
    pub zetas_prefix: Vec<Vec<F>>,
    pub s: usize,
    pub t: usize,
    pub log_n: usize,
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> BatchingStatement<F> {
    /// Single source of truth for the `zetas_prefix` shape — both the
    /// prover and verifier orchestrators construct their `BatchingStatement`
    /// through this. Drift between sides becomes structurally impossible.
    ///
    /// Layout: `[ζ_0, ood_chunk_0, …, ood_chunk_{s-1}, query_0, …, query_{t-1}]`.
    pub fn from_phase_outputs(
        zeta_0: Vec<F>,
        ood_samples_flat: &[F],
        query_eval_points: &[Vec<F>],
        s: usize,
        t: usize,
        log_n: usize,
    ) -> Self {
        let mut zetas: Vec<Vec<F>> = Vec::with_capacity(1 + s + t);
        zetas.push(zeta_0);
        for chunk in ood_samples_flat.chunks(log_n) {
            zetas.push(chunk.to_vec());
        }
        for q in query_eval_points {
            zetas.push(q.clone());
        }
        Self {
            zetas_prefix: zetas,
            s,
            t,
            log_n,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub struct BatchingProverInputs<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
}

pub struct BatchingVerifierInputs<F: Field> {
    /// `1 + s + t` ν values; used to compute `σ₂ = Σ ξ_eq · ν`.
    pub nus: Vec<F>,
    /// Multiplier on the final-claim oracle check.
    pub acc_mu: F,
}

pub struct BatchingReductionInputs<F: Field> {
    /// LSB-indexed sumcheck challenge vector.
    pub alpha: Vec<F>,
}

pub struct BatchingReducedStatement<F: Field> {
    /// New code-eval point (LSB-indexed).
    pub alpha: Vec<F>,
}

pub struct BatchingReducedWitness<F: Field> {
    /// `\hat f(α)` — prover's report.
    pub mu: F,
}

/// Batching phase configuration.
pub struct Batching<'a, F: Field> {
    pub _phantom: PhantomData<&'a F>,
}

impl<'a, F: Field> Batching<'a, F> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: Field> Default for Batching<'a, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, F> IOR for Batching<'a, F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    type Statement = BatchingStatement<F>;
    type Witness<'b>
        = ()
    where
        Self: 'b;
    type ProverInputs<'b>
        = BatchingProverInputs<'b, F>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = BatchingVerifierInputs<F>
    where
        Self: 'b;
    type ReductionInputs = BatchingReductionInputs<F>;
    type ReducedStatement = BatchingReducedStatement<F>;
    type ProofString = ();
    type ReducedWitness = BatchingReducedWitness<F>;
    type VerifierOutputs = ();

    fn reduce_statement(
        &self,
        _statement: &Self::Statement,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement {
        BatchingReducedStatement {
            alpha: inputs.alpha.clone(),
        }
    }

    #[tracing::instrument(
        name = "batching",
        skip_all,
        fields(s = statement.s, t = statement.t, log_n = statement.log_n)
    )]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        _witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> Result<
        (
            Self::ReductionInputs,
            Self::ProofString,
            Self::ReducedWitness,
        ),
        ProverError,
    >
    where
        'a: 'b,
    {
        let n = inputs.oracle.len();
        let r = 1 + statement.s + statement.t;
        let log_r = log2(r) as usize;
        debug_assert_eq!(statement.zetas_prefix.len(), r);

        let xis = prover_state.verifier_messages_vec::<F>(log_r);

        let (xi_eq_evals, ood_evals_vec) = {
            let _s = tracing::info_span!("batching.eq_evals").entered();
            let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<_>>();
            let ood_evals_vec = (0..1 + statement.s)
                .map(|i| {
                    (0..n)
                        .map(|a| eq_poly(&statement.zetas_prefix[i], a) * xi_eq_evals[i])
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (xi_eq_evals, ood_evals_vec)
        };

        let id_non_0_eval_sums = {
            let _s = tracing::info_span!("batching.accumulate_sparse").entered();
            accumulate_sparse_evaluations(&statement.zetas_prefix, &xi_eq_evals, statement.s, r)
        };

        // Run the inner-product sumcheck. MSB half-split → reverse once.
        let alpha = {
            let _s = tracing::info_span!("batching.sumcheck").entered();
            let log_n_bits = ark_std::log2(n) as u64;
            count_ops!(BatchingRounds, log_n_bits);
            let mut ip = InnerProductProver::new(
                inputs.oracle.evals().to_vec(),
                batched_constraint_poly(&ood_evals_vec, &id_non_0_eval_sums),
            );
            let mut challenges =
                sumcheck(&mut ip, log_n_bits as usize, prover_state, noop_hook).challenges;
            challenges.reverse();
            challenges
        };

        let mu = inputs.oracle.query_at_point(&alpha);

        Ok((
            BatchingReductionInputs {
                alpha: alpha.clone(),
            },
            (),
            BatchingReducedWitness { mu },
        ))
    }

    #[tracing::instrument(
        name = "batching.verify",
        skip_all,
        fields(s = statement.s, t = statement.t, log_n = statement.log_n)
    )]
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement,
        inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        'a: 'c,
    {
        let r = 1 + statement.s + statement.t;
        let log_r = log2(r) as usize;
        debug_assert_eq!(statement.zetas_prefix.len(), r);
        debug_assert_eq!(inputs.nus.len(), r);

        // Squeeze ξ matching the prover.
        let xis: Vec<F> = (0..log_r)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<F>>();

        // σ₂ = Σ ξ_eq · ν.
        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&inputs.nus)
            .fold(F::zero(), |acc, (xi_eq, nu)| acc + *xi_eq * nu);

        // Run sumcheck_verify and check the final-claim oracle check.
        let res = {
            let mut wrap = EffscVerifierTranscript(verifier_state);
            sumcheck_verify(sigma_2, 2, statement.log_n, &mut wrap, |_, _| Ok(()))?
        };
        let alpha_lsb: Vec<F> = res.challenges.iter().rev().copied().collect();

        let mut zeta_eqs = Vec::with_capacity(r);
        for zeta in &statement.zetas_prefix {
            zeta_eqs.push(eq_poly_non_binary(zeta, &alpha_lsb));
        }
        let expected = inputs.acc_mu
            * zeta_eqs
                .into_iter()
                .zip(&xi_eq_evals)
                .fold(F::zero(), |acc, (a, b)| acc + a * *b);
        (expected == res.final_claim).then_some(()).ok_or(VerifierError::Target)?;

        Ok((BatchingReductionInputs { alpha: alpha_lsb }, ()))
    }
}

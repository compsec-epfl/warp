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
//! IOR ports
//! ---------
//! - input (prover): `{ zeta_0, samples_flat, query_eval_points, oracle, s, t, log_n }`
//! - input (verifier): `{ zeta_0, samples_flat, query_eval_points, nus, acc_mu, s, t, log_n }`
//! - `reduced`: `{ alpha }` — same on both sides (verifier derives `alpha`
//!   from the transcript)
//! - `carry` (prover): `{ mu }` — the prover's reported `\hat f(α)`
//! - verifier has no carry

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
use crate::protocol::iors::IOR;
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

// ─── Statement helper ─────────────────────────────────────────────────────

/// Internal layout of the `1 + s + t` evaluation points used by the
/// batching sumcheck. Constructed inside `prove` / `verify` from the
/// `(zeta_0, samples_flat, query_eval_points, s, t, log_n)` tuple — single
/// source of truth so the two sides cannot drift.
struct BatchingStatement<F: Field> {
    /// `1 + s + t` evaluation points: `[ζ_0, ood_j…, query_k…]`.
    zetas_prefix: Vec<Vec<F>>,
    s: usize,
    t: usize,
    log_n: usize,
}

impl<F: Field> BatchingStatement<F> {
    /// Layout: `[ζ_0, ood_chunk_0, …, ood_chunk_{s-1}, query_0, …, query_{t-1}]`.
    fn from_ior_outputs(
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
        }
    }
}

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct BatchingProverInput<'a, F: Field> {
    pub zeta_0: &'a [F],
    pub samples_flat: &'a [F],
    pub query_eval_points: &'a [Vec<F>],
    pub oracle: &'a crate::protocol::oracle::Oracle<F>,
    pub s: usize,
    pub t: usize,
    pub log_n: usize,
}

pub struct BatchingVerifierInput<'a, F: Field> {
    pub zeta_0: &'a [F],
    pub samples_flat: &'a [F],
    pub query_eval_points: &'a [Vec<F>],
    /// `1 + s + t` ν values; used to compute `σ₂ = Σ ξ_eq · ν`.
    pub nus: Vec<F>,
    /// Multiplier on the final-claim oracle check.
    pub acc_mu: F,
    pub s: usize,
    pub t: usize,
    pub log_n: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// Public reduced claim — same on both sides.
pub struct BatchingReduced<F: Field> {
    /// New code-eval point (LSB-indexed).
    pub alpha: Vec<F>,
}

pub struct BatchingProverCarry<F: Field> {
    /// `\hat f(α)` — prover's report.
    pub mu: F,
}

pub struct BatchingProverOutput<F: Field> {
    pub reduced: BatchingReduced<F>,
    pub carry: BatchingProverCarry<F>,
}

pub struct BatchingVerifierOutput<F: Field> {
    pub reduced: BatchingReduced<F>,
    pub carry: (),
}

// ─── IOR ──────────────────────────────────────────────────────────────────

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
    const NAME: &'static str = "Batching";

    type ProverInput<'b>
        = BatchingProverInput<'b, F>
    where
        Self: 'b;
    type ProverOutput = BatchingProverOutput<F>;
    type VerifierInput<'b>
        = BatchingVerifierInput<'b, F>
    where
        Self: 'b;
    type VerifierOutput = BatchingVerifierOutput<F>;

    #[tracing::instrument(
        name = "batching",
        skip_all,
        fields(s = input.s, t = input.t, log_n = input.log_n)
    )]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        let statement = BatchingStatement::from_ior_outputs(
            input.zeta_0.to_vec(),
            input.samples_flat,
            input.query_eval_points,
            input.s,
            input.t,
            input.log_n,
        );

        let n = input.oracle.len();
        let r = 1 + statement.s + statement.t;
        let log_r = log2(r) as usize;
        debug_assert_eq!(statement.zetas_prefix.len(), r);

        let xis = transcript.verifier_messages_vec::<F>(log_r);

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
                input.oracle.evals().to_vec(),
                batched_constraint_poly(&ood_evals_vec, &id_non_0_eval_sums),
            );
            let mut challenges =
                sumcheck(&mut ip, log_n_bits as usize, transcript, noop_hook).challenges;
            challenges.reverse();
            challenges
        };

        let mu = input.oracle.query_at_point(&alpha);

        Ok(BatchingProverOutput {
            reduced: BatchingReduced {
                alpha: alpha.clone(),
            },
            carry: BatchingProverCarry { mu },
        })
    }

    #[tracing::instrument(
        name = "batching.verify",
        skip_all,
        fields(s = input.s, t = input.t, log_n = input.log_n)
    )]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        let statement = BatchingStatement::from_ior_outputs(
            input.zeta_0.to_vec(),
            input.samples_flat,
            input.query_eval_points,
            input.s,
            input.t,
            input.log_n,
        );

        let r = 1 + statement.s + statement.t;
        let log_r = log2(r) as usize;
        debug_assert_eq!(statement.zetas_prefix.len(), r);
        debug_assert_eq!(input.nus.len(), r);

        // Squeeze ξ matching the prover.
        let xis: Vec<F> = (0..log_r)
            .map(|_| transcript.verifier_message::<F>())
            .collect();
        let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<F>>();

        // σ₂ = Σ ξ_eq · ν.
        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&input.nus)
            .fold(F::zero(), |acc, (xi_eq, nu)| acc + *xi_eq * nu);

        // Run sumcheck_verify and check the final-claim oracle check.
        let res = {
            let mut wrap = EffscVerifierTranscript(transcript);
            sumcheck_verify(sigma_2, 2, statement.log_n, &mut wrap, |_, _| Ok(()))?
        };
        let alpha_lsb: Vec<F> = res.challenges.iter().rev().copied().collect();

        let mut zeta_eqs = Vec::with_capacity(r);
        for zeta in &statement.zetas_prefix {
            zeta_eqs.push(eq_poly_non_binary(zeta, &alpha_lsb));
        }
        let expected = input.acc_mu
            * zeta_eqs
                .into_iter()
                .zip(&xi_eq_evals)
                .fold(F::zero(), |acc, (a, b)| acc + a * *b);
        (expected == res.final_claim)
            .then_some(())
            .ok_or(VerifierError::Target)?;

        Ok(BatchingVerifierOutput {
            reduced: BatchingReduced { alpha: alpha_lsb },
            carry: (),
        })
    }
}

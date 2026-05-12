//! Batching sumcheck IOR. Reduces `Σ_i ξ(i)·f̂(ζ_i) = σ₂` to a single
//! claim `μ = f̂(α)` via inner-product sumcheck with the CBBZ23 / HyperPlonk
//! sparse-evaluation optimization.

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
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::oracles::evaluation::Oracle;
use crate::protocol::transcript::EffscVerifierTranscript;
use crate::utils::poly::{eq_poly, eq_poly_non_binary};

/// Sparse-eval optimization (CBBZ23 / HyperPlonk): shift-query zetas at
/// indices `1+s..r` are 0/1 vectors picking a single hypercube point.
fn accumulate_sparse_evaluations<F: Field>(
    zetas_evaluation_points: &[Vec<F>],
    xi_eq_evals: &[F],
    s_num_ood_samples: usize,
    r_total_points: usize,
) -> HashMap<usize, F> {
    let mut result: HashMap<usize, F> = HashMap::new();
    for i in 1 + s_num_ood_samples..r_total_points {
        let index = zetas_evaluation_points[i]
            .iter()
            .enumerate()
            .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
            .sum::<usize>();
        *result.entry(index).or_insert_with(F::zero) += xi_eq_evals[i];
    }
    result
}

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

pub struct BatchingStatement<F: Field> {
    /// `1 + s + t` evaluation points: `[ζ_0, ood_chunk_0…, query_k…]`.
    pub zetas_prefix: Vec<Vec<F>>,
    pub s_num_ood_samples: usize,
    pub t_num_queries: usize,
    pub log_n: usize,
    pub _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> BatchingStatement<F> {
    /// Single source of truth for `zetas_prefix` — both prover and verifier
    /// build the statement through this so layout drift is impossible.
    pub fn from_ior_outputs(
        zeta_0: Vec<F>,
        ood_samples_flat: &[F],
        query_eval_points: &[Vec<F>],
        s_num_ood_samples: usize,
        t_num_queries: usize,
        log_n: usize,
    ) -> Self {
        let mut zetas: Vec<Vec<F>> = Vec::with_capacity(1 + s_num_ood_samples + t_num_queries);
        zetas.push(zeta_0);
        for chunk in ood_samples_flat.chunks(log_n) {
            zetas.push(chunk.to_vec());
        }
        for q in query_eval_points {
            zetas.push(q.clone());
        }
        Self {
            zetas_prefix: zetas,
            s_num_ood_samples,
            t_num_queries,
            log_n,
            _phantom: std::marker::PhantomData,
        }
    }
}

pub struct BatchingProverInputs<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
}

pub struct BatchingVerifierInputs<F: Field> {
    pub nus_claimed_evals: Vec<F>,
    pub acc_mu: F,
}

pub struct BatchingReductionInputs<F: Field> {
    pub alpha_sumcheck_challenges: Vec<F>,
}

pub struct BatchingReducedStatement<F: Field> {
    pub alpha_sumcheck_challenges: Vec<F>,
}

pub struct BatchingReducedWitness<F: Field> {
    pub mu_claimed_eval: F,
}

#[derive(Default)]
pub struct Batching<F: Field>(PhantomData<F>);

impl<F> IOR for Batching<F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    const NAME: &'static str = "Batching";

    type Statement<'b>
        = BatchingStatement<F>
    where
        Self: 'b;
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

    fn reduce_statement<'b>(
        &self,
        _statement: &Self::Statement<'b>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
        BatchingReducedStatement {
            alpha_sumcheck_challenges: inputs.alpha_sumcheck_challenges.clone(),
        }
    }

    #[tracing::instrument(
        name = "batching",
        skip_all,
        fields(s = statement.s_num_ood_samples, t = statement.t_num_queries, log_n = statement.log_n)
    )]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        _witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'b,
    {
        let n = inputs.oracle.len();
        let r = 1 + statement.s_num_ood_samples + statement.t_num_queries;
        let log_r = log2(r) as usize;
        if statement.zetas_prefix.len() != r {
            return Err(ProverError::StatementShape {
                what: "zetas_prefix",
                expected: r,
                got: statement.zetas_prefix.len(),
            });
        }

        let xis = prover_state.verifier_messages_vec::<F>(log_r);

        let (xi_eq_evals, ood_evals_vec) = {
            let _s = tracing::info_span!("batching.eq_evals").entered();
            let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<_>>();
            let ood_evals_vec = (0..1 + statement.s_num_ood_samples)
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
            accumulate_sparse_evaluations(
                &statement.zetas_prefix,
                &xi_eq_evals,
                statement.s_num_ood_samples,
                r,
            )
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
                alpha_sumcheck_challenges: alpha.clone(),
            },
            (),
            BatchingReducedWitness {
                mu_claimed_eval: mu,
            },
        ))
    }

    #[tracing::instrument(
        name = "batching.verify",
        skip_all,
        fields(s = statement.s_num_ood_samples, t = statement.t_num_queries, log_n = statement.log_n)
    )]
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
    {
        let r = 1 + statement.s_num_ood_samples + statement.t_num_queries;
        let log_r = log2(r) as usize;
        if statement.zetas_prefix.len() != r {
            return Err(VerifierError::StatementShape {
                what: "zetas_prefix",
                expected: r,
                got: statement.zetas_prefix.len(),
            });
        }
        if inputs.nus_claimed_evals.len() != r {
            return Err(VerifierError::StatementShape {
                what: "nus_claimed_evals",
                expected: r,
                got: inputs.nus_claimed_evals.len(),
            });
        }

        // Squeeze ξ matching the prover.
        let xis: Vec<F> = (0..log_r)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        let xi_eq_evals = (0..r).map(|i| eq_poly(&xis, i)).collect::<Vec<F>>();

        // σ₂ = Σ ξ_eq · ν.
        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&inputs.nus_claimed_evals)
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
        (expected == res.final_claim)
            .then_some(())
            .ok_or(VerifierError::Target)?;

        Ok((
            BatchingReductionInputs {
                alpha_sumcheck_challenges: alpha_lsb,
            },
            (),
        ))
    }
}

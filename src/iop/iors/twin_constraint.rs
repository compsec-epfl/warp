//! Twin-constraint sumcheck IOR. Reduces `Σ_i τ(i) · (f(i) + ω·p(i)) = σ₁`
//! to evaluations at γ via protogalaxy folding.
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`.

use ark_ff::{Field, PrimeField};
use ark_iop::{
    IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple, IOR,
};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_vc::mvc::MultiVectorCommitment;
use effsc::{
    coefficient_sumcheck::RoundPolyEvaluator,
    folding::protogalaxy,
    hypercube::{compute_hypercube_eq_evals, Ascending},
    noop_hook,
    provers::coefficient_lsb::CoefficientProverLSB,
    runner::sumcheck,
    verifier::sumcheck_verify,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::accumulation_scheme::AccumulatorInstance;
use crate::count_ops;
use crate::error::VerifierError;
use crate::iop::oracles::evaluation::Oracle;
use crate::relations::r1cs::R1CSConstraints;
use crate::utils::{
    concat_slices,
    poly::{eq_poly, eq_poly_non_binary},
    scale_and_sum,
};

/// Degree-1 polynomial interpolating two field elements: `lo + (hi - lo)·X`.
fn linear_poly<F: Field>(lo: F, hi: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(vec![lo, hi - lo])
}

type R1CSConstraint<F> = (Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>);

fn eval_r1cs_constraint_poly<F: Field>(
    (a, b, c): &R1CSConstraint<F>,
    z0: &[F],
    z1: &[F],
) -> DensePolynomial<F> {
    let eval = |lc: &[(F, usize)], z: &[F]| {
        if z.is_empty() {
            F::ZERO
        } else {
            lc.iter().map(|(t, i)| z[*i] * t).sum::<F>()
        }
    };
    let (a0, b0, c0) = (eval(a, z0), eval(b, z0), eval(c, z0));
    let (a1, b1, c1) = (eval(a, z1) - a0, eval(b, z1) - b0, eval(c, z1) - c0);
    DensePolynomial::from_coefficients_vec(vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1])
}

struct TwinConstraintEvaluator<'a, F: Field> {
    r1cs: &'a R1CSConstraints<F>,
    omega: F,
    degree: usize,
}

impl<'a, F: Field> RoundPolyEvaluator<F> for TwinConstraintEvaluator<'a, F> {
    fn degree(&self) -> usize {
        self.degree
    }

    fn accumulate_pair(&self, coeffs: &mut [F], tw: &[(&[F], &[F])], pw: &[(F, F)]) {
        let (u_even, u_odd) = tw[0];
        let (z_even, z_odd) = tw[1];
        let (a_even, a_odd) = tw[2];
        let (b_even, b_odd) = tw[3];
        let (tau_even, tau_odd) = pw[0];

        if u_odd.is_empty() {
            let f_val = u_even
                .iter()
                .enumerate()
                .map(|(i, &u_i)| u_i * eq_poly(a_even, i))
                .sum::<F>();
            let p_val = self
                .r1cs
                .iter()
                .enumerate()
                .map(|(i, (a, b, c))| {
                    let eq = eq_poly(b_even, i);
                    let eval =
                        |lc: &[(F, usize)]| lc.iter().map(|(t, idx)| z_even[*idx] * t).sum::<F>();
                    eq * (eval(a) * eval(b) - eval(c))
                })
                .sum::<F>();
            let h_val = (f_val + self.omega * p_val) * tau_even;
            coeffs[0] += h_val;
            if coeffs.len() > 1 {
                coeffs[1] -= h_val;
            }
            return;
        }

        let f = protogalaxy::fold(
            a_even.iter().zip(a_odd).map(|(&l, &r)| (l, r - l)),
            u_even
                .iter()
                .zip(u_odd)
                .map(|(&l, &r)| linear_poly(l, r))
                .collect(),
        );

        let p = protogalaxy::fold(
            b_even.iter().zip(b_odd).map(|(&l, &r)| (l, r - l)),
            self.r1cs
                .iter()
                .map(|c| eval_r1cs_constraint_poly(c, z_even, z_odd))
                .collect(),
        );

        let t0 = tau_even;
        let t1 = tau_odd - tau_even;
        let f_coeffs = &f.coeffs;
        let p_coeffs = &p.coeffs;
        let mut q_im1 = F::zero();
        for (i, c) in coeffs.iter_mut().enumerate() {
            let f_i = f_coeffs.get(i).copied().unwrap_or(F::zero());
            let p_i = p_coeffs.get(i).copied().unwrap_or(F::zero());
            let q_i = f_i + self.omega * p_i;
            *c += q_im1 * t1 + q_i * t0;
            q_im1 = q_i;
        }
    }
}

pub struct TwinConstraintStatement<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub acc_instance: AccumulatorInstance<F, V>,
    pub l1_mus_codeword_first_coords: Vec<F>,
    pub l1_taus_zero_check_challenges: Vec<Vec<F>>,
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
}

pub struct TwinConstraintWitness<'a, F: Field> {
    pub acc_witness_w: &'a [Vec<F>],
    pub instances: &'a [Vec<F>],
    pub witnesses: &'a [Vec<F>],
}

pub struct TwinConstraintProverInputs<'a, F: Field> {
    pub fresh_codewords: &'a [Vec<F>],
    pub acc_codewords: &'a [Vec<F>],
}

/// Deferred oracle check: `final_claim ≟ eq(τ,γ)·(ν₀ + ω·η)`. Cannot fire
/// inside `verify` because ν₀, η arrive on the transcript only after Bridge.
#[must_use = "DeferredOracleCheck must be discharged by the downstream IOR; \
              dropping it without calling discharge() leaves the verifier unsound"]
pub struct DeferredOracleCheck<F: Field> {
    omega_zero_check_randomness: F,
    tau_zero_check_challenges: Vec<F>,
    claim: F,
    discharged: std::cell::Cell<bool>,
}

impl<F: Field> DeferredOracleCheck<F> {
    pub(crate) fn new(omega: F, tau: Vec<F>, claim: F) -> Self {
        Self {
            omega_zero_check_randomness: omega,
            tau_zero_check_challenges: tau,
            claim,
            discharged: std::cell::Cell::new(false),
        }
    }

    pub fn discharge(&self, gamma: &[F], nu_0: F, eta: F) -> Result<(), VerifierError> {
        let expected = eq_poly_non_binary(&self.tau_zero_check_challenges, gamma)
            * (nu_0 + self.omega_zero_check_randomness * eta);
        let ok = expected == self.claim;
        self.discharged.set(true);
        ok.then_some(()).ok_or(VerifierError::Target)
    }

    pub fn is_discharged(&self) -> bool {
        self.discharged.get()
    }
}

pub struct TwinConstraintReducedStatement<F: Field> {
    pub gamma_sumcheck_challenges: Vec<F>,
    pub zeta_0: Vec<F>,
    pub beta_tau: Vec<F>,
    pub deferred: DeferredOracleCheck<F>,
}

pub struct TwinConstraintReductionInputs<F: Field> {
    pub omega_zero_check_randomness: F,
    pub tau_zero_check_challenges: Vec<F>,
    pub gamma_sumcheck_challenges: Vec<F>,
    pub final_claim: F,
}

pub struct TwinConstraintReducedWitness<F: Field> {
    pub f_oracle: Oracle<F>,
    pub z_witness_assignment: Vec<F>,
}

pub struct TwinConstraint<'a, F, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub r1cs: &'a R1CSConstraints<F>,
    _phantom: PhantomData<V>,
}

impl<'a, F, V> TwinConstraint<'a, F, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub fn new(r1cs: &'a R1CSConstraints<F>) -> Self {
        Self { r1cs, _phantom: PhantomData }
    }
}

impl<'a, F, V> IOR for TwinConstraint<'a, F, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
{
    const NAME: &'static str = "TwinConstraint";
    const MESSAGE_TAGS: &'static [&'static str] =
        &["squeeze:omega", "squeeze:tau", "delegate:effsc.sumcheck"];

    type Statement<'b>
        = TwinConstraintStatement<F, V>
    where
        Self: 'b;
    type Witness<'b>
        = TwinConstraintWitness<'b, F>
    where
        Self: 'b;
    type ProverInputs<'b>
        = TwinConstraintProverInputs<'b, F>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ()
    where
        Self: 'b;
    type ReductionInputs = TwinConstraintReductionInputs<F>;
    type ReducedStatement = TwinConstraintReducedStatement<F>;
    type ProofString = ();
    type ReducedWitness = TwinConstraintReducedWitness<F>;
    type VerifierOutputs = ();

    fn reduce_statement<'b>(
        &self,
        statement: &Self::Statement<'b>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
        let log_l = statement.log_l;
        let log_n = statement.log_n;
        let l1 = statement.l1_mus_codeword_first_coords.len();

        let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &inputs.gamma_sumcheck_challenges);

        let alpha_vecs = concat_slices(
            &statement.acc_instance.alpha_fold_vectors,
            &vec![vec![F::zero(); log_n]; l1],
        );
        let zeta_0 = scale_and_sum(&alpha_vecs, &gamma_eq_evals);

        let beta_taus: Vec<Vec<F>> = statement
            .acc_instance
            .beta_twin_pairs
            .iter()
            .map(|p| p.tau.clone())
            .chain(statement.l1_taus_zero_check_challenges.iter().cloned())
            .collect();
        let beta_tau = scale_and_sum(&beta_taus, &gamma_eq_evals);

        TwinConstraintReducedStatement {
            gamma_sumcheck_challenges: inputs.gamma_sumcheck_challenges.clone(),
            zeta_0,
            beta_tau,
            deferred: DeferredOracleCheck::new(
                inputs.omega_zero_check_randomness,
                inputs.tau_zero_check_challenges.clone(),
                inputs.final_claim,
            ),
        }
    }
}

impl<'a, F, V> TwinConstraint<'a, F, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    V: MultiVectorCommitment<Alphabet = F>,
{
    #[tracing::instrument(
        name = "twin_constraint",
        skip_all,
        fields(log_l = statement.log_l, log_m = statement.log_m, log_n = statement.log_n)
    )]
    fn prove_inner(
        &self,
        prover_state: &mut ProverState,
        statement: &TwinConstraintStatement<F, V>,
        witness: &TwinConstraintWitness<'_, F>,
        inputs: &TwinConstraintProverInputs<'_, F>,
    ) -> ProverTriple<TwinConstraintReductionInputs<F>, (), TwinConstraintReducedWitness<F>> {
        let l1 = inputs.fresh_codewords.len();
        let log_l = statement.log_l;
        let log_m = statement.log_m;
        let log_n = statement.log_n;

        let omega: F = prover_state.verifier_message();
        let tau = prover_state.verifier_messages_vec::<F>(log_l);

        let tau_eq_evals = Ascending::new(log_l)
            .map(|p| eq_poly(&tau, p.index))
            .collect::<Vec<F>>();

        let alpha_vecs = concat_slices(
            &statement.acc_instance.alpha_fold_vectors,
            &vec![vec![F::zero(); log_n]; l1],
        );

        let z_vecs: Vec<Vec<F>> = statement
            .acc_instance
            .beta_twin_pairs
            .iter()
            .map(|p| &p.x)
            .zip(witness.acc_witness_w)
            .chain(witness.instances.iter().zip(witness.witnesses))
            .map(|(x, w)| concat_slices(x, w))
            .collect();

        let beta_vecs: Vec<Vec<F>> = statement
            .acc_instance
            .beta_twin_pairs
            .iter()
            .map(|p| p.tau.clone())
            .chain(statement.l1_taus_zero_check_challenges.iter().cloned())
            .collect();

        let tablewise = vec![
            concat_slices(inputs.acc_codewords, inputs.fresh_codewords),
            z_vecs,
            alpha_vecs,
            beta_vecs,
        ];
        let pw = vec![tau_eq_evals];

        let degree = 1 + (log_n + 1).max(log_m + 2);
        let evaluator = TwinConstraintEvaluator {
            r1cs: self.r1cs,
            omega,
            degree,
        };

        let mut cc = CoefficientProverLSB::new(&evaluator, tablewise, pw);
        let proof = {
            let _s = tracing::info_span!("twin_constraint.sumcheck").entered();
            count_ops!(TwinConstraintRounds, log_l as u64);
            sumcheck(&mut cc, log_l, prover_state, noop_hook)
        };
        if proof.challenges.len() != log_l {
            return Err(IorProverError::StatementShape {
                what: "sumcheck.challenges",
                expected: log_l,
                got: proof.challenges.len(),
            });
        }

        let reduced = cc.tablewise();
        if !reduced.iter().all(|t| t.len() == 1) {
            return Err(IorProverError::StatementShape {
                what: "sumcheck.tablewise (singleton after full fold)",
                expected: 1,
                got: reduced.iter().map(|t| t.len()).max().unwrap_or(0),
            });
        }
        let f = reduced[0][0].clone();
        let z = reduced[1][0].clone();

        Ok((
            TwinConstraintReductionInputs {
                omega_zero_check_randomness: omega,
                tau_zero_check_challenges: tau,
                gamma_sumcheck_challenges: proof.challenges,
                final_claim: proof.final_value,
            },
            (),
            TwinConstraintReducedWitness {
                f_oracle: Oracle::from_evals(f),
                z_witness_assignment: z,
            },
        ))
    }

    #[tracing::instrument(
        name = "twin_constraint.verify",
        skip_all,
        fields(log_l = statement.log_l, log_m = statement.log_m, log_n = statement.log_n)
    )]
    fn verify_inner(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &TwinConstraintStatement<F, V>,
    ) -> Result<(TwinConstraintReductionInputs<F>, ()), IorVerifierError> {
        let log_l = statement.log_l;
        let log_n = statement.log_n;
        let l1 = statement.l1_mus_codeword_first_coords.len();

        let omega: F = verifier_state.verifier_message();
        let tau: Vec<F> = (0..log_l)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();

        let tau_eq_evals = compute_hypercube_eq_evals(log_l, &tau);
        let etas_l2_first = concat_slices(
            &statement.acc_instance.eta_predicate_evals,
            &vec![F::zero(); l1],
        );
        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(
                statement
                    .acc_instance
                    .mu_claimed_evals
                    .iter()
                    .copied()
                    .chain(statement.l1_mus_codeword_first_coords.iter().copied())
                    .zip(etas_l2_first),
            )
            .fold(F::zero(), |acc, (eq_tau, (mu, eta))| {
                acc + eq_tau * (mu + omega * eta)
            });

        let tc_degree = 1 + (log_n + 1).max(statement.log_m + 2);
        let (gamma, final_claim) = {
            let res = sumcheck_verify(sigma_1, tc_degree, log_l, verifier_state, |_, _| Ok(()))
                .map_err(|e| IorVerifierError::Transcript(format!("sumcheck: {e:?}")))?;
            (res.challenges, res.final_claim)
        };

        Ok((
            TwinConstraintReductionInputs {
                omega_zero_check_randomness: omega,
                tau_zero_check_challenges: tau,
                gamma_sumcheck_challenges: gamma,
                final_claim,
            },
            (),
        ))
    }

    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &TwinConstraintStatement<F, V>,
        witness: &TwinConstraintWitness<'_, F>,
        inputs: &TwinConstraintProverInputs<'_, F>,
    ) -> Result<
        IorProveResult<TwinConstraintReducedStatement<F>, (), TwinConstraintReducedWitness<F>>,
        IorProverError,
    > {
        self.compose_prove(prover_state, statement, |t| {
            self.prove_inner(t, statement, witness, inputs)
        })
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &TwinConstraintStatement<F, V>,
        _inputs: &(),
    ) -> Result<IorVerifyResult<TwinConstraintReducedStatement<F>, ()>, IorVerifierError> {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement)
        })
    }
}

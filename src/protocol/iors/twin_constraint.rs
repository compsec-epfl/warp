//! Twin-constraint sumcheck IOR. Reduces `Σ_i τ(i) · (f(i) + ω·p(i)) = σ₁`
//! to evaluations at γ via protogalaxy folding.
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`.

use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
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

use crate::count_ops;
use crate::error::VerifierError;
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::oracles::evaluation::Oracle;
use crate::protocol::transcript::EffscVerifierTranscript;
use crate::relations::r1cs::R1CSConstraints;
use crate::utils::{
    concat_slices,
    poly::{eq_poly, eq_poly_non_binary},
    scale_and_sum,
};
use crate::warp::AccumulatorInstance;

/// Degree-1 polynomial interpolating two field elements: `lo + (hi - lo)·X`.
fn linear_poly<F: Field>(lo: F, hi: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(vec![lo, hi - lo])
}

/// A single R1CS constraint row: sparse representations of A, B, and C.
type R1CSConstraint<F> = (Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>);

/// Evaluate one R1CS constraint `Az·Bz - Cz` as a degree-2 polynomial
/// from two witness vectors `z0`, `z1`.
fn eval_r1cs_constraint_poly<F: Field>(
    (a, b, c): &R1CSConstraint<F>,
    z0: &[F],
    z1: &[F],
) -> DensePolynomial<F> {
    // effsc's `final_value` calls `accumulate_pair` once with the odd half
    // empty (singleton case after all rounds folded). Treat an empty `z` as
    // the all-zero vector so the eval returns `F::ZERO` rather than panicking.
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

/// Round-polynomial evaluator fusing α-fold, β-fold, and τ-linear into a
/// single sumcheck pass.
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
        // tw[0] = (u_even, u_odd), tw[1] = (z_even, z_odd),
        // tw[2] = (a_even, a_odd), tw[3] = (b_even, b_odd)
        // pw[0] = (tau_even, tau_odd)
        let (u_even, u_odd) = tw[0];
        let (z_even, z_odd) = tw[1];
        let (a_even, a_odd) = tw[2];
        let (b_even, b_odd) = tw[3];
        let (tau_even, tau_odd) = pw[0];

        // Singleton case: effsc's `coefficient_lsb::final_value` calls
        // `accumulate_pair` once after all rounds with `tw[i] = (singleton, &[])`
        // and `pw[0] = (singleton, F::ZERO)`. Evaluate the polynomial directly
        // at the singleton point; emit `[h, -h]` so `g(0) + g(1) == h`, matching
        // the convention used by the simple pairwise-only evaluators.
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

        // f(X) = fold(α, oracle_evals): protogalaxy fold over α pairs and linear polys from u
        let f = protogalaxy::fold(
            a_even.iter().zip(a_odd).map(|(&l, &r)| (l, r - l)),
            u_even
                .iter()
                .zip(u_odd)
                .map(|(&l, &r)| linear_poly(l, r))
                .collect(),
        );

        // p(X) = fold(β, Az·Bz - Cz): protogalaxy fold over β pairs and R1CS constraint polys
        let p = protogalaxy::fold(
            b_even.iter().zip(b_odd).map(|(&l, &r)| (l, r - l)),
            self.r1cs
                .iter()
                .map(|c| eval_r1cs_constraint_poly(c, z_even, z_odd))
                .collect(),
        );

        // h(X) = (f(X) + ω·p(X)) · t(X) where t is linear t_0 + t_1·X.
        // Closed form per coefficient: h_i = q_{i-1}·t_1 + q_i·t_0 with
        // q_i = f_i + ω·p_i. We accumulate directly into `coeffs` so the
        // (f + ω·p) sum and the (·t) multiplication never allocate temporary
        // DensePolynomials — the per-pair allocation count drops by 3
        // (the +, the *omega, and the naive_mul each used to allocate).
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

pub struct TwinConstraintStatement<F: Field, H: MerkleHasher> {
    pub acc_instance: AccumulatorInstance<F, H>,
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
pub struct DeferredOracleCheck<F: Field> {
    pub omega_zero_check_randomness: F,
    pub tau_zero_check_challenges: Vec<F>,
    pub claim: F,
}

impl<F: Field> DeferredOracleCheck<F> {
    pub fn discharge(&self, gamma: &[F], nu_0: F, eta: F) -> Result<(), VerifierError> {
        let expected = eq_poly_non_binary(&self.tau_zero_check_challenges, gamma)
            * (nu_0 + self.omega_zero_check_randomness * eta);
        (expected == self.claim)
            .then_some(())
            .ok_or(VerifierError::Target)
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

pub struct TwinConstraint<'a, F, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    H: MerkleHasher,
{
    pub r1cs: &'a R1CSConstraints<F>,
    pub _phantom: PhantomData<H>,
}

impl<'a, F, H> IOR for TwinConstraint<'a, F, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    H: MerkleHasher,
{
    const NAME: &'static str = "TwinConstraint";

    type Statement<'b>
        = TwinConstraintStatement<F, H>
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

    /// Single source of truth for ζ₀ / β_τ. Both prover and verifier
    /// land here with `(ω, τ, γ, final_claim)`; the new accumulator
    /// state is computed identically on both sides.
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

        // β τ-vectors: accumulated taus first (length l2), then PESAT taus
        // (length l1). The τ component of the new β = Σ γ_eq(i) · β_i.
        let beta_taus: Vec<Vec<F>> = statement
            .acc_instance
            .beta_twin_pairs
            .0
            .iter()
            .cloned()
            .chain(statement.l1_taus_zero_check_challenges.iter().cloned())
            .collect();
        let beta_tau = scale_and_sum(&beta_taus, &gamma_eq_evals);

        TwinConstraintReducedStatement {
            gamma_sumcheck_challenges: inputs.gamma_sumcheck_challenges.clone(),
            zeta_0,
            beta_tau,
            deferred: DeferredOracleCheck {
                omega_zero_check_randomness: inputs.omega_zero_check_randomness,
                tau_zero_check_challenges: inputs.tau_zero_check_challenges.clone(),
                claim: inputs.final_claim,
            },
        }
    }

    #[tracing::instrument(
        name = "twin_constraint",
        skip_all,
        fields(log_l = statement.log_l, log_m = statement.log_m, log_n = statement.log_n)
    )]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'b,
        'a: 'b,
        H: 'b,
    {
        let l1 = inputs.fresh_codewords.len();
        let log_l = statement.log_l;
        let log_m = statement.log_m;
        let log_n = statement.log_n;

        // a. zero-check randomness
        let omega: F = prover_state.verifier_message();
        let tau = prover_state.verifier_messages_vec::<F>(log_l);

        // b. assemble sumcheck tables
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
            .1
            .iter()
            .zip(witness.acc_witness_w)
            .chain(witness.instances.iter().zip(witness.witnesses))
            .map(|(x, w)| concat_slices(x, w))
            .collect();

        // β tables: accumulated β-τs first, then PESAT τs.
        let beta_vecs: Vec<Vec<F>> = statement
            .acc_instance
            .beta_twin_pairs
            .0
            .iter()
            .cloned()
            .chain(statement.l1_taus_zero_check_challenges.iter().cloned())
            .collect();

        let tablewise = vec![
            concat_slices(inputs.acc_codewords, inputs.fresh_codewords), // u
            z_vecs,                                                      // z
            alpha_vecs,                                                  // a
            beta_vecs,                                                   // b
        ];
        let pw = vec![tau_eq_evals]; // tau

        let degree = 1 + (log_n + 1).max(log_m + 2);
        let evaluator = TwinConstraintEvaluator {
            r1cs: self.r1cs,
            omega,
            degree,
        };

        // c. run the sumcheck.
        let mut cc = CoefficientProverLSB::new(&evaluator, tablewise, pw);
        let proof = {
            let _s = tracing::info_span!("twin_constraint.sumcheck").entered();
            count_ops!(TwinConstraintRounds, log_l as u64);
            sumcheck(&mut cc, log_l, prover_state, noop_hook)
        };
        debug_assert_eq!(proof.challenges.len(), log_l);

        // d. pull only the reduced *witness* halves out of CC. ζ₀ and β_τ
        // are NOT pulled here — `reduce_statement` recomputes them from
        // (statement, γ) via `scale_and_sum`, which is the single source
        // of truth that both prover and verifier go through.
        let reduced = cc.tablewise();
        debug_assert!(reduced.iter().all(|t| t.len() == 1));
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
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        _inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
        'a: 'c,
        H: 'c,
    {
        let log_l = statement.log_l;
        let log_n = statement.log_n;
        let l1 = statement.l1_mus_codeword_first_coords.len();

        // Squeeze ω, τ matching the prover.
        let omega: F = verifier_state.verifier_message();
        let tau: Vec<F> = (0..log_l)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();

        // Compute σ₁ = Σ_i τ_eq(i) · (μ_i + ω · η_i).
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

        // Run the sumcheck. The deferred oracle check
        //   final_claim == eq(τ, γ) · (ν₀ + ω · η)
        // is left to the orchestrator because ν₀ and η arrive on the
        // transcript AFTER the sumcheck rounds.
        let tc_degree = 1 + (log_n + 1).max(statement.log_m + 2);
        let (gamma, final_claim) = {
            let mut wrap = EffscVerifierTranscript(verifier_state);
            let res = sumcheck_verify(sigma_1, tc_degree, log_l, &mut wrap, |_, _| Ok(()))?;
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
}

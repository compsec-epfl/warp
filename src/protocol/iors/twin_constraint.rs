//! Twin-constraint sumcheck phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (oracle composition).
//! The forthcoming `docs/paper-mods/mod2_structured_sumcheck.tex` will
//! promote this phase's fused-fold prover to a first-class paper primitive.
//!
//! Reduces the claim
//!
//! ```text
//!   Σ_i τ(i) · (f(i) + ω · p(i)) = σ₁
//! ```
//!
//! to evaluations at a random point γ via protogalaxy folding, where
//!   - `f(X) = fold(α, oracle_evals)` — folded codeword check
//!   - `p(X) = fold(β, Az·Bz − Cz)` — folded R1CS constraint check
//!   - `t(X)` = linear interpolation of τ — equality polynomial
//!
//! Each round's round polynomial has the form `h(X) = (f(X) + ω·p(X))·t(X)`.
//!
//! IOR ports
//! ---------
//! - input (prover): `{ acc_instance, l1_mus, l1_taus, witnesses,
//!   instances, acc_witness_w, fresh_codewords, acc_codewords,
//!   log_l, log_m, log_n }`
//! - input (verifier): `{ parsed_acc, l1_mus, l1_taus, log_l, log_m, log_n }`
//! - `reduced`: `{ gamma, zeta_0, beta_tau, deferred }` — same on both
//!   sides; ζ₀ and β_τ are computed from γ via [`compute_reduced`],
//!   the single source of truth shared by `prove` and `verify`.
//! - `carry` (prover): `{ f, z }` — new reduced codeword oracle and the
//!   reduced witness vector `z = (x, w)`, consumed by η evaluation.
//! - `carry` (verifier): none — the verifier has no oracle data to carry.
//!
//! The deferred oracle check `final_claim ≟ eq(τ, γ) · (ν₀ + ω·η)` cannot
//! complete inside `verify` because ν₀ and η arrive on the transcript
//! *after* the sumcheck rounds. The obligation is exposed as
//! [`DeferredOracleCheck`] inside `reduced` and discharged by Bridge.

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
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::iors::IOR;
use crate::protocol::transcript::EffscVerifierTranscript;
use crate::relations::r1cs::R1CSConstraints;
use crate::types::AccumulatorInstance;
use crate::utils::{
    concat_slices,
    poly::{eq_poly, eq_poly_non_binary},
    scale_and_sum,
};

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

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct TwinConstraintProverInput<'a, F: Field, H: MerkleHasher> {
    pub acc_instance: AccumulatorInstance<F, H>,
    pub l1_mus: &'a [F],
    pub l1_taus: &'a [Vec<F>],
    pub witnesses: &'a [Vec<F>],
    pub instances: &'a [Vec<F>],
    pub acc_witness_w: &'a [Vec<F>],
    pub fresh_codewords: &'a [Vec<F>],
    pub acc_codewords: &'a [Vec<F>],
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
}

pub struct TwinConstraintVerifierInput<'a, F: Field, H: MerkleHasher> {
    pub parsed_acc: AccumulatorInstance<F, H>,
    pub l1_mus: &'a [F],
    pub l1_taus: &'a [Vec<F>],
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// A typed "you owe me a check" handle.
///
/// The TwinConstraint sumcheck reduces σ₁ to a sumcheck final value, but the
/// actual oracle check `final_claim ≟ eq(τ, γ) · (ν₀ + ω·η)` cannot be
/// completed inside `TwinConstraint::verify` because ν₀ and η arrive on the
/// transcript *after* the sumcheck rounds. Rather than splitting
/// TwinConstraint into two IORs (which cascades into other phases having
/// similar shapes), we expose the obligation as a typed value carried in
/// `reduced`.
///
/// Discharge by calling [`Self::discharge`] with the missing inputs once the
/// orchestrator has read them from the transcript.
pub struct DeferredOracleCheck<F: Field> {
    /// Zero-check randomness ω squeezed at TwinConstraint entry.
    pub omega: F,
    /// Zero-check challenge τ squeezed at TwinConstraint entry.
    pub tau: Vec<F>,
    /// Sumcheck final value — what the orchestrator must verify against
    /// `eq(τ, γ) · (ν₀ + ω·η)`.
    pub claim: F,
}

impl<F: Field> DeferredOracleCheck<F> {
    /// Discharge the deferred check.
    ///
    /// Returns `Ok(())` iff `eq(τ, γ) · (ν₀ + ω·η) == claim`. `γ` arrives via
    /// the parent [`TwinConstraintReduced`]; `ν₀, η` come from the transcript
    /// segment immediately following the TwinConstraint sumcheck.
    pub fn discharge(&self, gamma: &[F], nu_0: F, eta: F) -> Result<(), VerifierError> {
        let expected = eq_poly_non_binary(&self.tau, gamma) * (nu_0 + self.omega * eta);
        (expected == self.claim).then_some(()).ok_or(VerifierError::Target)
    }
}

/// Public reduced claim — same on both sides.
pub struct TwinConstraintReduced<F: Field> {
    /// Sumcheck challenge vector (LSB-indexed).
    pub gamma: Vec<F>,
    /// New code-evaluation point (becomes the new accumulator's α).
    pub zeta_0: Vec<F>,
    /// Reduced τ point (becomes the τ component of the new accumulator's β).
    pub beta_tau: Vec<F>,
    /// Typed obligation: the sumcheck's final value awaits verification
    /// against `(ν₀, η)` arriving on the transcript next. Call
    /// [`DeferredOracleCheck::discharge`] from the orchestrator.
    pub deferred: DeferredOracleCheck<F>,
}

pub struct TwinConstraintProverCarry<F: Field> {
    /// New reduced codeword oracle.
    pub f: Oracle<F>,
    /// Reduced witness vector `z = (x, w)` — consumed by η evaluation.
    pub z: Vec<F>,
}

pub struct TwinConstraintProverOutput<F: Field> {
    pub reduced: TwinConstraintReduced<F>,
    pub carry: TwinConstraintProverCarry<F>,
}

pub struct TwinConstraintVerifierOutput<F: Field> {
    pub reduced: TwinConstraintReduced<F>,
    pub carry: (),
}

// ─── Private reduction helper ─────────────────────────────────────────────

/// Single source of truth for ζ₀ / β_τ. Both prover and verifier land
/// here with `(ω, τ, γ, final_claim)` together with the public statement
/// pieces; the new accumulator state is computed identically on both
/// sides.
fn compute_reduced<F: Field, H: MerkleHasher>(
    omega: F,
    tau: Vec<F>,
    gamma: Vec<F>,
    final_claim: F,
    acc_instance: &AccumulatorInstance<F, H>,
    l1_taus: &[Vec<F>],
    l1: usize,
    log_l: usize,
    log_n: usize,
) -> TwinConstraintReduced<F> {
    let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &gamma);

    let alpha_vecs = concat_slices(&acc_instance.alpha, &vec![vec![F::zero(); log_n]; l1]);
    let zeta_0 = scale_and_sum(&alpha_vecs, &gamma_eq_evals);

    // β τ-vectors: accumulated taus first (length l2), then PESAT taus
    // (length l1). The τ component of the new β = Σ γ_eq(i) · β_i.
    let beta_taus: Vec<Vec<F>> = acc_instance
        .beta
        .0
        .iter()
        .cloned()
        .chain(l1_taus.iter().cloned())
        .collect();
    let beta_tau = scale_and_sum(&beta_taus, &gamma_eq_evals);

    TwinConstraintReduced {
        gamma,
        zeta_0,
        beta_tau,
        deferred: DeferredOracleCheck {
            omega,
            tau,
            claim: final_claim,
        },
    }
}

// ─── IOR ──────────────────────────────────────────────────────────────────

/// TwinConstraint phase configuration.
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

    type ProverInput<'b>
        = TwinConstraintProverInput<'b, F, H>
    where
        Self: 'b;
    type ProverOutput = TwinConstraintProverOutput<F>;
    type VerifierInput<'b>
        = TwinConstraintVerifierInput<'b, F, H>
    where
        Self: 'b;
    type VerifierOutput = TwinConstraintVerifierOutput<F>;

    #[tracing::instrument(
        name = "twin_constraint",
        skip_all,
        fields(log_l = input.log_l, log_m = input.log_m, log_n = input.log_n)
    )]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        let l1 = input.fresh_codewords.len();
        let log_l = input.log_l;
        let log_m = input.log_m;
        let log_n = input.log_n;

        // a. zero-check randomness
        let omega: F = transcript.verifier_message();
        let tau = transcript.verifier_messages_vec::<F>(log_l);

        // b. assemble sumcheck tables
        let tau_eq_evals = Ascending::new(log_l)
            .map(|p| eq_poly(&tau, p.index))
            .collect::<Vec<F>>();

        let alpha_vecs = concat_slices(
            &input.acc_instance.alpha,
            &vec![vec![F::zero(); log_n]; l1],
        );

        let z_vecs: Vec<Vec<F>> = input
            .acc_instance
            .beta
            .1
            .iter()
            .zip(input.acc_witness_w)
            .chain(input.instances.iter().zip(input.witnesses))
            .map(|(x, w)| concat_slices(x, w))
            .collect();

        // β tables: accumulated β-τs first, then PESAT τs.
        let beta_vecs: Vec<Vec<F>> = input
            .acc_instance
            .beta
            .0
            .iter()
            .cloned()
            .chain(input.l1_taus.iter().cloned())
            .collect();

        let tablewise = vec![
            concat_slices(input.acc_codewords, input.fresh_codewords), // u
            z_vecs,                                                    // z
            alpha_vecs,                                                // a
            beta_vecs,                                                 // b
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
            sumcheck(&mut cc, log_l, transcript, noop_hook)
        };
        debug_assert_eq!(proof.challenges.len(), log_l);

        // d. pull only the reduced *witness* halves out of CC. ζ₀ and β_τ
        // are NOT pulled here — `compute_reduced` recomputes them from
        // (input, γ) via `scale_and_sum`, which is the single source of
        // truth that both prover and verifier go through.
        let reduced_tables = cc.tablewise();
        debug_assert!(reduced_tables.iter().all(|t| t.len() == 1));
        let f = reduced_tables[0][0].clone();
        let z = reduced_tables[1][0].clone();

        let reduced = compute_reduced::<F, H>(
            omega,
            tau,
            proof.challenges,
            proof.final_value,
            &input.acc_instance,
            input.l1_taus,
            l1,
            log_l,
            log_n,
        );

        Ok(TwinConstraintProverOutput {
            reduced,
            carry: TwinConstraintProverCarry {
                f: Oracle::from_evals(f),
                z,
            },
        })
    }

    #[tracing::instrument(
        name = "twin_constraint.verify",
        skip_all,
        fields(log_l = input.log_l, log_m = input.log_m, log_n = input.log_n)
    )]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        let log_l = input.log_l;
        let log_m = input.log_m;
        let log_n = input.log_n;
        let l1 = input.l1_mus.len();

        // Squeeze ω, τ matching the prover.
        let omega: F = transcript.verifier_message();
        let tau: Vec<F> = (0..log_l)
            .map(|_| transcript.verifier_message::<F>())
            .collect();

        // Compute σ₁ = Σ_i τ_eq(i) · (μ_i + ω · η_i).
        let tau_eq_evals = compute_hypercube_eq_evals(log_l, &tau);
        let etas_l2_first = concat_slices(&input.parsed_acc.eta, &vec![F::zero(); l1]);
        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(
                input
                    .parsed_acc
                    .mu
                    .iter()
                    .copied()
                    .chain(input.l1_mus.iter().copied())
                    .zip(etas_l2_first),
            )
            .fold(F::zero(), |acc, (eq_tau, (mu, eta))| {
                acc + eq_tau * (mu + omega * eta)
            });

        // Run the sumcheck. The deferred oracle check
        //   final_claim == eq(τ, γ) · (ν₀ + ω · η)
        // is left to the orchestrator because ν₀ and η arrive on the
        // transcript AFTER the sumcheck rounds.
        let tc_degree = 1 + (log_n + 1).max(log_m + 2);
        let (gamma, final_claim) = {
            let mut wrap = EffscVerifierTranscript(transcript);
            let res = sumcheck_verify(sigma_1, tc_degree, log_l, &mut wrap, |_, _| Ok(()))?;
            (res.challenges, res.final_claim)
        };

        let reduced = compute_reduced::<F, H>(
            omega,
            tau,
            gamma,
            final_claim,
            &input.parsed_acc,
            input.l1_taus,
            l1,
            log_l,
            log_n,
        );

        Ok(TwinConstraintVerifierOutput { reduced, carry: () })
    }
}

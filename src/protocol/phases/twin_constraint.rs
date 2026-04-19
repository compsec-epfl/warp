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

use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use efficient_sumcheck::{
    coefficient_sumcheck::{coefficient_sumcheck, RoundPolyEvaluator},
    folding::protogalaxy,
    hypercube::Hypercube,
    order_strategy::AscendingOrder,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::hasher::WarpHasher;
use crate::protocol::oracle::Oracle;
use crate::relations::r1cs::R1CSConstraints;
use crate::types::AccumulatorInstance;
use crate::utils::{concat_slices, poly::eq_poly};

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
    let eval = |lc: &[(F, usize)], z: &[F]| lc.iter().map(|(t, i)| z[*i] * t).sum::<F>();
    let (a0, b0, c0) = (eval(a, z0), eval(b, z0), eval(c, z0));
    let (a1, b1, c1) = (eval(a, z1) - a0, eval(b, z1) - b0, eval(c, z1) - c0);
    DensePolynomial::from_coefficients_vec(vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1])
}

/// Round-polynomial evaluator fusing α-fold, β-fold, and τ-linear into a
/// single sumcheck pass. See `mod2_structured_sumcheck.tex` (stub) — the
/// fusion will be promoted to a paper-level primitive in Plan B'.
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

        // t(X) = tau_even + (tau_odd - tau_even) · X
        let t = linear_poly(tau_even, tau_odd);

        // h(X) = (f(X) + ω·p(X)) · t(X)
        let h = (f + p * self.omega).naive_mul(&t);

        for (c, &hc) in coeffs.iter_mut().zip(h.coeffs.iter()) {
            *c += hc;
        }
    }
}

/// Output of the twin-constraint sumcheck. All oracles / vectors are the
/// reduced claim state consumed by downstream phases (OOD, batching, final
/// target).
pub struct TwinConstraintOutput<F: Field> {
    /// Reduced codeword oracle `f` — consumed by OOD, batching, proximity.
    pub f: Oracle<F>,
    /// Reduced witness vector `z = (x, w)` — consumed by η evaluation.
    pub z: Vec<F>,
    /// New code evaluation point `ζ₀` — becomes the new accumulator α.
    pub zeta_0: Vec<F>,
    /// Reduced τ — becomes the τ component of the new accumulator β.
    pub beta_tau: Vec<F>,
}

/// Run the twin-constraint sumcheck prover.
///
/// Takes codeword slices by reference so the caller (orchestrator) can hand
/// them to [`proximity::prove`](super::proximity::prove) after this phase
/// returns. `fresh_taus` and `acc_instance` are consumed into the sumcheck
/// tables — neither is needed downstream.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "twin_constraint",
    skip_all,
    fields(log_l = log_l, log_m = log_m, log_n = log_n)
)]
pub fn prove<F, H>(
    prover_state: &mut ProverState,
    fresh_codewords: &[Vec<F>],
    fresh_taus: Vec<Vec<F>>,
    acc_instance: AccumulatorInstance<F, H>,
    acc_witness_f: &[Vec<F>],
    acc_witness_w: &[Vec<F>],
    instances: &[Vec<F>],
    witnesses: &[Vec<F>],
    r1cs: &R1CSConstraints<F>,
    log_l: usize,
    log_m: usize,
    log_n: usize,
) -> TwinConstraintOutput<F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    H: WarpHasher<F>,
{
    let l1 = fresh_codewords.len();

    // a. zero-check randomness
    let omega: F = prover_state.verifier_message();
    let tau = prover_state.verifier_messages_vec::<F>(log_l);

    // b. assemble sumcheck tables
    let tau_eq_evals = Hypercube::<AscendingOrder>::new(log_l)
        .map(|(index, _point)| eq_poly(&tau, index))
        .collect::<Vec<F>>();

    let alpha_vecs = concat_slices(&acc_instance.alpha, &vec![vec![F::zero(); log_n]; l1]);

    let z_vecs: Vec<Vec<F>> = acc_instance
        .beta
        .1
        .iter()
        .zip(acc_witness_w)
        .chain(instances.iter().zip(witnesses))
        .map(|(x, w)| concat_slices(x, w))
        .collect();

    let beta_vecs: Vec<Vec<F>> = acc_instance.beta.0.into_iter().chain(fresh_taus).collect();

    let mut tablewise = [
        concat_slices(acc_witness_f, fresh_codewords), // u
        z_vecs,                                        // z
        alpha_vecs,                                    // a
        beta_vecs,                                     // b
    ];
    let mut pw = [tau_eq_evals]; // tau

    let degree = 1 + (log_n + 1).max(log_m + 2);
    let evaluator = TwinConstraintEvaluator {
        r1cs,
        omega,
        degree,
    };

    // c. run the sumcheck
    let sc = {
        let _s = tracing::info_span!("twin_constraint.sumcheck").entered();
        count_ops!(TwinConstraintRounds, log_l as u64);
        coefficient_sumcheck(&evaluator, &mut tablewise, &mut pw, log_l, prover_state)
    };
    debug_assert_eq!(sc.verifier_messages.len(), log_l);

    // d. pop reduced tables — each group has one table left after log_l rounds
    let [mut u_red, mut z_red, mut a_red, mut b_red] = tablewise;
    let f = u_red.pop().unwrap();
    let z = z_red.pop().unwrap();
    let zeta_0 = a_red.pop().unwrap();
    let beta_tau = b_red.pop().unwrap();

    TwinConstraintOutput {
        f: Oracle::from_evals(f),
        z,
        zeta_0,
        beta_tau,
    }
}

/// Reduce the twin-constraint sumcheck's per-round coefficient messages
/// against the verifier challenges `γ`. Returns the final reduced target.
///
/// The prover sends only `d` coefficients per round; the leading coefficient
/// `c_d` is derived from the round claim `T = 2·c_0 + c_1 + … + c_d` so
/// `c_d = T − 2·c_0 − c_1 − … − c_{d−1}`. Matches the encoding in
/// `src/protocol/transcript/verifier.rs::derive_randomness`.
#[tracing::instrument(name = "twin_constraint.verify", skip_all)]
pub fn verify_claim<F>(sigma_1: F, coeffs_per_round: Vec<Vec<F>>, gamma: &[F]) -> F
where
    F: Field,
{
    let mut target = sigma_1;
    for (mut coeffs, g) in coeffs_per_round.into_iter().zip(gamma) {
        let partial_sum: F = coeffs.iter().skip(1).copied().sum();
        let leading = target - coeffs[0].double() - partial_sum;
        coeffs.push(leading);
        let h = DensePolynomial::from_coefficients_vec(coeffs);
        target = h.evaluate(g);
    }
    target
}

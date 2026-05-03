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
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use effsc::{
    coefficient_sumcheck::RoundPolyEvaluator, folding::protogalaxy, hypercube::Ascending,
    noop_hook, provers::coefficient_lsb::CoefficientProverLSB, runner::sumcheck,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::error::ProverError;
use crate::protocol::oracle::Oracle;
use crate::protocol::phases::ProverPhase;
use crate::relations::r1cs::R1CSConstraints;
use crate::types::AccumulatorInstance;
use crate::utils::{concat_slices, poly::eq_poly};
use ark_crypto_primitives::merkle_tree::Config;

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

/// Twin-constraint sumcheck phase: fold τ-zero-check + α-codeword check +
/// β-R1CS check into a single coefficient-form sumcheck.
///
/// Takes codeword slices by reference so the caller (orchestrator) can hand
/// them to [`Proximity`](super::proximity::Proximity) after this phase
/// returns. `fresh_taus` and `acc_instance` are consumed into the sumcheck
/// tables — neither is needed downstream.
pub struct TwinConstraint<'a, F, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    pub fresh_codewords: &'a [Vec<F>],
    pub fresh_taus: Vec<Vec<F>>,
    pub acc_instance: AccumulatorInstance<F, MT>,
    pub acc_witness_f: &'a [Vec<F>],
    pub acc_witness_w: &'a [Vec<F>],
    pub instances: &'a [Vec<F>],
    pub witnesses: &'a [Vec<F>],
    pub r1cs: &'a R1CSConstraints<F>,
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
}

impl<'a, F, MT> ProverPhase for TwinConstraint<'a, F, MT>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
{
    type Output = TwinConstraintOutput<F>;

    #[tracing::instrument(
        name = "twin_constraint",
        skip_all,
        fields(log_l = self.log_l, log_m = self.log_m, log_n = self.log_n)
    )]
    fn prove(self, prover_state: &mut ProverState) -> Result<Self::Output, ProverError> {
        let TwinConstraint {
            fresh_codewords,
            fresh_taus,
            acc_instance,
            acc_witness_f,
            acc_witness_w,
            instances,
            witnesses,
            r1cs,
            log_l,
            log_m,
            log_n,
        } = self;
        let l1 = fresh_codewords.len();

        // a. zero-check randomness
        let omega: F = prover_state.verifier_message();
        let tau = prover_state.verifier_messages_vec::<F>(log_l);

        // b. assemble sumcheck tables
        let tau_eq_evals = Ascending::new(log_l)
            .map(|p| eq_poly(&tau, p.index))
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

        let tablewise = vec![
            concat_slices(acc_witness_f, fresh_codewords), // u
            z_vecs,                                        // z
            alpha_vecs,                                    // a
            beta_vecs,                                     // b
        ];
        let pw = vec![tau_eq_evals]; // tau

        let degree = 1 + (log_n + 1).max(log_m + 2);
        let evaluator = TwinConstraintEvaluator {
            r1cs,
            omega,
            degree,
        };

        // c. run the sumcheck. `CoefficientProverLSB` + `runner::sumcheck` is
        // the new-style `SumcheckProver` entry point; wire format is `d+1`
        // evaluations per round (the verifier uses `effsc::sumcheck_verify` on
        // the other side).
        let mut cc = CoefficientProverLSB::new(&evaluator, tablewise, pw);
        {
            let _s = tracing::info_span!("twin_constraint.sumcheck").entered();
            count_ops!(TwinConstraintRounds, log_l as u64);
            let proof = sumcheck(&mut cc, log_l, prover_state, noop_hook);
            debug_assert_eq!(proof.challenges.len(), log_l);
        }

        // d. pull the single remaining row out of each tablewise table.
        let reduced = cc.tablewise();
        debug_assert!(reduced.iter().all(|t| t.len() == 1));
        let f = reduced[0][0].clone();
        let z = reduced[1][0].clone();
        let zeta_0 = reduced[2][0].clone();
        let beta_tau = reduced[3][0].clone();

        Ok(TwinConstraintOutput {
            f: Oracle::from_evals(f),
            z,
            zeta_0,
            beta_tau,
        })
    }
}

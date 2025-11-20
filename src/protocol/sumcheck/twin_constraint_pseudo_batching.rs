use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use efficient_sumcheck::multilinear::reductions::{pairwise, tablewise};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};

use crate::{relations::r1cs::R1CSConstraints, utils::errs::WARPProverError};

use super::{protogalaxy_trick, Sumcheck};

use super::{WARPSumcheckProverError, WARPSumcheckVerifierError};

pub struct Evals<F> {
    pub u: Vec<Vec<F>>,
    pub z: Vec<Vec<F>>,
    pub a: Vec<Vec<F>>,
    pub b: Vec<Vec<F>>,
    pub tau: Vec<F>,
}

pub type EvalTuple<F> = (Vec<F>, Vec<F>, Vec<F>, Vec<F>);

impl<F> Evals<F> {
    pub fn new(
        u: Vec<Vec<F>>,
        z: Vec<Vec<F>>,
        a: Vec<Vec<F>>,
        b: Vec<Vec<F>>,
        tau: Vec<F>,
    ) -> Self {
        Self { u, z, a, b, tau }
    }

    pub fn get_last_evals(&mut self) -> Result<EvalTuple<F>, WARPProverError> {
        let z = self.z.pop().ok_or(WARPProverError::EmptyEval)?;
        let beta_tau = self.b.pop().ok_or(WARPProverError::EmptyEval)?;
        let u = self.u.pop().ok_or(WARPProverError::EmptyEval)?;
        let alpha = self.a.pop().unwrap();
        Ok((u, z, alpha, beta_tau))
    }
}

pub struct TwinConstraintPseudoBatchingSumcheck {}

impl<F: Field> Sumcheck<F> for TwinConstraintPseudoBatchingSumcheck {
    type Evaluations = Evals<F>;
    type ProverAuxiliary<'a> = (&'a R1CSConstraints<F>, F);
    type VerifierAuxiliary<'a> = (usize, usize); // log_m, log_n
    type Target = F;
    type Challenge = F;

    fn prove_round(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        Evals { u, z, a, b, tau }: &mut Self::Evaluations,
        &(r1cs, xi): &Self::ProverAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckProverError> {
        // compute prover message `h`
        let f_iter = u.chunks(2).zip(a.chunks(2)).map(|(u, a)| {
            protogalaxy_trick(
                a[0].iter().zip(&a[1]).map(|(&l, &r)| (l, r - l)),
                u[0].par_iter()
                    .zip(&u[1])
                    .map(|(&l, &r)| DensePolynomial::from_coefficients_vec(vec![l, r - l]))
                    .collect::<Vec<_>>(),
            )
        });
        let p_iter = b.chunks(2).zip(z.chunks(2)).map(|(b, z)| {
            protogalaxy_trick(
                b[0].iter().zip(&b[1]).map(|(&l, &r)| (l, r - l)),
                r1cs.par_iter()
                    .map(|(a, b, c)| {
                        let a0 = a.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let a1 = a.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - a0;
                        let b0 = b.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let b1 = b.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - b0;
                        let c0 = c.iter().map(|(t, i)| z[0][*i] * t).sum::<F>();
                        let c1 = c.iter().map(|(t, i)| z[1][*i] * t).sum::<F>() - c0;
                        vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1]
                    })
                    .map(DensePolynomial::from_coefficients_vec)
                    .collect::<Vec<_>>(),
            )
        });
        let t_iter = tau
            .chunks(2)
            .map(|t| DensePolynomial::from_coefficients_vec(vec![t[0], t[1] - t[0]]));
        let h = f_iter
            .zip(p_iter)
            .zip(t_iter)
            .map(|((f, p), t)| (f + p * xi).naive_mul(&t))
            .fold(DensePolynomial::zero(), |acc, r| acc + r);

        prover_state.add_scalars(&h.coeffs)?;

        // get challenge
        let [c] = prover_state.challenge_scalars::<1>()?;
        // update evaluation tables
        tablewise::reduce_evaluations(u, c);
        tablewise::reduce_evaluations(z, c);
        tablewise::reduce_evaluations(a, c);
        tablewise::reduce_evaluations(b, c);
        pairwise::reduce_evaluations(tau, c);
        Ok(c)
    }

    fn verify_round(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        aux: &Self::VerifierAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckVerifierError> {
        let mut h_coeffs = vec![F::zero(); 2 + (aux.1 + 1).max(aux.0 + 2)];
        verifier_state.fill_next_scalars(&mut h_coeffs)?;
        let h = DensePolynomial::from_coefficients_vec(h_coeffs);
        if h.evaluate(&F::zero()) + h.evaluate(&F::one()) != *target {
            return Err(WARPSumcheckVerifierError::SumcheckRound);
        }

        // get challenge
        let [c] = verifier_state.challenge_scalars::<1>()?;
        // update sumcheck target for next round
        *target = h.evaluate(&c);
        Ok(c)
    }
}

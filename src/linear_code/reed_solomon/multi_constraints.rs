use std::marker::PhantomData;

use ark_ff::FftField;
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::log2;
use efficient_sumcheck::{hypercube::Hypercube, order_strategy::AscendingOrder};

use crate::{
    linear_code::{linear_code::MultiConstrainedLinearCode, LinearCode},
    relations::relation::BundledPESAT,
    utils::poly::eq_poly,
    WARPError,
};

use super::ReedSolomonConfig;

#[derive(Clone)]
pub struct MultiConstrainedReedSolomon<
    F: FftField,
    C: LinearCode<F, Config: CanonicalSerialize>,
    P: BundledPESAT<F>,
> {
    pub _p: PhantomData<P>,
    pub _c: PhantomData<C>,
    pub r: usize,
    pub config: ReedSolomonConfig<F>,
    // (\alpha_i, \mu_i)_{r}
    pub evaluations: Vec<(Vec<F>, F)>,
    // (tau, x)
    pub beta: (Vec<F>, Vec<F>),
    // we store computations for eq(\tau, j)_{j \in {0, 1}^{\log m}} within a table indexed by
    // hypercube points
    pub tau_eq_evals: Vec<F>,
    // expected evaluation result of the bundled pesat \hat{p}(beta, w)
    pub eta: F,
}

impl<F: FftField, C: LinearCode<F, Config = ReedSolomonConfig<F>>, P: BundledPESAT<F>>
    MultiConstrainedLinearCode<F, C, P> for MultiConstrainedReedSolomon<F, C, P>
{
    fn as_multilinear_extension(num_vars: usize, f: &Vec<F>) -> DenseMultilinearExtension<F> {
        DenseMultilinearExtension::from_evaluations_slice(num_vars, f)
    }

    fn new_with_constraint(
        config: ReedSolomonConfig<F>,
        evaluations: Vec<(Vec<F>, F)>,
        beta: (Vec<F>, Vec<F>), // (tau, x)
        eta: F,
    ) -> Self {
        let hypercube = Hypercube::<AscendingOrder>::new(beta.0.len());
        let tau = &beta.0;

        // TODO: multithread this
        // initialize table for eq(tau, i)
        let tau_eq_evals = hypercube.map(|(index, _point)| eq_poly(tau, index)).collect();

        Self {
            _p: PhantomData::<P>,
            _c: PhantomData::<C>,
            r: evaluations.len(),
            config,
            evaluations,
            tau_eq_evals,
            beta,
            eta,
        }
    }

    fn check_constraints(&self, w: &Vec<F>, f: &Vec<F>, p: &P) -> Result<(), WARPError> {
        // let rs = ReedSolomon::new(self.config.clone());

        // // contains instance vector x
        // let mut z = self.beta.1.clone();
        // let w = rs.decode(f).ok_or(WARPError::DecodeFailed)?;
        // z.extend_from_slice(&w);
        let mut z = self.beta.1.clone();
        z.extend_from_slice(w);

        // evaluate bundled constraints
        let eval_bundled = p.evaluate_bundled(&self.tau_eq_evals, &z)?;
        let is_correct_bundled_eval = eval_bundled == self.eta;

        // evaluate multilinear points
        let is_correct_multilinear_evals = if !self.evaluations.is_empty() {
            let num_vars = log2(self.config.code_length) as usize;
            let f_hat = Self::as_multilinear_extension(num_vars, f);
            self.evaluations.iter().fold(true, |acc, (point, eval)| {
                (f_hat.evaluate(point) == *eval) & acc
            })
        } else {
            true
        };

        if is_correct_bundled_eval & is_correct_multilinear_evals {
            Ok(())
        } else {
            Err(WARPError::UnsatisfiedMultiConstraints(
                is_correct_bundled_eval,
                is_correct_multilinear_evals,
            ))
        }
    }

    fn get_constraints(&self) -> (&[(Vec<F>, F)], &(Vec<F>, Vec<F>), F) {
        (&self.evaluations, &self.beta, self.eta)
    }
}

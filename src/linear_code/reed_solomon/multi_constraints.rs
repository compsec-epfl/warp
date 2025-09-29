use std::collections::HashMap;

use ark_ff::FftField;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::CanonicalSerialize;
use whir::poly_utils::hypercube::BinaryHypercube;

use crate::{
    linear_code::{linear_code::MultiConstrainedLinearCode, LinearCode},
    utils::poly::eq_poly,
};

#[derive(Clone)]
pub struct MultiConstrainedReedSolomon<
    F: FftField,
    C: LinearCode<F, Config: CanonicalSerialize>,
    const R: usize,
> {
    pub config: C::Config,
    // (\alpha_i, \mu_i)_{r}
    pub evaluations: [(Vec<F>, F); R],
    pub beta: (Vec<F>, Vec<F>), // (tau, x)
    // we store computations for eq(\tau, j)_{j \in {0, 1}^{\log m}} within a table indexed by
    // hypercube points
    pub tau_eq_evals: HashMap<usize, F>,
    pub eta: F,
}

impl<F: FftField, C: LinearCode<F, Config: CanonicalSerialize>, const R: usize>
    MultiConstrainedLinearCode<F, C, R> for MultiConstrainedReedSolomon<F, C, R>
{
    fn as_multilinear_extension(num_vars: usize, f: &Vec<F>) -> DenseMultilinearExtension<F> {
        DenseMultilinearExtension::from_evaluations_slice(num_vars, f)
    }

    fn new_with_constraint(
        config: C::Config,
        evaluations: [(Vec<F>, F); R],
        beta: (Vec<F>, Vec<F>), // (tau, x)
        eta: F,
    ) -> Self {
        let mut tau_eq_evals = HashMap::<usize, F>::new();
        let hypercube = BinaryHypercube::new(beta.0.len());
        let tau = &beta.0;

        // TODO: multithread this
        // initialize table for eq(tau, i)
        for point in hypercube {
            tau_eq_evals.insert(point.0, eq_poly(tau, point));
        }

        Self {
            config,
            evaluations,
            tau_eq_evals,
            beta,
            eta,
        }
    }
}

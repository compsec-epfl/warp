use ark_ff::FftField;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::CanonicalSerialize;

use crate::linear_code::{linear_code::MultiConstrainedLinearCode, LinearCode};

#[derive(Clone, CanonicalSerialize)]
pub struct MultiConstrainedReedSolomon<
    F: FftField,
    C: LinearCode<F, Config: CanonicalSerialize>,
    const R: usize,
> {
    config: C::Config,
    // (\alpha_i, \mu_i)_{r}
    evaluations: [(Vec<F>, F); R],
    beta: (Vec<F>, Vec<F>), // (tau, x)
    eta: F,
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
        Self {
            config,
            evaluations,
            beta,
            eta,
        }
    }
}

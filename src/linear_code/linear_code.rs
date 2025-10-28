use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;

use crate::{relations::BundledPESAT, WARPError};

pub trait LinearCode<F: Field> {
    type Config: Clone;
    fn new(config: Self::Config) -> Self;
    fn encode(&self, message: &[F]) -> Vec<F>;
    fn message_len(&self) -> usize;
    fn code_len(&self) -> usize;
}

pub trait MultiConstrainedLinearCode<F: Field, C: LinearCode<F>, P: BundledPESAT<F>> {
    fn new_with_constraint(
        config: <C as LinearCode<F>>::Config,
        evaluations: Vec<(Vec<F>, F)>,
        beta: (Vec<F>, Vec<F>), // (tau, x)
        eta: F,
    ) -> Self;
    fn as_multilinear_extension(num_vars: usize, f: &[F]) -> DenseMultilinearExtension<F>;
    fn check_constraints(&self, w: &Vec<F>, f: &Vec<F>, p: &P) -> Result<(), WARPError>;
    fn get_constraints(&self) -> (&[(Vec<F>, F)], &(Vec<F>, Vec<F>), F);
}

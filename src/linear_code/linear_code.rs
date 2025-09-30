use ark_ff::Field;
use ark_poly::DenseMultilinearExtension;

use crate::{relations::relation::BundledPESAT, WARPError};

pub trait LinearCode<F: Field> {
    type Config;

    fn new(config: Self::Config) -> Self;

    // encode a k-symbol message into an n-symbol codeword
    fn encode(&self, message: &[F]) -> Vec<F>;

    // decode an n-symbol codeword back into the original k-symbol message
    // should return None if decoding fails (bc errors are beyond capacity etc)
    fn decode(&self, received: &[F]) -> Option<Vec<F>>;

    fn message_len(&self) -> usize;

    fn code_len(&self) -> usize;

    fn config(&self) -> Self::Config;
}

pub trait MultiConstrainedLinearCode<F: Field, C: LinearCode<F>, P: BundledPESAT<F>, const R: usize>
{
    fn new_with_constraint(
        config: <C as LinearCode<F>>::Config,
        evaluations: [(Vec<F>, F); R],
        beta: (Vec<F>, Vec<F>), // (tau, x)
        eta: F,
    ) -> Self;

    fn as_multilinear_extension(num_vars: usize, f: &Vec<F>) -> DenseMultilinearExtension<F>;

    fn check_constraints(&self, f: &Vec<F>, p: &P) -> Result<(), WARPError>;
}

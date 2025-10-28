use ark_ff::Field;

use crate::WARPVerifierError;

pub fn check_code_evaluation_point<F: Field>(
    provided: &[F],
    expected: &[F],
) -> Result<(), WARPVerifierError> {
    if provided
        .iter()
        .zip(expected)
        .fold(true, |acc, (a_x, a_i)| acc & (a_x == a_i))
        != true
    {
        Err(WARPVerifierError::CodeEvaluationPoint)
    } else {
        Ok(())
    }
}

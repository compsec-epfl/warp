use ark_ff::{FftField, Field};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain};
use ark_serialize::CanonicalSerialize;

use crate::linear_code::{LinearCode, ReedSolomonConfig};

#[derive(Clone, CanonicalSerialize)]
pub struct ReedSolomon<F: Field + FftField> {
    config: ReedSolomonConfig<F>,
}

// NOTE: would want LDE for completeness but this should work for benches
impl<F: Field + FftField> LinearCode<F> for ReedSolomon<F> {
    type Config = ReedSolomonConfig<F>;

    fn message_len(&self) -> usize {
        self.config.message_length
    }

    fn new(config: Self::Config) -> Self {
        Self { config }
    }

    fn encode(&self, message: &[F]) -> Vec<F> {
        assert_eq!(message.len(), self.config.message_length);

        // build a polynomial of degree < k from the message
        let poly = DensePolynomial::from_coefficients_vec(message.to_vec());

        // evaluate it on the n-point domain (using fft) to get the codeword
        self.config.domain.fft(&poly)
    }

    fn code_len(&self) -> usize {
        self.config.code_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as BLS12_381;

    #[test]
    fn sanity() {
        let message: Vec<BLS12_381> = (0..4_u64).map(|i| BLS12_381::from(i)).collect();
        let rs = ReedSolomon::<BLS12_381>::new(ReedSolomonConfig::<BLS12_381>::default(4, 8));
        let _codeword = rs.encode(&message);
    }
}

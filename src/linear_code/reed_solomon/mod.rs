use ark_ff::{FftField, Field};
use ark_poly::domain::GeneralEvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain};
use ark_serialize::CanonicalSerialize;

use crate::linear_code::LinearCode;

pub mod multi_constraints;

#[derive(Clone, CanonicalSerialize)]
pub struct ReedSolomonConfig<F: Field + FftField> {
    // k, the number of symbols in the message
    pub message_length: usize,
    // n, the number of symbols in the codeword
    pub code_length: usize,
    // the evaluation domain of size n
    domain: GeneralEvaluationDomain<F>,
}

impl<F: Field + FftField> ReedSolomonConfig<F> {
    // when you have a domain already, you can use this constructor
    pub fn new(
        message_length: usize,
        code_length: usize,
        domain: GeneralEvaluationDomain<F>,
    ) -> Self {
        assert!(
            code_length > message_length,
            "Code length must be greater than message length"
        );
        assert_eq!(
            domain.size(),
            code_length,
            "Domain size must equal code length"
        );
        ReedSolomonConfig {
            message_length,
            code_length,
            domain,
        }
    }
    // otherwise, you can use this constructor
    pub fn default(message_length: usize, code_length: usize) -> Self {
        assert!(
            code_length > message_length,
            "Code length must be greater than message length"
        );
        let domain = GeneralEvaluationDomain::<F>::new(code_length).unwrap();
        assert_eq!(
            domain.size(),
            code_length,
            "Domain size must equal code length"
        );
        ReedSolomonConfig {
            message_length,
            code_length,
            domain,
        }
    }
}

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

    fn code_len(&self) -> usize {
        self.config.code_length
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as BLS12_381;

    #[test]
    fn sanity() {
        let message: Vec<BLS12_381> = (0..4_u64).map(|i| BLS12_381::from(i)).collect();
        let rs = ReedSolomon::<BLS12_381>::new(ReedSolomonConfig::<BLS12_381>::default(4, 8));
        let codeword = rs.encode(&message);
        // let decoded = rs.decode(&codeword).unwrap();
        // assert_eq!(decoded, message);
    }
}

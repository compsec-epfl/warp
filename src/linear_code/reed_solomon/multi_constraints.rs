use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial, EvaluationDomain,
};
use ark_serialize::CanonicalSerialize;

use crate::linear_code::linear_code::MultiConstrainedLinearCode;

use super::ReedSolomonConfig;

#[derive(Clone, CanonicalSerialize)]
pub struct MultiConstrainedReedSolomon<F: FftField, const R: usize> {
    config: ReedSolomonConfig<F>,
    // (\alpha_i, \mu_i)_{r}
    evaluations: [(Vec<F>, F); R],
    beta: (Vec<F>, Vec<F>), // (tau, x)
    eta: F,
}

impl<F: FftField, const R: usize> MultiConstrainedLinearCode<F, R>
    for MultiConstrainedReedSolomon<F, R>
{
    type Config = ReedSolomonConfig<F>;

    fn message_len(&self) -> usize {
        self.config.message_length
    }

    fn code_len(&self) -> usize {
        self.config.code_length
    }

    fn encode(&self, message: &[F]) -> Vec<F> {
        assert_eq!(message.len(), self.config.message_length);

        // build a polynomial of degree < k from the message
        let poly = DensePolynomial::from_coefficients_vec(message.to_vec());

        // evaluate it on the n-point domain (using fft) to get the codeword
        self.config.domain.fft(&poly)
    }

    fn decode(&self, received: &[F]) -> Option<Vec<F>> {
        assert_eq!(received.len(), self.config.code_length);

        // perform inverse FFT to get polynomial coefficients
        let coeffs = self.config.domain.ifft(received);

        // NOTE: this is where you would check for errors and correct
        // let (message_coeffs, syndrome_coeffs) = coeffs.split_at(self.config.message_length);
        // if syndrome_coeffs.iter().any(|s| !s.is_zero()) {}

        // extract the first k coefficients
        Some(coeffs[..self.config.message_length].to_vec())
    }

    fn as_multilinear_extension(num_vars: usize, f: &Vec<F>) -> DenseMultilinearExtension<F> {
        DenseMultilinearExtension::from_evaluations_slice(num_vars, f)
    }

    fn new(
        config: &Self::Config,
        evaluations: [(Vec<F>, F); R],
        beta: (Vec<F>, Vec<F>),
        eta: F,
    ) -> Self {
        let config = ReedSolomonConfig {
            message_length: config.message_length,
            code_length: config.code_length,
            domain: config.domain,
        };
        Self {
            config,
            evaluations,
            beta,
            eta,
        }
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }
}

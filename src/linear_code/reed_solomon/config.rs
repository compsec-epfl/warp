use ark_ff::{FftField, Field};
use ark_poly::domain::GeneralEvaluationDomain;
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;

#[derive(Clone, CanonicalSerialize)]
pub struct ReedSolomonConfig<F: Field + FftField> {
    // k, the number of symbols in the message
    pub message_length: usize,
    // n, the number of symbols in the codeword
    pub code_length: usize,
    // the evaluation domain of size n
    pub domain: GeneralEvaluationDomain<F>,
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

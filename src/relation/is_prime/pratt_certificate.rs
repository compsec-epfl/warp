use ark_ff::{Field, PrimeField};

#[derive(Clone)]
pub struct PrattCertificate<F: Field + PrimeField> {
    pub prime: F,
    pub generator: F,
    pub prime_factors_p_minus_one: Vec<F>,
    pub prime_factors_p_minus_one_exponents: Vec<usize>,
}

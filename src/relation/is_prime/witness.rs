use ark_ff::{Field, PrimeField};

use crate::relation::is_prime::PrattCertificate;

#[derive(Clone)]
pub struct IsPrimeWitness<F: Field + PrimeField> {
    pub pratt_certificates: Vec<PrattCertificate<F>>,
}

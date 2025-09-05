use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

use crate::relation::is_prime::PrattCertificate;

#[derive(Clone, CanonicalSerialize)]
pub struct IsPrimeWitness<F: Field + PrimeField> {
    pub pratt_certificates: Vec<PrattCertificate<F>>,
}

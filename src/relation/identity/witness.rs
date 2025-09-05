use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

#[derive(Clone, CanonicalSerialize)]
pub struct IdentityWitness<F: Field + PrimeField> {
    pub w: F,
}

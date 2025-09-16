use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

#[derive(CanonicalSerialize, Clone)]
pub struct IdentityInstance<F: Field + PrimeField> {
    pub x: F,
}

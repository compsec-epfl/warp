use ark_ff::{Field, PrimeField};

#[derive(Clone)]
pub struct IdentityInstance<F: Field + PrimeField> {
    pub x: F,
}

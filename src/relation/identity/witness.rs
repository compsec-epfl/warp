use ark_ff::{Field, PrimeField};

#[derive(Clone)]
pub struct IdentityWitness<F: Field + PrimeField> {
    pub w: F,
}

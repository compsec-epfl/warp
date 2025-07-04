use ark_ff::{Field, PrimeField};

#[derive(Clone)]
pub struct IsPrimeInstance<F: Field + PrimeField> {
    pub prime: F,
}

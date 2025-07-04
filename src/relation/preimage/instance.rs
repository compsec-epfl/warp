use ark_ff::{Field, PrimeField};

#[derive(Clone)]
pub struct PreimageInstance<F>
where
    F: Field + PrimeField,
{
    pub digest: F,
}

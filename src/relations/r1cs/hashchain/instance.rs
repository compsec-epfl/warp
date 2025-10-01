use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

#[derive(Clone, CanonicalSerialize)]
pub struct HashChainInstance<F>
where
    F: Field + PrimeField,
{
    pub digest: F,
}

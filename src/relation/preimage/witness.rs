use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::{Field, PrimeField};
use ark_std::marker::PhantomData;

#[derive(Clone)]
pub struct PreimageWitness<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
{
    pub preimage: Vec<F>,
    pub _crhs_scheme: PhantomData<H>,
}

use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

#[derive(CanonicalSerialize)]
pub struct HashChainWitness<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
{
    pub preimage: Vec<F>,
    pub(crate) _crhs_scheme: PhantomData<H>,
}

impl<F, H> HashChainWitness<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
{
    pub fn new(preimage: Vec<F>) -> Self {
        Self {
            preimage,
            _crhs_scheme: PhantomData,
        }
    }
}

impl<F, H> Clone for HashChainWitness<F, H>
where
    F: Field + PrimeField + Clone,
    H: CRHScheme<Input = [F]>,
{
    fn clone(&self) -> Self {
        HashChainWitness {
            preimage: self.preimage.clone(),
            _crhs_scheme: PhantomData,
        }
    }
}

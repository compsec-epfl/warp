use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

#[derive(CanonicalSerialize)]
pub struct PreimageWitness<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
{
    pub preimage: Vec<F>,
    pub _crhs_scheme: PhantomData<H>,
}

impl<F, H> Clone for PreimageWitness<F, H>
where
    F: Field + PrimeField + Clone,
    H: CRHScheme<Input = [F]>,
{
    fn clone(&self) -> Self {
        PreimageWitness {
            preimage: self.preimage.clone(),
            _crhs_scheme: PhantomData,
        }
    }
}

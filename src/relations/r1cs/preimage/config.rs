use ark_crypto_primitives::crh::CRHScheme;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

#[derive(Clone, CanonicalSerialize)]
pub struct PreimageConfig<F, H>
where
    F: Field + PrimeField + Clone,
    H: CRHScheme<Input = [F]>,
{
    pub hash_params: H::Parameters,
}

use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config as MerkleConfig};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

#[derive(Clone, CanonicalSerialize)]
pub struct MerkleInclusionInstance<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F>,
    MG: Clone,
{
    pub leaf: Vec<F>,
    pub root: M::InnerDigest,
    pub _merkle_config_gadget: PhantomData<MG>,
}

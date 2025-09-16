use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config as MerkleConfig, Path};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

#[derive(Clone, CanonicalSerialize)]
pub struct MerkleInclusionWitness<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F>,
    MG: Clone,
{
    pub proof: Path<M>,
    pub _merkle_config_gadget: PhantomData<MG>,
}

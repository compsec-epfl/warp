use ark_crypto_primitives::merkle_tree::{
    constraints::ConfigGadget, Config as MerkleConfig, LeafParam, TwoToOneParam,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

#[derive(Clone, CanonicalSerialize)]
pub struct MerkleInclusionConfig<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    pub leaf_len: usize,
    pub height: usize,
    pub leaf_hash_param: LeafParam<M>,
    pub two_to_one_hash_param: TwoToOneParam<M>,
    pub _merkle_config_gadget: PhantomData<MG>,
}

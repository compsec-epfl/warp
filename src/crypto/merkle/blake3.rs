use super::parameters::MerkleTreeParams;
use crate::crypto::blake3_crh::fields::Blake3F;
use crate::crypto::blake3_crh::{Blake3, GenericDigest};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config as MerkleConfig, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;

#[derive(Clone)]
pub struct Blake3MerkleConfig<F: PrimeField> {
    _field: PhantomData<F>,
}

pub type Blake3MerkleTreeParams<F> = MerkleTreeParams<F, Blake3F<F>, Blake3, GenericDigest<32>>;

impl<F: PrimeField + Absorb> MerkleConfig for Blake3MerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = Blake3F<F>; // blake3, over field elements
    type TwoToOneHash = Blake3;
}

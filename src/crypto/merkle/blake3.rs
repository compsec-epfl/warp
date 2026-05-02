use super::parameters::MerkleTreeParams;
use ark_crypto_primitives::crh::blake3::{Blake3CRH, Blake3TwoToOneCRH};
use ark_crypto_primitives::crh::ByteDigest;
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

pub type Blake3MerkleTreeParams<F> =
    MerkleTreeParams<F, Blake3CRH<F>, Blake3TwoToOneCRH, ByteDigest<32>>;

impl<F: PrimeField + Absorb> MerkleConfig for Blake3MerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = Blake3CRH<F>;
    type TwoToOneHash = Blake3TwoToOneCRH;
}

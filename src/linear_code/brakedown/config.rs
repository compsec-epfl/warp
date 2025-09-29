use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config as MerkleConfig, LeafParam, TwoToOneParam},
};
use ark_ff::{FftField, Field};
use ark_serialize::CanonicalSerialize;
use std::marker::PhantomData;

#[derive(CanonicalSerialize)]
pub struct BrakedownConfig<F, M, H>
where
    F: Field + FftField,
    M: MerkleConfig,
    H: CRHScheme,
    LeafParam<M>: Clone,
    TwoToOneParam<M>: Clone,
    <H as CRHScheme>::Parameters: Clone,
{
    pub message_len: usize,
    pub leaf_hash_param: LeafParam<M>,
    pub one_two_hash_param: TwoToOneParam<M>,
    pub column_hash_param: H::Parameters,
    pub rng_seed: [u8; 32],
    pub _f: PhantomData<F>,
}

impl<F, M, H> Clone for BrakedownConfig<F, M, H>
where
    F: Field + FftField,
    M: MerkleConfig,
    M::LeafHash: CRHScheme,
    M::TwoToOneHash: TwoToOneCRHScheme,
    H: CRHScheme,
    LeafParam<M>: Clone,
    TwoToOneParam<M>: Clone,
    <H as CRHScheme>::Parameters: Clone,
{
    fn clone(&self) -> Self {
        Self {
            message_len: self.message_len,
            leaf_hash_param: self.leaf_hash_param.clone(),
            one_two_hash_param: self.one_two_hash_param.clone(),
            column_hash_param: self.column_hash_param.clone(),
            rng_seed: self.rng_seed,
            _f: PhantomData,
        }
    }
}

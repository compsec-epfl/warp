use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config as MerkleConfig, IdentityDigestConverter},
    sponge::Absorb,
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{borrow::Borrow, marker::PhantomData, rand::RngCore};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::merkle::{digest::GenericDigest, parameters::MerkleTreeParams};

#[derive(Clone)]
pub struct Blake3MerkleConfig<F: PrimeField> {
    _field: PhantomData<F>,
}

pub type Blake3MerkleTreeParams<F> =
    MerkleTreeParams<F, Blake3CRHScheme<F>, Blake3TwoToOneCRHScheme, GenericDigest<32>>;

impl<F: PrimeField + Absorb> MerkleConfig for Blake3MerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = Blake3CRHScheme<F>;
    type TwoToOneHash = Blake3TwoToOneCRHScheme;
}

#[derive(Clone)]
pub struct Blake3CRHScheme<F: Field> {
    _f: PhantomData<F>,
}

#[derive(Debug, Default)]
pub struct HashCounter;

static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl HashCounter {
    pub(crate) fn add() -> usize {
        HASH_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    pub fn reset() {
        HASH_COUNTER.store(0, Ordering::SeqCst);
    }

    pub fn get() -> usize {
        HASH_COUNTER.load(Ordering::SeqCst)
    }
}

impl<F: Field> CRHScheme for Blake3CRHScheme<F> {
    type Input = [F];
    type Output = GenericDigest<32>;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut buf = Vec::new();
        input.borrow().serialize_compressed(&mut buf)?;

        let output: [_; 32] = blake3::hash(&buf).into();
        HashCounter::add();
        Ok(output.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3TwoToOneCRHScheme;

impl TwoToOneCRHScheme for Blake3TwoToOneCRHScheme {
    type Input = GenericDigest<32>;
    type Output = GenericDigest<32>;
    type Parameters = ();

    fn setup<R: RngCore>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        (): &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let output: [_; 32] =
            blake3::hash(&[left_input.borrow().0, right_input.borrow().0].concat()).into();
        HashCounter::add();
        Ok(output.into())
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::evaluate(parameters, left_input, right_input)
    }
}

#[cfg(test)]
mod tests {
    use super::Blake3MerkleConfig;
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::merkle_tree::MerkleTree;

    #[test]
    fn blake3_merkle_example_usage() {
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // build Merkle tree
        let mt = MerkleTree::<Blake3MerkleConfig<BLS12_381>>::new(&(), &(), &leaves).unwrap();

        // get proofs
        let proof0 = mt.generate_proof(0).unwrap();
        let proof1 = mt.generate_proof(1).unwrap();

        // verify proofs for valid leaves
        assert!(proof0.verify(&(), &(), &mt.root(), leaf0.clone()).unwrap());
        assert!(proof1.verify(&(), &(), &mt.root(), leaf1.clone()).unwrap());

        // verify proofs are not valid for other leaves
        assert!(!proof0.verify(&(), &(), &mt.root(), leaf1).unwrap());
        assert!(!proof1.verify(&(), &(), &mt.root(), leaf0).unwrap());
    }
}

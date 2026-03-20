pub mod fields;

use ark_crypto_primitives::{crh::TwoToOneCRHScheme, sponge::Absorb, Error};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use core::borrow::Borrow;

/// A generic fixed-size digest (copied from whir).
#[derive(Clone, Debug, Eq, PartialEq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct GenericDigest<const N: usize>(pub [u8; N]);

impl<const N: usize> Default for GenericDigest<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> AsRef<[u8]> for GenericDigest<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for GenericDigest<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Absorb for GenericDigest<N> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.0);
    }

    fn to_sponge_field_elements<F: ark_ff::PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from_be_bytes_mod_order(&self.0));
    }
}

/// Blake3 two-to-one hash for internal Merkle tree nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake3;

impl TwoToOneCRHScheme for Blake3 {
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

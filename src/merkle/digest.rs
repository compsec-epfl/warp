use ark_crypto_primitives::sponge::Absorb;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// This is copy/ paste from https://github.com/WizardOfMenlo/whir/blob/3d627d31cec7d73a470a31a913229dd3128ee0cf/src/crypto/merkle_tree/digest.rs

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

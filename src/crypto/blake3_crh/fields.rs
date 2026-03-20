use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use core::borrow::Borrow;
use core::marker::PhantomData;

use ark_crypto_primitives::{crh::CRHScheme, Error};

use super::GenericDigest;

/// Blake3 leaf hash that takes field elements as input.
#[derive(Clone)]
pub struct Blake3F<F: Field> {
    _f: PhantomData<F>,
}

impl<F: Field> CRHScheme for Blake3F<F> {
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
        Ok(output.into())
    }
}

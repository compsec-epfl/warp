use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::Field;

use crate::{linear_code::LinearCode, WARPError};

use spongefish::{DuplexSpongeInterface, ProverState, Unit as SpongefishUnit};
pub mod codeword_batching;
pub mod pesat;
pub mod pseudo_batching;

#[derive(Clone)]
pub struct IORConfig<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> {
    code: C,
    _f: PhantomData<F>,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> IORConfig<F, C, MT> {
    pub fn new(
        code: C,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            code,
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
            _f: PhantomData,
        }
    }
}

pub trait IOR<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config, S: DuplexSpongeInterface<F>>
{
    type Instance;
    type Witness;
    type OutputInstance;
    type OutputWitness;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState<S, F>,
        instance: Self::Instance,
        witness: Self::Witness,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError>;

    fn verify();
}

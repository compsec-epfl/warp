use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::Field;

use crate::{linear_code::LinearCode, WARPError};

use spongefish::{DuplexSpongeInterface, ProverState, Unit as SpongefishUnit};
pub mod ior_codewords_batch;
pub mod pesat;

pub struct IORConfig<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> {
    code: C,
    _f: PhantomData<F>,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

pub trait IOR<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config, S: DuplexSpongeInterface<F>>
{
    type Instance<'a>;
    type Witness<'a>;
    type OutputInstance<'a>;
    type OutputWitness<'a>;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState<S, F>,
        instance: Self::Instance<'a>,
        witness: Self::Witness<'a>,
    ) -> Result<(Self::OutputInstance<'a>, Self::OutputWitness<'a>), WARPError>;

    fn verify();
}

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;

use crate::{linear_code::LinearCode, WARPError};

use spongefish::{
    codecs::arkworks_algebra::UnitToField, ProverState, Unit as SpongefishUnit, UnitToBytes,
};

pub mod codeword_batching;
pub mod multilinear_constraint_batching;
pub mod twin_constraint_pseudo_batching;
pub mod pesat;

pub trait IORConfig {
    fn get_config(&self) -> Self;
}

pub trait IOR<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> {
    type Instance;
    type Witness;
    type OutputInstance;
    type OutputWitness;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        instance: Self::Instance,
        witness: Self::Witness,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError>
    where
        ProverState: UnitToField<F> + UnitToBytes;

    fn verify();
}

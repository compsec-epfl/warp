mod accumulator;
pub mod baseline; // TODO(z-tech): baseline behind test flag or later deleted?
pub mod warp;

pub use accumulator::RelationAccumulator;
use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
    BytesToUnitDeserialize, ProofResult, ProverState, UnitToBytes, VerifierState,
};

use crate::utils::{DigestToUnitDeserialize, DigestToUnitSerialize};

pub trait AccumulationScheme<F: Field, MT: Config> {
    type Index;
    type ProverKey;
    type VerifierKey;
    type AccumulatorInstance;
    type AccumulatorWitness;
    type Instance;
    type Witness;
    type Proof;

    // on given index, returns prover and verifier keys
    fn index(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> ProofResult<(Self::ProverKey, Self::VerifierKey)>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>;

    // prove accumulation of instances and witnesses with previous accumulators `accs`
    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Vec<Self::Witness>,
        instances: Vec<Self::Instance>,
        acc_instances: Vec<Self::AccumulatorInstance>,
        acc_witnesses: Vec<Self::AccumulatorWitness>,
    ) -> ProofResult<(
        (Self::AccumulatorInstance, Self::AccumulatorWitness),
        Self::Proof,
    )>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        prover_state: &mut VerifierState<'a>,
        acc_instance: Self::AccumulatorInstance,
        proof: Self::Proof,
    ) -> ProofResult<()>
    where
        VerifierState<'a>: UnitToBytes
            + FieldToUnitDeserialize<F>
            + UnitToField<F>
            + DigestToUnitDeserialize<MT>
            + BytesToUnitDeserialize;

    fn decide();
}

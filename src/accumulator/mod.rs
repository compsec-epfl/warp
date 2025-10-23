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

use crate::{
    utils::{DigestToUnitDeserialize, DigestToUnitSerialize},
    WARPError,
};

pub trait AccumulationScheme<F: Field, MT: Config> {
    type Index;
    type ProverKey;
    type VerifierKey;
    type AccumulatorInstances;
    type AccumulatorWitnesses;
    type Instances;
    type Witnesses;
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
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instances: Self::AccumulatorInstances,
        acc_witnesses: Self::AccumulatorWitnesses,
    ) -> Result<
        (
            (Self::AccumulatorInstances, Self::AccumulatorWitnesses),
            Self::Proof,
        ),
        WARPError,
    >
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        prover_state: &mut VerifierState<'a>,
        acc_instance: Self::AccumulatorInstances,
        proof: Self::Proof,
    ) -> Result<(), WARPError>
    where
        VerifierState<'a>: UnitToBytes
            + FieldToUnitDeserialize<F>
            + UnitToField<F>
            + DigestToUnitDeserialize<MT>
            + BytesToUnitDeserialize;

    fn decide(
        &self,
        acc_witness: Self::AccumulatorWitnesses,
        acc_instance: Self::AccumulatorInstances,
    ) -> Result<(), WARPError>;
}

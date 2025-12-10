use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
    BytesToUnitDeserialize, BytesToUnitSerialize, ProofResult, UnitToBytes,
};

use crate::utils::{
    errs::{WARPError, WARPProverError, WARPVerifierError},
    DigestToUnitDeserialize, DigestToUnitSerialize,
};

pub type WARPAccumResult<F, MT, S> = (
    (
        <S as AccumulationScheme<F, MT>>::AccumulatorInstances,
        <S as AccumulationScheme<F, MT>>::AccumulatorWitnesses,
    ),
    <S as AccumulationScheme<F, MT>>::Proof,
);

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
    fn index<ProverState>(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> ProofResult<(Self::ProverKey, Self::VerifierKey)>
    where
        ProverState: BytesToUnitSerialize + FieldToUnitSerialize<F>;

    // prove accumulation of instances and witnesses with previous accumulators `accs`
    fn prove<ProverState>(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instances: Self::AccumulatorInstances,
        acc_witnesses: Self::AccumulatorWitnesses,
    ) -> Result<WARPAccumResult<F, MT, Self>, WARPProverError>
    where
        ProverState:
            UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT> + FieldToUnitSerialize<F>;

    fn verify<VerifierState>(
        &self,
        vk: Self::VerifierKey,
        prover_state: &mut VerifierState,
        acc_instance: Self::AccumulatorInstances,
        proof: Self::Proof,
    ) -> Result<(), WARPVerifierError>
    where
        VerifierState: UnitToBytes
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

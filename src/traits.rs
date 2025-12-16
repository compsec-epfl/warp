use ark_crypto_primitives::{Error, merkle_tree::Config};
use ark_ff::Field;
use spongefish::{ProverState, VerifierState};
// use spongefish::{
//     codecs::arkworks_algebra::{FieldToUnitDeserialize, UnitToField},
//     BytesToUnitDeserialize, ProofResult, ProverState, UnitToBytes, VerifierState,
// };

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
    fn index(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), Error>
    where
        ProverState: DigestToUnitSerialize<MT>;

    // prove accumulation of instances and witnesses with previous accumulators `accs`
    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instances: Self::AccumulatorInstances,
        acc_witnesses: Self::AccumulatorWitnesses,
    ) -> Result<WARPAccumResult<F, MT, Self>, WARPProverError>
    where
        ProverState: DigestToUnitSerialize<MT>;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        prover_state: &mut VerifierState<'a>,
        acc_instance: Self::AccumulatorInstances,
        proof: Self::Proof,
    ) -> Result<(), WARPVerifierError>
    where
        VerifierState<'a>: 
            DigestToUnitDeserialize<MT>;

    fn decide(
        &self,
        acc_witness: Self::AccumulatorWitnesses,
        acc_instance: Self::AccumulatorInstances,
    ) -> Result<(), WARPError>;
}

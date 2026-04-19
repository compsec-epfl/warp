use ark_ff::PrimeField;
use spongefish::{ProverState, VerificationResult, VerifierState};

use crate::error::{VerifierError, WARPError};
use crate::types::{AccumulatorInstance, AccumulatorWitness, ProveResult, WARPProof};

pub trait AccumulationScheme<F: PrimeField> {
    type Index;
    type ProverKey;
    type VerifierKey;
    type Instances;
    type Witnesses;

    // on given index, returns prover and verifier keys
    fn index(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> VerificationResult<(Self::ProverKey, Self::VerifierKey)>;

    // prove accumulation of instances and witnesses with previous accumulators `accs`
    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instance: AccumulatorInstance<F>,
        acc_witness: AccumulatorWitness<F>,
    ) -> ProveResult<F>;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F>,
        proof: WARPProof<F>,
    ) -> Result<(), VerifierError>;

    fn decide(
        &self,
        acc_witness: AccumulatorWitness<F>,
        acc_instance: AccumulatorInstance<F>,
    ) -> Result<(), WARPError>;
}

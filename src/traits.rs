use ark_ff::PrimeField;
use spongefish::{ProverState, VerificationResult, VerifierState};

use crate::error::{VerifierError, WARPError};
use crate::hasher::WarpHasher;
use crate::types::{AccumulatorInstance, AccumulatorWitness, ProveResult, WARPProof};

pub trait AccumulationScheme<F: PrimeField, H: WarpHasher<F>> {
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
        acc_instance: AccumulatorInstance<F, H>,
        acc_witness: AccumulatorWitness<F, H>,
    ) -> ProveResult<F, H>;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F, H>,
        proof: WARPProof<F, H>,
    ) -> Result<(), VerifierError>;

    fn decide(
        &self,
        acc_witness: AccumulatorWitness<F, H>,
        acc_instance: AccumulatorInstance<F, H>,
    ) -> Result<(), WARPError>;
}

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{ProverState, VerificationResult, VerifierState};

use crate::error::{ProverError, VerifierError, WARPError};
use crate::types::{AccumulatorInstance, AccumulatorWitness, WARPProof};

pub trait AccumulationScheme<F: Field, MT: Config> {
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
        acc_instance: AccumulatorInstance<F, MT>,
        acc_witness: AccumulatorWitness<F, MT>,
    ) -> Result<
        (
            (AccumulatorInstance<F, MT>, AccumulatorWitness<F, MT>),
            WARPProof<F, MT>,
        ),
        ProverError,
    >;

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F, MT>,
        proof: WARPProof<F, MT>,
    ) -> Result<(), VerifierError>;

    fn decide(
        &self,
        acc_witness: AccumulatorWitness<F, MT>,
        acc_instance: AccumulatorInstance<F, MT>,
    ) -> Result<(), WARPError>;
}

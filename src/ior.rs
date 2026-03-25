use ark_ff::Field;
use spongefish::{ProverState, VerifierState};

use crate::error::{DeciderError, ProverError, VerifierError};

/// An interactive oracle reduction transforms a claim on an input relation
/// into a claim on an (ideally simpler) output relation,
/// through prover/verifier interaction.
///
/// This trait captures the general pattern described in the WARP paper:
///   InputRelation --IOR--> OutputRelation
///
/// The prover produces a proof alongside the output claim.
/// The verifier, given the input instance and proof, derives the output instance.
pub trait InteractiveOracleReduction<F: Field> {
    /// The relation being reduced FROM (input claim).
    type InputInstance;
    type InputWitness;

    /// The relation being reduced TO (output claim).
    type OutputInstance;
    type OutputWitness;

    /// Proof messages produced during this reduction step.
    type Proof;

    /// Parameters needed for this reduction (e.g., index, code, Merkle params).
    type Parameters;

    /// Prover side of the reduction: given an input claim (instance + witness),
    /// interact with the transcript and produce an output claim + proof.
    fn reduce_prove(
        params: &Self::Parameters,
        prover_state: &mut ProverState,
        input_instance: &Self::InputInstance,
        input_witness: &Self::InputWitness,
    ) -> Result<(Self::OutputInstance, Self::OutputWitness, Self::Proof), ProverError>;

    /// Verifier side of the reduction: given an input instance + proof,
    /// interact with the transcript and derive the output instance.
    fn reduce_verify<'a>(
        params: &Self::Parameters,
        verifier_state: &mut VerifierState<'a>,
        input_instance: &Self::InputInstance,
        proof: &Self::Proof,
    ) -> Result<Self::OutputInstance, VerifierError>;
}

/// A relation that can be checked directly without further reduction.
/// This is the "base case" — the decider checks the final accumulator.
pub trait Decidable<F: Field> {
    type Instance;
    type Witness;
    type Parameters;

    fn decide(
        params: &Self::Parameters,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Result<(), DeciderError>;
}

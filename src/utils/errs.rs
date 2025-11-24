use crate::protocol::sumcheck::{WARPSumcheckProverError, WARPSumcheckVerifierError};
use ark_crypto_primitives::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WARPProverError {
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error(transparent)]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error(transparent)]
    SpongeFishDomainSeparatorError(#[from] spongefish::DomainSeparatorMismatch),
    #[error(transparent)]
    SumcheckError(#[from] WARPSumcheckProverError),
    #[error("Expected eval, got None")]
    EmptyEval,
}

#[derive(Error, Debug)]
pub enum WARPVerifierError {
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error(transparent)]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error(transparent)]
    SpongeFishDomainSeparatorError(#[from] spongefish::DomainSeparatorMismatch),
    #[error("Invalid new code evaluation point")]
    CodeEvaluationPoint,
    #[error("Found invalid number of shift queries points")]
    NumShiftQueries,
    #[error("Found invalid shift query index")]
    ShiftQueryIndex,
    #[error("Couldn't verify shift query")]
    ShiftQuery,
    #[error("Found invalid number of l2 accumulated instances")]
    NumL2Instances,
    #[error(transparent)]
    SumcheckError(#[from] WARPSumcheckVerifierError),
}

#[derive(Error, Debug)]
pub enum WARPDeciderError {
    #[error("Invalid merkle root")]
    MerkleRoot,
    #[error("Invalid merkle trapdoor")]
    MerkleTrapDoor,
    #[error("Invalid multilinear extension evaluation")]
    MLExtensionEvaluation,
    #[error("Invalid bundled evaluation")]
    BundledEvaluation,
    #[error("Invalid encoded witness")]
    EncodedWitness,
}

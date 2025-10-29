#[doc(hidden)]
pub mod tests;

pub mod accumulator;
pub mod domainsep;
pub mod linear_code;
pub mod merkle;
pub mod relations;
pub mod sumcheck;
pub mod utils;

use ark_crypto_primitives::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WARPError {
    #[error(transparent)]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error(transparent)]
    SpongeFishDomainSeparatorError(#[from] spongefish::DomainSeparatorMismatch),
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error("Incorrect IOR config")]
    IORConfigError,
    #[error("z.len() is {0}, but tried accessing at {1}")]
    R1CSWitnessSize(usize, usize),
    #[error("Tried accessing at {1} when z.len() is {0}")]
    ZeroEvaderSize(usize, usize),
    #[error("LC does not exist")]
    R1CSNonExistingLC,
    #[error("Error decoding codeword")]
    DecodeFailed,
    #[error("Bundled PESAT eval returned {0}, multilinear evals returned {1}")]
    UnsatisfiedMultiConstraints(bool, bool),
    #[error("f.len() is {0}, but tried accessing at {1}")]
    CodewordSize(usize, usize),
    #[error("Expected eval, got None")]
    EmptyEval,
    #[error("{0}")]
    VerificationFailed(String),
    #[error(transparent)]
    VerifierError(#[from] WARPVerifierError),
    #[error(transparent)]
    DeciderError(#[from] WARPDeciderError),
}

#[derive(Error, Debug)]
pub enum WARPVerifierError {
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
    #[error("Found invalid number of sumcheck rounds")]
    NumSumcheckRounds,
    #[error("Sumcheck round verification failed")]
    SumcheckRound,
    #[error("Incorrect target")]
    Target,
}

#[derive(Error, Debug)]
pub enum WARPDeciderError {
    #[error("Invalid merkle root")]
    MerkleRoot,
    #[error("Invalid multilinear extension evaluation")]
    MLExtensionEvaluation,
    #[error("Invalid bundled evaluation")]
    BundledEvaluation,
    #[error("Invalid encoded witness")]
    EncodedWitness,
}

pub fn concat_slices<F: Clone>(a: &Vec<F>, b: &Vec<F>) -> Vec<F> {
    let mut v = Vec::<F>::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

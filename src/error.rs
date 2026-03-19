use ark_crypto_primitives::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WARPError {
    #[error(transparent)]
    ProverError(#[from] ProverError),
    #[error(transparent)]
    VerifierError(#[from] VerifierError),
    #[error(transparent)]
    DeciderError(#[from] DeciderError),
    #[error(transparent)]
    ArkError(#[from] Error),
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
}

#[derive(Error, Debug)]
pub enum ProverError {
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error("Spongefish verification error")]
    SpongeFish,
    #[error("Expected eval, got None")]
    EmptyEval,
}

impl From<spongefish::VerificationError> for ProverError {
    fn from(_: spongefish::VerificationError) -> Self {
        Self::SpongeFish
    }
}

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error("Spongefish verification error")]
    SpongeFish,
    #[error("Invalid new code evaluation point")]
    CodeEvaluationPoint,
    #[error("Invalid new circuit evaluation point")]
    CircuitEvaluationPoint,
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

impl From<spongefish::VerificationError> for VerifierError {
    fn from(_: spongefish::VerificationError) -> Self {
        Self::SpongeFish
    }
}

#[derive(Error, Debug)]
pub enum DeciderError {
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

use ark_crypto_primitives::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WarpError {
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
    #[error("R1CS construction: {reason}")]
    R1CSConstruction { reason: &'static str },
}

#[derive(Error, Debug)]
pub enum ProverError {
    #[error(transparent)]
    ArkError(#[from] Error),
    #[error("Spongefish verification error")]
    SpongeFish,
    #[error("instance batch must contain at least 2 instances; got {got}")]
    InsufficientInstances { got: usize },
    #[error("instances.len() ({instances}) != witnesses.len() ({witnesses})")]
    InstanceWitnessLengthMismatch { instances: usize, witnesses: usize },
    #[error("acc_witness.td_committed_codewords.len() ({roots}) != acc_instance.rt_merkle_roots.len() ({instances})")]
    AccumulatorShapeMismatch { instances: usize, roots: usize },
    #[error("config parameter invalid: {reason}")]
    ConfigParameterInvalid { reason: String },
    #[error("instance length mismatch: expected {expected}, got {got}")]
    InstanceLengthMismatch { expected: usize, got: usize },
    #[error("statement layout mismatch: {what} expected {expected}, got {got}")]
    StatementShape {
        what: &'static str,
        expected: usize,
        got: usize,
    },
}

impl From<spongefish::VerificationError> for ProverError {
    fn from(_: spongefish::VerificationError) -> Self {
        Self::SpongeFish
    }
}

impl From<ark_iop::IorProverError> for ProverError {
    fn from(e: ark_iop::IorProverError) -> Self {
        match e {
            ark_iop::IorProverError::StatementShape {
                what,
                expected,
                got,
            } => Self::StatementShape {
                what,
                expected,
                got,
            },
            ark_iop::IorProverError::Transcript(_) => Self::SpongeFish,
            ark_iop::IorProverError::Custom(msg) => Self::ConfigParameterInvalid { reason: msg },
        }
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
    #[error("statement layout mismatch: {what} expected {expected}, got {got}")]
    StatementShape {
        what: &'static str,
        expected: usize,
        got: usize,
    },
}

impl From<spongefish::VerificationError> for VerifierError {
    fn from(_: spongefish::VerificationError) -> Self {
        Self::SpongeFish
    }
}

impl From<ark_iop::IorVerifierError> for VerifierError {
    fn from(e: ark_iop::IorVerifierError) -> Self {
        match e {
            ark_iop::IorVerifierError::StatementShape {
                what,
                expected,
                got,
            } => Self::StatementShape {
                what,
                expected,
                got,
            },
            ark_iop::IorVerifierError::Target => Self::Target,
            ark_iop::IorVerifierError::Transcript(_) => Self::SpongeFish,
            ark_iop::IorVerifierError::Custom(_) => Self::Target,
        }
    }
}

impl From<effsc::proof::SumcheckError> for VerifierError {
    fn from(err: effsc::proof::SumcheckError) -> Self {
        use effsc::proof::SumcheckError;
        match err {
            // Round consistency or degree checks failed inside the library.
            SumcheckError::ConsistencyCheck { .. } | SumcheckError::DegreeMismatch { .. } => {
                Self::SumcheckRound
            }
            // The caller-supplied oracle_check (the final-claim equality)
            // rejected — surfaces as warp's `Target` variant for backwards
            // compatibility with the existing negative tests.
            SumcheckError::FinalEvaluation => Self::Target,
            // Ran out of transcript or malformed bytes.
            SumcheckError::TranscriptError { .. } => Self::SpongeFish,
            // Not reachable: warp passes `noop_hook_verify`.
            SumcheckError::HookError { .. } => Self::SumcheckRound,
        }
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

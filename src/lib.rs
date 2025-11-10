#[doc(hidden)]
pub mod tests;

pub mod accumulator;
pub mod domainsep;
pub mod fields;
pub mod linear_code;
pub mod merkle;
pub mod relations;
pub mod sumcheck;
pub mod utils;

use ark_crypto_primitives::Error;
use thiserror::Error;
use utils::errs::{WARPDeciderError, WARPProverError, WARPVerifierError};

#[derive(Error, Debug)]
pub enum WARPError {
    #[error(transparent)]
    ProverError(#[from] WARPProverError),
    #[error(transparent)]
    VerifierError(#[from] WARPVerifierError),
    #[error(transparent)]
    DeciderError(#[from] WARPDeciderError),
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

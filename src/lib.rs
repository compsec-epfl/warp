pub mod accumulator;
pub mod iors;
pub mod linear_code;
pub mod merkle;
pub mod relations;
pub mod utils;

use ark_crypto_primitives::Error;
use spongefish::ProofError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WARPError {
    #[error("{0}")]
    ProofError(#[from] ProofError),
    #[error("{0}")]
    ArkError(#[from] Error),
    #[error("Incorrect IOR config")]
    IORConfigError,
    #[error("Tried accessing at {1} when z.len() is {0}")]
    R1CSWitnessSize(usize, usize),
    #[error("LC does not exist")]
    R1CSNonExistingLC,
}

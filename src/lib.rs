pub mod accumulator;
pub mod domainsep;
pub mod iors;
pub mod linear_code;
pub mod merkle;
pub mod relations;
pub mod sumcheck;
pub mod utils;

use ark_crypto_primitives::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WARPError {
    #[error("{0}")]
    SpongeFishProofError(#[from] spongefish::ProofError),
    #[error("{0}")]
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
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

pub fn concat_slices<F: Clone>(a: &Vec<F>, b: &Vec<F>) -> Vec<F> {
    let mut v = Vec::<F>::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

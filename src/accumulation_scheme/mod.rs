//! WarpAccumulationScheme accumulation scheme: the `AccumulationScheme` trait (in [`trait_def`])
//! and WarpAccumulationScheme's implementation of it (orchestration in [`prove`] / [`verify`],
//! decider + IOP/AccumulationScheme trait impls in [`iop`], plus types
//! [`scheme`], [`accumulator`], [`keys`], [`params`], [`proof`]).

pub mod accumulator;
pub mod iop;
pub mod keys;
pub mod params;
pub mod proof;
pub mod prove;
pub mod scheme;
pub mod trait_def;
pub mod transcript;
pub mod verify;

pub use accumulator::{AccumulatorInstance, AccumulatorWitness};
pub use keys::{WarpProverKey, WarpVerifierKey};
pub use params::WarpParams;
pub use proof::{ProveResult, WarpProof};
pub use scheme::WarpAccumulationScheme;
pub use trait_def::AccumulationScheme;

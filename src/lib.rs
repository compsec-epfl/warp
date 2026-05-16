//! Warp accumulation scheme: folds R1CS instances into a sublinear-to-check
//! accumulator. Per round runs six IORs (`Pesat` → `TwinConstraint` → `Bridge`
//! → `Ood` → `SampleQueries` → `Batching`) through a Fiat-Shamir transcript,
//! plus an FS-transparent `Proximity` step for the openings. Entry point:
//! [`WarpAccumulationScheme`].

pub mod accumulation_scheme;
pub mod config;
pub mod crypto;
pub mod error;
pub mod iop;
pub mod params;
pub mod profile;
pub mod relations;
pub mod serialize;
pub mod utils;

pub use crate::accumulation_scheme::{
    AccumulationScheme, AccumulatorInstance, AccumulatorWitness, WarpAccumulationScheme,
    WarpProof, WarpProverKey, WarpVerifierKey,
};
pub use crate::config::WarpConfig;
pub use crate::error::{DeciderError, ProverError, VerifierError, WarpError};
pub use crate::iop::{IorSchema, ProtocolSchema};

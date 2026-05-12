pub mod accumulation;
pub mod config;
pub mod constraints;
pub mod crypto;
pub mod error;
pub mod params;
pub mod profile;
pub mod protocol;
pub mod relations;
pub mod serialize;
pub mod utils;
pub mod warp;

/// Re-exports the handful of items every WARP consumer needs. Use as
/// `use warp::prelude::*;`.
pub mod prelude {
    pub use crate::accumulation::AccumulationScheme;
    pub use crate::config::WARPConfig;
    pub use crate::error::{DeciderError, ProverError, VerifierError, WARPError};
    pub use crate::warp::{
        AccumulatorInstance, AccumulatorWitness, WARPProof, WARPProverKey, WARPVerifierKey, WARP,
    };
}

pub use crate::warp::WARP;

//! # WarpAccumulationScheme — accumulation scheme with code-based commitments
//!
//! WarpAccumulationScheme folds many R1CS instances into a single, sub-linear-to-check accumulator.
//! Per accumulation round it runs six IORs (Interactive Oracle Reductions) in
//! order through a Fiat-Shamir transcript, producing a new accumulator and a
//! per-round proof. A separate [`WarpAccumulationScheme::decide`] step closes the accumulator.
//!
//! Entry point: [`WarpAccumulationScheme`]. The same type implements [`ark_iop::IOP`]
//! (per-round protocol identity) and [`crate::accumulation_scheme::AccumulationScheme`]
//! (split-accumulation wrapper). One value, two traits.
//!
//! ## End-to-end flow
//!
//! ```text
//! WarpAccumulationScheme::prove   ──▶ ((AccumulatorInstance, AccumulatorWitness), WarpProof)
//! WarpAccumulationScheme::verify  ──▶ accept the new accumulator instance (or reject)
//! WarpAccumulationScheme::decide  ──▶ close the accumulator (final accept / reject)
//! ```
//!
//! See `examples/hash_chain.rs` for a runnable end-to-end example.
//!
//! ## Where to look
//!
//! - [`WarpAccumulationScheme`] (`src/accumulation_scheme/scheme.rs`) — the scheme value carrying code, ck, predicate.
//! - [`accumulation_scheme::iop`](`crate::accumulation_scheme::iop`) (`src/accumulation_scheme/iop.rs`) —
//!   `IOP` + `AccumulationScheme` impls on `WarpAccumulationScheme`. Names the ordered IOR list and provides
//!   the FS prologue + decider.
//! - [`accumulation_scheme::trait_def`](`crate::accumulation_scheme::trait_def`)
//!   (`src/accumulation_scheme/trait_def.rs`) — the `AccumulationScheme` trait itself,
//!   warp-local for now (slated for upstream to `ark-iop` when a second accumulating
//!   consumer arrives).
//! - [`iop::iors`](`crate::iop::iors`) (`src/iop/iors/`) — the six IORs run per round,
//!   in this order: `Pesat` → `TwinConstraint` → `Bridge` → `Ood` → `SampleQueries`
//!   → `Batching`. Plus `Proximity` (FS-transparent).
//!
//! ## Fiat-Shamir hygiene (structural)
//!
//! Two parity invariants are compiled in via [`ark_iop`]:
//!
//! 1. **Reduction parity** — `IOR::compose_prove` / `compose_verify` are
//!    the only legal constructors of result types; both funnel through
//!    `reduce_statement`.
//! 2. **Message-order parity** — every IOR declares `const MESSAGE_TAGS`;
//!    `compose_*` absorbs them as an FS prologue. The outer scheme adds
//!    `AccumulationScheme::absorb_scheme_prologue_*` for the protocol-map
//!    domain separator.

pub mod accumulation_scheme;
pub mod config;
pub mod constraints;
pub mod crypto;
pub mod error;
pub mod iop;
pub mod params;
pub mod profile;
pub mod relations;
pub mod serialize;
pub mod utils;

pub use crate::accumulation_scheme::{
    AccumulatorInstance, AccumulatorWitness, WarpAccumulationScheme, WarpProof, WarpProverKey,
    WarpVerifierKey,
};
pub use crate::config::WarpConfig;
pub use crate::error::{DeciderError, ProverError, VerifierError, WarpError};

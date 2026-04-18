//! Warp IOR phases as first-class modules.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (shared Oracle composition)
//! and the forthcoming `docs/paper-mods/mod2_structured_sumcheck.tex`,
//! `mod3_accumulator_state.tex`.
//!
//! Each submodule implements one IOR from the Warp construction. The phase
//! functions are concrete (no `IOR` trait) but share a consistent shape:
//!
//! - **prove**: takes the current prover state, the accumulator, and any
//!   fresh inputs; runs the IOR's prover; returns the reduced claim and any
//!   emitted [`Oracle`](super::oracle::Oracle)s.
//! - **verify** (where applicable): consumes a subset of
//!   `DerivedRandomness` plus the prior claim; returns the reduced claim.
//!
//! The top-level orchestrators live in `src/lib.rs::WARP::prove` and
//! `::verify`, which thread state between phases.

pub mod batching;
pub mod ood;
pub mod pesat;
pub mod proximity;
pub mod twin_constraint;

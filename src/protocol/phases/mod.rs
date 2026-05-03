//! Warp IOR phases as first-class modules.
//!
//! Paired spec: `docs/paper-mods/mod3_accumulator_state.tex` (forthcoming) —
//! the accumulator-as-state framing where each phase is a typed transition
//! in the protocol.
//!
//! Each submodule implements one IOR from the Warp construction. They share
//! a consistent shape, lifted into the [`ProverPhase`] / [`VerifierPhase`]
//! traits below: a phase is a struct that captures the static / borrowed
//! context it needs (codes, R1CS, merkle params, residues from upstream
//! phases), consumed by `prove` / `verify` along with a shared transcript
//! handle.
//!
//! The top-level orchestrators in `src/lib.rs::WARP::prove` and `::verify`
//! thread state between phases by chaining `Phase::prove` / `Phase::verify`
//! calls — each phase's typed [`Output`](ProverPhase::Output) feeds the next
//! phase's struct.
//!
//! The traits cover what is genuinely uniform across phases (consume static
//! context + transcript → produce typed residue). Verifier-side phases like
//! "derive transcript randomness" that are pure plumbing are not wrapped in
//! `VerifierPhase` — they live in `src/protocol/transcript` and are called
//! directly from the orchestrator.

pub mod batching;
pub mod ood;
pub mod pesat;
pub mod proximity;
pub mod twin_constraint;

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};

/// Prover-side IOR phase.
///
/// Implementors are structs whose fields hold the borrowed context the phase
/// needs. `prove` consumes the phase struct together with the shared
/// `ProverState`, returns a typed [`Output`](Self::Output) residue threaded
/// forward to downstream phases.
pub trait ProverPhase {
    type Output;
    fn prove(self, prover_state: &mut ProverState) -> Result<Self::Output, ProverError>;
}

/// Verifier-side IOR phase.
///
/// Mirrors [`ProverPhase`] for the verifier. Phases whose verifier counterpart
/// is purely transcript-derived (PESAT, OOD) skip this trait — the orchestrator
/// reads the relevant randomness via helpers in `src/protocol/transcript`.
pub trait VerifierPhase {
    type Output;
    fn verify<'a>(
        self,
        verifier_state: &mut VerifierState<'a>,
    ) -> Result<Self::Output, VerifierError>;
}

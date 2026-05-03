//! Warp IOR phases as first-class modules.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (composition rule) and the
//! forthcoming `docs/paper-mods/mod3_accumulator_state.tex`.
//!
//! Each submodule implements one Interactive Oracle Reduction from the Warp
//! construction. The [`IOR`] trait below names the five paper-level
//! components — Statement, Witness, InputOracles, ReducedStatement,
//! OutputOracles — and splits oracle types into prover-side (full data) /
//! verifier-side (commitments) halves so the trait can serve both roles
//! against the same struct.
//!
//! Implementor pattern: a phase is a struct holding setup parameters
//! (codes, merkle hash params); `prove` and `verify` are `&self` methods
//! that take statement / witness / inputs per call and return reduced
//! statement + output oracles.
//!
//! The top-level orchestrators in `src/lib.rs::WARP::prove` and `::verify`
//! thread state between phases by chaining `IOR::prove` / `IOR::verify`
//! calls — each phase's `ReducedStatement` and `Outputs` feed the next
//! phase's `Statement` / `Inputs`.

pub mod batching;
pub mod ood;
pub mod pesat;
pub mod proximity;
pub mod twin_constraint;

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};

/// Interactive Oracle Reduction.
///
/// Mirrors the IOR signature from `docs/paper-mods/mod1_oracle.tex` §4:
///
/// ```text
///   (stmt, wit, oracles_in)  -->  (stmt', oracles_out)
/// ```
///
/// Seven associated types decompose the paper's tripartite split:
///
/// - `Statement` / `ReducedStatement` are shared between prover and verifier
///   (what's claimed before and after the reduction).
/// - `Witness` is prover-only.
/// - Oracle types are split per role: the prover sees full evaluation data
///   (`ProverInputs` / `ProverOutputs`); the verifier sees commitments
///   (`VerifierInputs` / `VerifierOutputs`). For phases that don't pass any
///   oracle through one role, use `()`.
pub trait IOR {
    /// Pre-reduction claim. Visible to prover and verifier.
    type Statement;
    /// Prover-only inputs (full witness data, etc.).
    type Witness;
    /// Oracles flowing in from upstream IORs (prover view: full data).
    type ProverInputs;
    /// Oracles flowing in from upstream IORs (verifier view: commitments).
    type VerifierInputs;
    /// Post-reduction claim. Visible to prover and verifier.
    type ReducedStatement;
    /// Oracles emitted by this IOR (prover view: full data, plus any private
    /// reduced witness state).
    type ProverOutputs;
    /// Oracles emitted by this IOR (verifier view: commitments).
    type VerifierOutputs;

    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        witness: Self::Witness,
        inputs: Self::ProverInputs,
    ) -> Result<(Self::ReducedStatement, Self::ProverOutputs), ProverError>;

    fn verify<'a>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement,
        inputs: Self::VerifierInputs,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError>;
}

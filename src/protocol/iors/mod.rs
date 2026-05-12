//! Warp IOR phases as first-class modules.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex` (composition rule) and the
//! forthcoming `docs/paper-mods/mod3_accumulator_state.tex`.
//!
//! Each submodule implements one Interactive Oracle Reduction from the Warp
//! construction. The [`IOR`] trait below names the paper-level components
//! and splits oracle types into prover-side / verifier-side halves so the
//! trait can serve both roles against the same struct.
//!
//! Implementor pattern: a phase is a struct holding setup parameters
//! (codes, hashers); implementors write [`IOR::prove_inner`],
//! [`IOR::verify_inner`], and [`IOR::reduce_statement`]. The trait provides
//! default `prove` / `verify` that mechanically chain
//! `*_inner -> reduce_statement` so the prover and verifier *cannot* drift
//! on how `ReducedStatement` is computed from transcript data.
//!
//! The top-level orchestrators in `src/lib.rs::WARP::prove` and `::verify`
//! thread state between phases by chaining `IOR::prove` / `IOR::verify`
//! calls — each phase's `ReducedStatement`, `ProofString`, and
//! `ReducedWitness` feed the next phase's `Statement` / `ProverInputs` /
//! the global proof object.

// `prove_inner` returns the 3-tuple `(ReductionInputs, ProofString,
// ReducedWitness)`; clippy flags the resulting type as "complex" but
// the structure is exactly what the IOR formalism asks for.
#![allow(clippy::type_complexity)]

pub mod batching;
pub mod bridge;
pub mod ood;
pub mod oracle_handle;
pub mod pesat;
pub mod proximity;
pub mod sample_queries;
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
/// **Convention.** `Witness` and `ProverInputs` are conventionally
/// reference-holding wrappers (e.g. `PesatWitness<'a, F> { witnesses:
/// &'a [Vec<F>] }`). The trait takes them by `&` so the caller never has
/// to clone bulk data on the way in. None of WARP / WHIR / STIR / FRI /
/// sumcheck-based protocols consume their witness at the IOR level.
///
/// **Drift prevention.** Implementors write [`prove_inner`],
/// [`verify_inner`], and [`reduce_statement`]. The default `prove` /
/// `verify` chain them automatically; the `ReducedStatement` is computed
/// in exactly one place (`reduce_statement`), eliminating the bug class
/// where prover and verifier compute the same reduction via parallel
/// code paths that silently diverge.
pub trait IOR {
    /// Human-readable identifier — the WARP paper's name for the IOR.
    const NAME: &'static str;

    /// Pre-reduction claim. Visible to prover and verifier. GAT so the
    /// statement may borrow from upstream-IOR outputs.
    type Statement<'a>
    where
        Self: 'a;
    /// Prover-only data the prover reads.
    type Witness<'a>
    where
        Self: 'a;
    /// Oracles flowing in from upstream IORs (prover view: full data).
    type ProverInputs<'a>
    where
        Self: 'a;
    /// Oracles flowing in from upstream IORs (verifier view: commitments).
    type VerifierInputs<'a>
    where
        Self: 'a;
    /// Explicit inputs that determine [`Self::ReducedStatement`]. Both
    /// prover-side and verifier-side machinery produce this struct, then
    /// hand it to [`Self::reduce_statement`] for the (single) statement
    /// derivation.
    type ReductionInputs;
    /// Post-reduction claim. Visible to prover and verifier. Computed
    /// exclusively by [`Self::reduce_statement`].
    type ReducedStatement;
    /// Out-of-band proof bytes the verifier always reads (auth paths,
    /// shift-query answers, …). The orchestrator collects these into the
    /// global proof object.
    type ProofString;
    /// Reduced-witness handoff to the next IOR — full prover-side data
    /// (oracles, witness vectors, committed trees). In terminal-round
    /// protocols (e.g. WHIR's final fold) this can also be revealed to
    /// the verifier; the trait does not assume it is private.
    type ReducedWitness;
    /// Verifier-side outputs (commitments, parsed digests). Threaded into
    /// downstream IORs' `VerifierInputs`.
    type VerifierOutputs;

    /// THE single source of truth for `ReducedStatement`.
    ///
    /// Both prover and verifier call this with their respective
    /// [`Self::ReductionInputs`] (assembled in `prove_inner` /
    /// `verify_inner`). Drift between sides is structurally impossible
    /// because both go through this function.
    fn reduce_statement<'a>(
        &self,
        statement: &Self::Statement<'a>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'a;

    /// Implementor's prover-side body. Runs the protocol's prover
    /// machinery and returns the inputs `reduce_statement` needs, plus
    /// the proof string and reduced witness.
    fn prove_inner<'a>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'a>,
        witness: &Self::Witness<'a>,
        inputs: &Self::ProverInputs<'a>,
    ) -> Result<
        (
            Self::ReductionInputs,
            Self::ProofString,
            Self::ReducedWitness,
        ),
        ProverError,
    >
    where
        Self: 'a;

    /// Implementor's verifier-side body. Runs the protocol's verifier
    /// machinery (sumcheck checks, transcript reads, soundness checks)
    /// and returns the inputs `reduce_statement` needs.
    fn verify_inner<'a, 'b>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement<'b>,
        inputs: &Self::VerifierInputs<'b>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'b;

    /// Default impl. Implementors should not override.
    fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'a>,
        witness: &Self::Witness<'a>,
        inputs: &Self::ProverInputs<'a>,
    ) -> Result<
        (
            Self::ReducedStatement,
            Self::ProofString,
            Self::ReducedWitness,
        ),
        ProverError,
    >
    where
        Self: 'a,
    {
        let (red_inputs, proof, red_wit) =
            self.prove_inner(prover_state, statement, witness, inputs)?;
        let reduced = self.reduce_statement(statement, &red_inputs);
        Ok((reduced, proof, red_wit))
    }

    /// Default impl. Implementors should not override.
    fn verify<'a, 'b>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement<'b>,
        inputs: &Self::VerifierInputs<'b>,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError>
    where
        Self: 'b,
    {
        let (red_inputs, vouts) = self.verify_inner(verifier_state, statement, inputs)?;
        let reduced = self.reduce_statement(statement, &red_inputs);
        Ok((reduced, vouts))
    }
}

// ─── Choreography-syntax helpers ─────────────────────────────────────────
//
// These wrap the trait's tuple return into named-field structs so
// `lib.rs` can destructure `reduced` / `proof` / `witness` by name. The
// IOR trait itself stays formal (Statement / Witness / ProverInputs /
// ReductionInputs / ReducedStatement / ProofString / ReducedWitness /
// VerifierOutputs); these are pure call-site syntax sugar.

/// Generic destructuring carrier for `IOR::prove`. The macro
/// [`prove_ior!`] returns this so callers can write
/// `let IorProveResult { reduced, proof, witness } = prove_ior!(...)?;`.
pub struct IorProveResult<R, P, W> {
    pub reduced: R,
    pub proof: P,
    pub witness: W,
}

/// Generic destructuring carrier for `IOR::verify`.
pub struct IorVerifyResult<R, V> {
    pub reduced: R,
    pub outputs: V,
}

/// Calls `IOR::prove` on the given IOR and packages the `(reduced,
/// proof, witness)` tuple into a named-field [`IorProveResult`].
///
/// ```ignore
/// let IorProveResult {
///     reduced: PesatReducedStatement { mus, taus },
///     proof: _,
///     witness: PesatReducedWitness { codewords, td_0 },
/// } = prove_ior!(
///     pesat_ior,
///     prover_state,
///     statement: PesatStatement { l1, log_m },
///     witness: PesatWitness { witnesses: &witnesses },
///     inputs: (),
/// )?;
/// ```
#[macro_export]
macro_rules! prove_ior {
    (
        $ior:expr,
        $transcript:expr,
        statement: $statement:expr,
        witness: $witness:expr,
        inputs: $inputs:expr $(,)?
    ) => {{
        let __stmt = $statement;
        let __wit = $witness;
        let __ins = $inputs;
        $crate::protocol::iors::IOR::prove(&$ior, $transcript, &__stmt, &__wit, &__ins).map(
            |(reduced, proof, witness)| $crate::protocol::iors::IorProveResult {
                reduced,
                proof,
                witness,
            },
        )
    }};
}

/// Calls `IOR::verify` on the given IOR and packages the `(reduced,
/// outputs)` tuple into a named-field [`IorVerifyResult`].
#[macro_export]
macro_rules! verify_ior {
    (
        $ior:expr,
        $transcript:expr,
        statement: $statement:expr,
        inputs: $inputs:expr $(,)?
    ) => {{
        let __stmt = $statement;
        let __ins = $inputs;
        $crate::protocol::iors::IOR::verify(&$ior, $transcript, &__stmt, &__ins).map(
            |(reduced, outputs)| $crate::protocol::iors::IorVerifyResult { reduced, outputs },
        )
    }};
}

//! Warp's Interactive Oracle Reductions. Paired spec:
//! `docs/paper-mods/mod1_oracle.tex`.

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

/// Interactive Oracle Reduction. `(stmt, wit, oracles_in) -> (stmt',
/// oracles_out)`. Implementors write `prove_inner` / `verify_inner` /
/// `reduce_statement`; the default `prove` / `verify` chain them so the
/// reduced statement is computed in one place and prover/verifier
/// cannot drift.
pub trait IOR {
    const NAME: &'static str;

    type Statement<'a>
    where
        Self: 'a;
    type Witness<'a>
    where
        Self: 'a;
    type ProverInputs<'a>
    where
        Self: 'a;
    type VerifierInputs<'a>
    where
        Self: 'a;
    type ReductionInputs;
    type ReducedStatement;
    type ProofString;
    type ReducedWitness;
    type VerifierOutputs;

    /// Single source of truth: both sides feed their `ReductionInputs` here.
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
// Call-site sugar: the macros wrap the trait's tuple return into the
// named-field structs below so `lib.rs` can destructure by name.

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

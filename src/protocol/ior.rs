//! The Interactive Oracle Reduction abstraction. Paired spec:
//! `docs/paper-mods/mod1_oracle.tex`.

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};

/// Return type of [`IOR::prove_inner`] / [`IOR::prove`]:
/// `Result<(stmt-like, proof-string, reduced-witness), _>`.
pub type ProverTriple<A, P, W> = Result<(A, P, W), ProverError>;

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

    fn prove_inner<'a>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'a>,
        witness: &Self::Witness<'a>,
        inputs: &Self::ProverInputs<'a>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'a;

    fn verify_inner<'a, 'b>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement<'b>,
        inputs: &Self::VerifierInputs<'b>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'b;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'a>,
        witness: &Self::Witness<'a>,
        inputs: &Self::ProverInputs<'a>,
    ) -> ProverTriple<Self::ReducedStatement, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'a,
    {
        let (red_inputs, proof, red_wit) =
            self.prove_inner(prover_state, statement, witness, inputs)?;
        let reduced = self.reduce_statement(statement, &red_inputs);
        Ok((reduced, proof, red_wit))
    }

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

/// Destructuring carrier for [`IOR::prove`].
pub struct IorProveResult<R, P, W> {
    pub reduced: R,
    pub proof: P,
    pub witness: W,
}

/// Destructuring carrier for [`IOR::verify`].
pub struct IorVerifyResult<R, V> {
    pub reduced: R,
    pub outputs: V,
}

/// Call `IOR::prove` and package the `(reduced, proof, witness)` tuple
/// into a named-field [`IorProveResult`].
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
        $crate::protocol::ior::IOR::prove(&$ior, $transcript, &__stmt, &__wit, &__ins).map(
            |(reduced, proof, witness)| $crate::protocol::ior::IorProveResult {
                reduced,
                proof,
                witness,
            },
        )
    }};
}

/// Call `IOR::verify` and package the `(reduced, outputs)` tuple into a
/// named-field [`IorVerifyResult`].
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
        $crate::protocol::ior::IOR::verify(&$ior, $transcript, &__stmt, &__ins)
            .map(|(reduced, outputs)| $crate::protocol::ior::IorVerifyResult { reduced, outputs })
    }};
}

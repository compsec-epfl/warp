//! Out-of-domain sampling phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`. This phase is a thin
//! composition of point queries on the committed oracle — see
//! [`Oracle::query_at_point`](crate::protocol::oracle::Oracle::query_at_point).
//! The verifier derives the same random points from the transcript.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(s, log_n)`
//! - `Witness`          — `()`
//! - `ProverInputs`     — `&Oracle<F>` (the committed oracle, full data)
//! - `VerifierInputs`   — `()` (the oracle check is deferred to the batching
//!   sumcheck's final claim)
//! - `ReducedStatement` — `(samples_flat, answers)` — query points + their answers
//! - `ProverOutputs`    — `()`
//! - `VerifierOutputs`  — `()`

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::phases::IOR;

pub struct OodStatement {
    pub s: usize,
    pub log_n: usize,
}

pub struct OodProverInputs<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
}

pub struct OodReducedStatement<F: Field> {
    /// Flat challenge vector of length `s · log_n`.
    pub samples_flat: Vec<F>,
    /// Answers `\hat f(ζ_j)` for each of the `s` chunked challenges.
    pub answers: Vec<F>,
}

/// OOD phase configuration. Stateless; the lifetime parameter exists only
/// to anchor `ProverInputs<'a>` for the trait impl.
pub struct Ood<'a, F: Field> {
    pub _phantom: PhantomData<&'a F>,
}

impl<'a, F: Field> Ood<'a, F> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: Field> Default for Ood<'a, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, F> IOR for Ood<'a, F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    type Statement = OodStatement;
    type Witness = ();
    type ProverInputs = OodProverInputs<'a, F>;
    type VerifierInputs = ();
    type ReducedStatement = OodReducedStatement<F>;
    type ProverOutputs = ();
    type VerifierOutputs = ();

    #[tracing::instrument(name = "ood", skip_all, fields(s = statement.s, log_n = statement.log_n))]
    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        _witness: Self::Witness,
        inputs: Self::ProverInputs,
    ) -> Result<(Self::ReducedStatement, Self::ProverOutputs), ProverError> {
        let samples_flat = prover_state.verifier_messages_vec::<F>(statement.s * statement.log_n);
        count_ops!(OodPointQueries, statement.s as u64);
        let answers = samples_flat
            .chunks(statement.log_n)
            .map(|zeta| inputs.oracle.query_at_point(zeta))
            .collect::<Vec<F>>();
        prover_state.prover_messages(&answers);
        Ok((
            OodReducedStatement {
                samples_flat,
                answers,
            },
            (),
        ))
    }

    #[tracing::instrument(
        name = "ood.verify",
        skip_all,
        fields(s = statement.s, log_n = statement.log_n)
    )]
    fn verify<'b>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement,
        _inputs: Self::VerifierInputs,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError> {
        let samples_flat: Vec<F> = (0..statement.s * statement.log_n)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        let answers: Vec<F> = verifier_state.prover_messages_vec(statement.s)?;
        Ok((
            OodReducedStatement {
                samples_flat,
                answers,
            },
            (),
        ))
    }
}

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
//! - `ReductionInputs`  — `(samples_flat, answers)` — both sides arrive here
//!   from the same transcript reads and feed into `reduce_statement`.
//! - `ReducedStatement` — `(samples_flat, answers)` — query points + their answers
//! - `ProofString`      — `()`
//! - `ReducedWitness`   — `()`
//! - `VerifierOutputs`  — `()`

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::iors::IOR;

pub struct OodStatement {
    pub s: usize,
    pub log_n: usize,
}

pub struct OodProverInputs<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
}

pub struct OodReductionInputs<F: Field> {
    pub samples_flat: Vec<F>,
    pub answers: Vec<F>,
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
    const NAME: &'static str = "OOD";

    type Statement<'b>
        = OodStatement
    where
        Self: 'b;
    type Witness<'b>
        = ()
    where
        Self: 'b;
    type ProverInputs<'b>
        = OodProverInputs<'b, F>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ()
    where
        Self: 'b;
    type ReductionInputs = OodReductionInputs<F>;
    type ReducedStatement = OodReducedStatement<F>;
    type ProofString = ();
    type ReducedWitness = ();
    type VerifierOutputs = ();

    fn reduce_statement<'b>(
        &self,
        _statement: &Self::Statement<'b>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
        OodReducedStatement {
            samples_flat: inputs.samples_flat.clone(),
            answers: inputs.answers.clone(),
        }
    }

    #[tracing::instrument(name = "ood", skip_all, fields(s = statement.s, log_n = statement.log_n))]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        _witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> Result<
        (
            Self::ReductionInputs,
            Self::ProofString,
            Self::ReducedWitness,
        ),
        ProverError,
    >
    where
        Self: 'b,
    {
        let samples_flat = prover_state.verifier_messages_vec::<F>(statement.s * statement.log_n);
        count_ops!(OodPointQueries, statement.s as u64);
        let answers = samples_flat
            .chunks(statement.log_n)
            .map(|zeta| inputs.oracle.query_at_point(zeta))
            .collect::<Vec<F>>();
        prover_state.prover_messages(&answers);
        Ok((
            OodReductionInputs {
                samples_flat,
                answers,
            },
            (),
            (),
        ))
    }

    #[tracing::instrument(
        name = "ood.verify",
        skip_all,
        fields(s = statement.s, log_n = statement.log_n)
    )]
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        _inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
    {
        let samples_flat: Vec<F> = (0..statement.s * statement.log_n)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        let answers: Vec<F> = verifier_state.prover_messages_vec(statement.s)?;
        Ok((
            OodReductionInputs {
                samples_flat,
                answers,
            },
            (),
        ))
    }
}

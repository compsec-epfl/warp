//! Shift-query sampling phase.
//!
//! Between OOD and Batching, the verifier draws `t · log_n` random
//! bits and decodes them into `t` shift-query positions over
//! `{0, 1}^log_n`, plus their corresponding evaluation-point vectors.
//!
//! This is the simplest possible IOR — one round of pure verifier
//! randomness, no prover messages, no oracles. Modeled as an IOR for
//! uniformity with the rest of the choreography.
//!
//! IOR ports
//! ---------
//! - input (prover): `{ log_n, t }`
//! - input (verifier): `{ log_n, t }`
//! - `reduced`: `{ queries }` — same on both sides (verifier squeezes
//!   the same bytes the prover did)

use ark_ff::Field;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::error::{ProverError, VerifierError};
use crate::protocol::iors::IOR;
use crate::protocol::query::QueryIndices;

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct SampleQueriesProverInput {
    pub log_n: usize,
    pub t: usize,
}

pub struct SampleQueriesVerifierInput {
    pub log_n: usize,
    pub t: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// Public reduced claim — same on both sides.
pub struct SampleQueriesReduced<F: Field> {
    pub queries: QueryIndices<F>,
}

pub struct SampleQueriesProverOutput<F: Field> {
    pub reduced: SampleQueriesReduced<F>,
    pub carry: (),
}

pub struct SampleQueriesVerifierOutput<F: Field> {
    pub reduced: SampleQueriesReduced<F>,
    pub carry: (),
}

// ─── IOR ──────────────────────────────────────────────────────────────────

/// Shift-query sampling phase configuration. Stateless.
pub struct SampleQueries<'a, F: Field> {
    pub _phantom: PhantomData<&'a F>,
}

impl<'a, F: Field> SampleQueries<'a, F> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: Field> Default for SampleQueries<'a, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, F> IOR for SampleQueries<'a, F>
where
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    const NAME: &'static str = "SampleQueries";

    type ProverInput<'b>
        = SampleQueriesProverInput
    where
        Self: 'b;
    type ProverOutput = SampleQueriesProverOutput<F>;
    type VerifierInput<'b>
        = SampleQueriesVerifierInput
    where
        Self: 'b;
    type VerifierOutput = SampleQueriesVerifierOutput<F>;

    #[tracing::instrument(name = "sample_queries", skip_all, fields(t = input.t, log_n = input.log_n))]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        let queries = QueryIndices::<F>::sample(transcript, input.log_n, input.t);
        Ok(SampleQueriesProverOutput {
            reduced: SampleQueriesReduced { queries },
            carry: (),
        })
    }

    #[tracing::instrument(name = "sample_queries.verify", skip_all, fields(t = input.t, log_n = input.log_n))]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        let n_bytes = (input.t * input.log_n).div_ceil(8);
        let bytes: Vec<u8> = (0..n_bytes)
            .map(|_| transcript.verifier_message::<[u8; 1]>()[0])
            .collect();
        let queries = QueryIndices::from_squeezed_bytes(&bytes, input.log_n, input.t);
        Ok(SampleQueriesVerifierOutput {
            reduced: SampleQueriesReduced { queries },
            carry: (),
        })
    }
}

//! Shift-query sampling IOR.
//!
//! Between OOD and Batching, the verifier draws `t · log_n` random
//! bits and decodes them into `t` shift-query positions over
//! `{0, 1}^log_n`, plus their corresponding evaluation-point vectors.
//!
//! This is the simplest possible IOR — one round of pure verifier
//! randomness, no prover messages, no oracles. Modeled as an IOR for
//! uniformity with the rest of the choreography.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(log_n, t)`
//! - `Witness`          — `()`
//! - `ProverInputs`     — `()`
//! - `VerifierInputs`   — `()`
//! - `ReductionInputs`  — the sampled [`QueryIndices`]
//! - `ReducedStatement` — same — both sides receive the queries
//! - `ProofString`      — `()`
//! - `ReducedWitness`   — `()` (no asymmetric data: both sides hold the same queries)
//! - `VerifierOutputs`  — `()`

use ark_ff::Field;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::error::{ProverError, VerifierError};
use crate::protocol::ior::IOR;
use crate::protocol::oracles::query_indices::QueryIndices;

pub struct SampleQueriesStatement {
    pub log_n: usize,
    pub t: usize,
}

pub struct SampleQueriesReductionInputs<F: Field> {
    pub queries: QueryIndices<F>,
}

pub struct SampleQueriesReducedStatement<F: Field> {
    pub queries: QueryIndices<F>,
}

/// Shift-query sampling IOR configuration. Stateless.
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

    type Statement<'b>
        = SampleQueriesStatement
    where
        Self: 'b;
    type Witness<'b>
        = ()
    where
        Self: 'b;
    type ProverInputs<'b>
        = ()
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ()
    where
        Self: 'b;
    type ReductionInputs = SampleQueriesReductionInputs<F>;
    type ReducedStatement = SampleQueriesReducedStatement<F>;
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
        SampleQueriesReducedStatement {
            queries: inputs.queries.clone(),
        }
    }

    #[tracing::instrument(name = "sample_queries", skip_all, fields(t = statement.t, log_n = statement.log_n))]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        _witness: &Self::Witness<'b>,
        _inputs: &Self::ProverInputs<'b>,
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
        let queries = QueryIndices::<F>::sample(prover_state, statement.log_n, statement.t);
        Ok((SampleQueriesReductionInputs { queries }, (), ()))
    }

    #[tracing::instrument(name = "sample_queries.verify", skip_all)]
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        _inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
    {
        let n_bytes = (statement.t * statement.log_n).div_ceil(8);
        let bytes: Vec<u8> = (0..n_bytes)
            .map(|_| verifier_state.verifier_message::<[u8; 1]>()[0])
            .collect();
        let queries = QueryIndices::from_squeezed_bytes(&bytes, statement.log_n, statement.t);
        Ok((SampleQueriesReductionInputs { queries }, ()))
    }
}

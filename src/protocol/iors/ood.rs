//! Out-of-domain sampling IOR.

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::error::VerifierError;
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::oracles::evaluation::Oracle;

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
    pub samples_flat: Vec<F>,
    pub answers: Vec<F>,
}

#[derive(Default)]
pub struct Ood<F: Field>(PhantomData<F>);

impl<F> IOR for Ood<F>
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
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
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

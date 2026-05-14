//! Out-of-domain sampling IOR.

use ark_ff::{Field, PrimeField};
use ark_iop::{
    IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple, IOR,
};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::iop::oracles::evaluation::Oracle;

pub struct OodStatement {
    pub s_num_ood_samples: usize,
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
    const MESSAGE_TAGS: &'static [&'static str] = &["squeeze:samples", "send:answers"];

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
}

impl<F> Ood<F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    #[tracing::instrument(name = "ood", skip_all, fields(s = statement.s_num_ood_samples, log_n = statement.log_n))]
    fn prove_inner(
        &self,
        prover_state: &mut ProverState,
        statement: &OodStatement,
        inputs: &OodProverInputs<'_, F>,
    ) -> ProverTriple<OodReductionInputs<F>, (), ()> {
        let samples_flat =
            prover_state.verifier_messages_vec::<F>(statement.s_num_ood_samples * statement.log_n);
        count_ops!(OodPointQueries, statement.s_num_ood_samples as u64);
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
        fields(s = statement.s_num_ood_samples, log_n = statement.log_n)
    )]
    fn verify_inner(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &OodStatement,
    ) -> Result<(OodReductionInputs<F>, ()), IorVerifierError> {
        let samples_flat: Vec<F> = (0..statement.s_num_ood_samples * statement.log_n)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        let answers: Vec<F> = verifier_state
            .prover_messages_vec(statement.s_num_ood_samples)
            .map_err(|e| IorVerifierError::Transcript(e.to_string()))?;
        Ok((
            OodReductionInputs {
                samples_flat,
                answers,
            },
            (),
        ))
    }

    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &OodStatement,
        _witness: &(),
        inputs: &OodProverInputs<'_, F>,
    ) -> Result<IorProveResult<OodReducedStatement<F>, (), ()>, IorProverError> {
        self.compose_prove(prover_state, statement, |t| {
            self.prove_inner(t, statement, inputs)
        })
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &OodStatement,
        _inputs: &(),
    ) -> Result<IorVerifyResult<OodReducedStatement<F>, ()>, IorVerifierError> {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement)
        })
    }
}

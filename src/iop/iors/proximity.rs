//! Shift-query IOR. Computes shift-query answers from raw codewords;
//! the orchestrator emits the VC opens (`V::open_multiple` /
//! `V::check_multiple`) so the IOR stays VC-agnostic on both sides.

use ark_ff::Field;
use ark_iop::{IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple, IOR};
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::iop::oracles::query_indices::QueryIndices;

pub struct ProximityStatement<F: Field> {
    pub queries: QueryIndices<F>,
    pub l2_second_fold_factor: usize,
    pub t_num_queries: usize,
    pub n_code_len: usize,
}

/// Inner slices are codewords-per-commitment; outer order is acc first then
/// fresh, opposite to the orchestrator's open order (fresh first then accs).
pub struct ProximityProverInputs<'a, F: Field> {
    pub acc_codewords: &'a [&'a [Vec<F>]],
    pub fresh_codewords: &'a [Vec<F>],
}

pub struct ProximityProofString<F: Field> {
    /// `[t][l2_acc + l1_fresh]`. Auth paths live in the FS transcript.
    pub shift_query_answers: Vec<Vec<F>>,
}

#[derive(Default)]
pub struct Proximity<F: Field>(PhantomData<F>);

impl<F: Field> IOR for Proximity<F> {
    const NAME: &'static str = "Proximity";
    // Tag absorbed by compose_prove/verify here; orchestrator emits the bytes.
    const MESSAGE_TAGS: &'static [&'static str] = &["delegate:vc.open_multiple"];

    type Statement<'b>
        = ProximityStatement<F>
    where
        Self: 'b;
    type Witness<'b>
        = ()
    where
        Self: 'b;
    type ProverInputs<'b>
        = ProximityProverInputs<'b, F>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ()
    where
        Self: 'b;
    type ReductionInputs = ();
    type ReducedStatement = ();
    type ProofString = ProximityProofString<F>;
    type ReducedWitness = ();
    type VerifierOutputs = ();

    fn reduce_statement<'b>(
        &self,
        _statement: &Self::Statement<'b>,
        _inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
    }
}

impl<F: Field> Proximity<F> {
    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_codewords.len(),
        )
    )]
    fn prove_inner(
        &self,
        _prover_state: &mut ProverState,
        statement: &ProximityStatement<F>,
        inputs: &ProximityProverInputs<'_, F>,
    ) -> ProverTriple<(), ProximityProofString<F>, ()> {
        let leaf_positions = &statement.queries.leaf_positions;

        let total_codewords: usize = inputs.acc_codewords.iter().map(|cws| cws.len()).sum::<usize>()
            + inputs.fresh_codewords.len();

        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let mut answers = vec![vec![F::default(); total_codewords]; leaf_positions.len()];
            for (qi, idx) in leaf_positions.iter().enumerate() {
                let mut col = 0usize;
                for cws in inputs.acc_codewords.iter() {
                    for cw in *cws {
                        answers[qi][col] = cw[*idx];
                        col += 1;
                    }
                }
                for cw in inputs.fresh_codewords {
                    answers[qi][col] = cw[*idx];
                    col += 1;
                }
            }
            answers
        };

        Ok((
            (),
            ProximityProofString {
                shift_query_answers,
            },
            (),
        ))
    }

    #[tracing::instrument(name = "proximity.verify", skip_all)]
    fn verify_inner(
        &self,
        _verifier_state: &mut VerifierState<'_>,
        _statement: &ProximityStatement<F>,
        _inputs: &(),
    ) -> Result<((), ()), IorVerifierError> {
        Ok(((), ()))
    }

    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &ProximityStatement<F>,
        _witness: &(),
        inputs: &ProximityProverInputs<'_, F>,
    ) -> Result<IorProveResult<(), ProximityProofString<F>, ()>, IorProverError> {
        self.compose_prove(prover_state, statement, |t| {
            self.prove_inner(t, statement, inputs)
        })
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &ProximityStatement<F>,
        inputs: &(),
    ) -> Result<IorVerifyResult<(), ()>, IorVerifierError> {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement, inputs)
        })
    }
}

//! Shift-query sampling IOR. Squeezes `t · log_n` bits into `t` query
//! positions over `{0,1}^log_n`.

use ark_ff::Field;
use ark_iop::{
    IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple,
    VerifierTranscript, IOR,
};
use spongefish::{ProverState, VerifierState};
use std::marker::PhantomData;

use crate::iop::oracles::query_indices::QueryIndices;

pub struct SampleQueriesStatement {
    pub log_n: usize,
    pub t_num_queries: usize,
}

pub struct SampleQueriesReductionInputs<F: Field> {
    pub queries: QueryIndices<F>,
}

pub struct SampleQueriesReducedStatement<F: Field> {
    pub queries: QueryIndices<F>,
}

#[derive(Default)]
pub struct SampleQueries<F: Field>(PhantomData<F>);

impl<F: Field> IOR for SampleQueries<F> {
    const NAME: &'static str = "SampleQueries";
    const MESSAGE_TAGS: &'static [&'static str] = &["squeeze:queries"];

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
}

impl<F: Field> SampleQueries<F> {
    #[tracing::instrument(name = "sample_queries", skip_all, fields(t = statement.t_num_queries, log_n = statement.log_n))]
    fn prove_inner(
        &self,
        prover_state: &mut ProverState,
        statement: &SampleQueriesStatement,
    ) -> ProverTriple<SampleQueriesReductionInputs<F>, (), ()> {
        let queries =
            QueryIndices::<F>::sample(prover_state, statement.log_n, statement.t_num_queries);
        Ok((SampleQueriesReductionInputs { queries }, (), ()))
    }

    #[tracing::instrument(name = "sample_queries.verify", skip_all)]
    fn verify_inner(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &SampleQueriesStatement,
    ) -> Result<(SampleQueriesReductionInputs<F>, ()), IorVerifierError> {
        let n_bytes = (statement.t_num_queries * statement.log_n).div_ceil(8);
        let bytes = verifier_state.squeeze_bytes(n_bytes);
        let queries =
            QueryIndices::from_squeezed_bytes(&bytes, statement.log_n, statement.t_num_queries);
        Ok((SampleQueriesReductionInputs { queries }, ()))
    }

    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &SampleQueriesStatement,
        _witness: &(),
        _inputs: &(),
    ) -> Result<IorProveResult<SampleQueriesReducedStatement<F>, (), ()>, IorProverError> {
        self.compose_prove(prover_state, statement, |t| self.prove_inner(t, statement))
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &SampleQueriesStatement,
        _inputs: &(),
    ) -> Result<IorVerifyResult<SampleQueriesReducedStatement<F>, ()>, IorVerifierError> {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement)
        })
    }
}

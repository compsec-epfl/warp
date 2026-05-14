//! Proximity / shift-query IOR.
//!
//! Index queries on the committed oracles. Opens both the fresh PESAT
//! commitment and each accumulated commitment at the query positions.
//! Opening proofs (auth paths + sibling digests) are written into the
//! spongefish transcript by `V::open_multiple` rather than carried as
//! separate proof fields.

use ark_ff::Field;
use ark_iop::{
    IndexedOracle, IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple,
    IOR,
};
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::vc::CommittedCodewords;
use crate::iop::oracles::query_indices::QueryIndices;

pub struct ProximityStatement<F: Field> {
    pub queries: QueryIndices<F>,
    pub l2_second_fold_factor: usize,
    pub t_num_queries: usize,
    pub n_code_len: usize,
}

pub struct ProximityProverInputs<'a, F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub ck: &'a V::CommitterKey,
    pub td_0_committed_codeword: &'a CommittedCodewords<F, V>,
    pub acc_td_committed_codewords: &'a [CommittedCodewords<F, V>],
}

/// Verifier-side inputs. The IOR sees [`IndexedOracle`] handles, not
/// raw commitments / opening proofs — IORs stay BCS-agnostic.
pub struct ProximityVerifierInputs<'a, F, O>
where
    F: Field,
    O: IndexedOracle<Vec<F>>,
{
    pub fresh: &'a O,
    pub acc: &'a [O],
    pub _f: PhantomData<F>,
}

/// Wire-format proof string. Auth paths + sibling digests now live in
/// the spongefish transcript; only the shift-query answers remain
/// out-of-band.
pub struct ProximityProofString<F: Field> {
    /// Per-query × per-codeword. Outer length = t (queries). Inner
    /// length = (l2 acc + l1 fresh).
    pub shift_query_answers: Vec<Vec<F>>,
}

pub struct Proximity<'a, F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub ck: &'a V::CommitterKey,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, V> IOR for Proximity<'a, F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    const NAME: &'static str = "Proximity";
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
        = ProximityProverInputs<'b, F, V>
    where
        Self: 'b;
    type VerifierInputs<'b>
        = ProximityVerifierInputs<'b, F, ark_iop::ValidatedOracle<F>>
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

impl<'a, F, V> Proximity<'a, F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_td_committed_codewords.len(),
        )
    )]
    fn prove_inner(
        &self,
        prover_state: &mut ProverState,
        statement: &ProximityStatement<F>,
        inputs: &ProximityProverInputs<'_, F, V>,
    ) -> ProverTriple<(), ProximityProofString<F>, ()> {
        let leaf_positions = &statement.queries.leaf_positions;

        let mut sorted_unique = leaf_positions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();

        let column_tuples = |codewords: &[Vec<F>]| -> Vec<Vec<F>> {
            sorted_unique
                .iter()
                .map(|&i| codewords.iter().map(|c| c[i]).collect())
                .collect()
        };

        {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, sorted_unique.len() as u64);
            let values = column_tuples(&inputs.td_0_committed_codeword.codewords);
            V::open_multiple(
                inputs.ck,
                inputs
                    .td_0_committed_codeword
                    .codewords
                    .iter()
                    .map(|c| c.iter()),
                &inputs.td_0_committed_codeword.commitment,
                sorted_unique.iter().copied(),
                values.into_iter(),
                &inputs.td_0_committed_codeword.state,
                prover_state,
            )
            .expect("proximity: open_multiple (fresh) failed");
        }

        {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (inputs.acc_td_committed_codewords.len() * sorted_unique.len()) as u64
            );
            for td in inputs.acc_td_committed_codewords.iter() {
                let values = column_tuples(&td.codewords);
                V::open_multiple(
                    inputs.ck,
                    td.codewords.iter().map(|c| c.iter()),
                    &td.commitment,
                    sorted_unique.iter().copied(),
                    values.into_iter(),
                    &td.state,
                    prover_state,
                )
                .expect("proximity: open_multiple (acc) failed");
            }
        }

        let shift_query_answers = {
            let _s = tracing::info_span!("proximity.shift_queries").entered();
            let total_codewords = inputs
                .acc_td_committed_codewords
                .iter()
                .map(|td| td.codewords.len())
                .sum::<usize>()
                + inputs.td_0_committed_codeword.codewords.len();
            let mut answers = vec![vec![F::default(); total_codewords]; leaf_positions.len()];
            for (qi, idx) in leaf_positions.iter().enumerate() {
                let mut col = 0usize;
                for td in inputs.acc_td_committed_codewords.iter() {
                    for cw in &td.codewords {
                        answers[qi][col] = cw[*idx];
                        col += 1;
                    }
                }
                for cw in &inputs.td_0_committed_codeword.codewords {
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

    #[tracing::instrument(
        name = "proximity.verify",
        skip_all,
        fields(t = statement.t_num_queries, l2 = statement.l2_second_fold_factor)
    )]
    fn verify_inner(
        &self,
        _verifier_state: &mut VerifierState<'_>,
        statement: &ProximityStatement<F>,
        inputs: &ProximityVerifierInputs<'_, F, ark_iop::ValidatedOracle<F>>,
    ) -> Result<((), ()), IorVerifierError> {
        (inputs.acc.len() == statement.l2_second_fold_factor)
            .then_some(())
            .ok_or_else(|| {
                IorVerifierError::Custom(format!(
                    "Proximity: NumL2Instances mismatch (got {}, expected {})",
                    inputs.acc.len(),
                    statement.l2_second_fold_factor
                ))
            })?;

        // Validation by construction: ValidatedOracle's existence
        // already attests the orchestrator ran V::check_multiple
        // upstream. No runtime validate() call needed.
        count_ops!(
            MerklePathsVerified,
            statement.queries.leaf_positions.len() as u64
        );
        for _ in inputs.acc.iter() {
            count_ops!(
                MerklePathsVerified,
                statement.queries.leaf_positions.len() as u64
            );
        }

        Ok(((), ()))
    }

    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &ProximityStatement<F>,
        _witness: &(),
        inputs: &ProximityProverInputs<'_, F, V>,
    ) -> Result<IorProveResult<(), ProximityProofString<F>, ()>, IorProverError> {
        self.compose_prove(prover_state, statement, |t| {
            self.prove_inner(t, statement, inputs)
        })
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &ProximityStatement<F>,
        inputs: &ProximityVerifierInputs<'_, F, ark_iop::ValidatedOracle<F>>,
    ) -> Result<IorVerifyResult<(), ()>, IorVerifierError> {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement, inputs)
        })
    }
}

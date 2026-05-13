//! Proximity / shift-query IOR.
//!
//! Index queries on the committed oracles. Opens both the fresh PESAT
//! commitment and each accumulated commitment at the query positions.
//! With the trait migration, opening proofs (auth paths + sibling
//! digests) are written into the spongefish transcript by
//! `V::open_multiple` rather than carried as separate proof fields.
//!
use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::vc::CommittedCodewords;
use crate::error::VerifierError;
use crate::protocol::ior::{ProverTriple, IOR};
use crate::protocol::oracles::indexed::IndexedOracle;
use crate::protocol::oracles::query_indices::QueryIndices;

pub struct ProximityStatement<F: Field> {
    pub queries: QueryIndices<F>,
    pub l2_second_fold_factor: usize,
    pub t_num_queries: usize,
    /// Codeword length (`code.code_len()`), needed by both prover and
    /// verifier.
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
/// the spongefish transcript (written by `V::open_multiple`); only the
/// shift-query answers remain as out-of-band data.
pub struct ProximityProofString<F: Field> {
    /// Per-query × per-codeword. Outer length = t (queries). Inner
    /// length = (l2 acc + l1 fresh).
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Proximity IOR configuration. Holds the trait CK used by `open_multiple`.
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
        = ProximityVerifierInputs<'b, F, crate::protocol::oracles::indexed::ValidatedOracle<F>>
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

    #[tracing::instrument(
        name = "proximity",
        skip_all,
        fields(
            n_queries = statement.queries.leaf_positions.len(),
            n_accumulators = inputs.acc_td_committed_codewords.len(),
        )
    )]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        _witness: &Self::Witness<'b>,
        inputs: &Self::ProverInputs<'b>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        Self: 'b,
        'a: 'b,
        V: 'b,
    {
        let leaf_positions = &statement.queries.leaf_positions;

        // Trait `open_multiple` requires sorted unique indices.
        let mut sorted_unique = leaf_positions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();

        // Helper: column-tuple values at the sorted positions for one
        // commitment's codewords.
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

        // Shift query answers: per query position, values across
        // (acc_codewords ++ fresh_codewords).
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
    fn verify_inner<'b, 'c>(
        &self,
        _verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        Self: 'c,
        'a: 'c,
        V: 'c,
    {
        // Arity check.
        (inputs.acc.len() == statement.l2_second_fold_factor)
            .then_some(())
            .ok_or(VerifierError::NumL2Instances)?;

        // Validation already happened upstream (orchestrator called
        // V::check_multiple before invoking this IOR). Handles are
        // pre-validated; this IOR is BCS-agnostic.
        inputs
            .fresh
            .validate()
            .then_some(())
            .ok_or(VerifierError::ShiftQuery)?;
        count_ops!(
            MerklePathsVerified,
            statement.queries.leaf_positions.len() as u64
        );
        for handle in inputs.acc.iter() {
            handle
                .validate()
                .then_some(())
                .ok_or(VerifierError::ShiftQuery)?;
            count_ops!(
                MerklePathsVerified,
                statement.queries.leaf_positions.len() as u64
            );
        }

        Ok(((), ()))
    }
}

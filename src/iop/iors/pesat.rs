//! PESAT Reduction IOR.
//!
//! Encodes fresh witnesses into codewords, commits via the trait's
//! joint-commit path (one commitment over all l1 codewords), absorbs
//! that commitment + code evaluations, and derives the τ zero-check
//! challenges.

use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_iop::{
    IorProveResult, IorProverError, IorVerifierError, IorVerifyResult, ProverTriple, IOR,
};
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::vc::CommittedCodewords;

pub struct PesatStatement {
    pub l1_first_fold_factor: usize,
    pub log_m: usize,
}

pub struct PesatWitness<'a, F: Field> {
    pub witnesses: &'a [Vec<F>],
}

pub struct PesatReductionInputs<F: Field> {
    pub mus_codeword_first_coords: Vec<F>,
    pub taus_zero_check_challenges: Vec<Vec<F>>,
}

pub struct PesatReducedStatement<F: Field> {
    pub mus_codeword_first_coords: Vec<F>,
    pub taus_zero_check_challenges: Vec<Vec<F>>,
}

pub struct PesatReducedWitness<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub codewords: Vec<Vec<F>>,
    pub td_0_committed_codeword: CommittedCodewords<F, V>,
}

pub struct PesatVerifierOutputs<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub rt_0_fresh_commitment: V::Commitment,
}

/// PESAT IOR configuration. Holds borrowed code + the trait CK; the
/// IOR is generic over any `MultiVectorCommitment` over `F`.
pub struct Pesat<'a, F, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub code: &'a C,
    pub ck: &'a V::CommitterKey,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, C, V> IOR for Pesat<'a, F, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    const NAME: &'static str = "PESAT";
    const MESSAGE_TAGS: &'static [&'static str] =
        &["send:rt_0_commitment", "send:mus", "squeeze:taus"];
    type Statement<'b>
        = PesatStatement
    where
        Self: 'b;
    type Witness<'b>
        = PesatWitness<'b, F>
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
    type ReductionInputs = PesatReductionInputs<F>;
    type ReducedStatement = PesatReducedStatement<F>;
    type ProofString = ();
    type ReducedWitness = PesatReducedWitness<F, V>;
    type VerifierOutputs = PesatVerifierOutputs<F, V>;

    fn reduce_statement<'b>(
        &self,
        _statement: &Self::Statement<'b>,
        inputs: &Self::ReductionInputs,
    ) -> Self::ReducedStatement
    where
        Self: 'b,
    {
        PesatReducedStatement {
            mus_codeword_first_coords: inputs.mus_codeword_first_coords.clone(),
            taus_zero_check_challenges: inputs.taus_zero_check_challenges.clone(),
        }
    }
}

impl<'a, F, C, V> Pesat<'a, F, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize,
{
    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = statement.l1_first_fold_factor, log_m = statement.log_m, n_witnesses = witness.witnesses.len())
    )]
    fn prove_inner(
        &self,
        prover_state: &mut ProverState,
        statement: &PesatStatement,
        witness: &PesatWitness<'_, F>,
    ) -> ProverTriple<PesatReductionInputs<F>, (), PesatReducedWitness<F, V>> {
        let codewords: Vec<Vec<F>> = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, witness.witnesses.len() as u64);
            witness
                .witnesses
                .iter()
                .map(|w| self.code.encode(w))
                .collect()
        };

        let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

        let td_0 = {
            let _s = tracing::info_span!("pesat.merkle_commit").entered();
            count_ops!(MerkleTreeBuilds);
            let (commitment, state) =
                V::commit_multiple(self.ck, codewords.iter().map(|c| c.iter()))
                    .expect("pesat: commit_multiple failed");
            CommittedCodewords {
                commitment,
                state,
                codewords: codewords.clone(),
            }
        };

        let taus = {
            let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
            prover_state.prover_message(&td_0.commitment);
            prover_state.prover_messages(&mus);

            (0..statement.l1_first_fold_factor)
                .map(|_| prover_state.verifier_messages_vec::<F>(statement.log_m))
                .collect::<Vec<_>>()
        };

        Ok((
            PesatReductionInputs {
                mus_codeword_first_coords: mus.clone(),
                taus_zero_check_challenges: taus,
            },
            (),
            PesatReducedWitness {
                codewords,
                td_0_committed_codeword: td_0,
            },
        ))
    }

    #[tracing::instrument(
        name = "pesat.verify",
        skip_all,
        fields(l1 = statement.l1_first_fold_factor, log_m = statement.log_m)
    )]
    fn verify_inner(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &PesatStatement,
    ) -> Result<(PesatReductionInputs<F>, PesatVerifierOutputs<F, V>), IorVerifierError> {
        let rt_0: V::Commitment = verifier_state
            .prover_message()
            .map_err(|e| IorVerifierError::Transcript(e.to_string()))?;
        let mus: Vec<F> = verifier_state
            .prover_messages_vec(statement.l1_first_fold_factor)
            .map_err(|e| IorVerifierError::Transcript(e.to_string()))?;
        let taus: Vec<Vec<F>> = (0..statement.l1_first_fold_factor)
            .map(|_| {
                (0..statement.log_m)
                    .map(|_| verifier_state.verifier_message::<F>())
                    .collect()
            })
            .collect();

        Ok((
            PesatReductionInputs {
                mus_codeword_first_coords: mus,
                taus_zero_check_challenges: taus,
            },
            PesatVerifierOutputs {
                rt_0_fresh_commitment: rt_0,
            },
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &PesatStatement,
        witness: &PesatWitness<'_, F>,
        _inputs: &(),
    ) -> Result<
        IorProveResult<PesatReducedStatement<F>, (), PesatReducedWitness<F, V>>,
        IorProverError,
    > {
        self.compose_prove(prover_state, statement, |t| {
            self.prove_inner(t, statement, witness)
        })
    }

    pub fn verify(
        &self,
        verifier_state: &mut VerifierState<'_>,
        statement: &PesatStatement,
        _inputs: &(),
    ) -> Result<
        IorVerifyResult<PesatReducedStatement<F>, PesatVerifierOutputs<F, V>>,
        IorVerifierError,
    > {
        self.compose_verify(verifier_state, statement, |t| {
            self.verify_inner(t, statement)
        })
    }
}

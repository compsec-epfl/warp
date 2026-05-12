//! PESAT Reduction IOR.
//!
//! Encodes fresh witnesses into codewords, commits via a multi-vector
//! Merkle tree (one root over all l1 codewords), absorbs commitment +
//! code evaluations, and derives the τ zero-check challenges.
//!
use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{encode_codewords, warp_scheme, WarpCommitted};
use crate::error::VerifierError;
use crate::protocol::ior::{ProverTriple, IOR};

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

pub struct PesatReducedWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub codewords: Vec<Vec<F>>,
    pub td_0_committed_codeword: WarpCommitted<H, F>,
}

pub struct PesatVerifierOutputs<H: MerkleHasher> {
    pub rt_0_fresh_merkle_root: H::Digest,
}

/// PESAT IOR configuration.
pub struct Pesat<'a, F, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub code: &'a C,
    pub hasher: &'a H,
    pub _phantom: PhantomData<(F, H)>,
}

impl<'a, F, C, H> IOR for Pesat<'a, F, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    const NAME: &'static str = "PESAT";
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
    type ReducedWitness = PesatReducedWitness<F, H>;
    type VerifierOutputs = PesatVerifierOutputs<H>;

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

    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = statement.l1_first_fold_factor, log_m = statement.log_m, n_witnesses = witness.witnesses.len())
    )]
    fn prove_inner<'b>(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement<'b>,
        witness: &Self::Witness<'b>,
        _inputs: &Self::ProverInputs<'b>,
    ) -> ProverTriple<Self::ReductionInputs, Self::ProofString, Self::ReducedWitness>
    where
        'a: 'b,
        H: 'b,
    {
        let codewords = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, witness.witnesses.len() as u64);
            encode_codewords(self.code, witness.witnesses)
        };

        let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

        let td_0 = {
            let _s = tracing::info_span!("pesat.merkle_commit").entered();
            count_ops!(MerkleTreeBuilds);
            let scheme = warp_scheme(self.hasher.clone(), self.code.code_len());
            scheme.commit(&codewords)
        };

        let taus = {
            let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
            prover_state.prover_message(td_0.root());
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
    fn verify_inner<'b, 'c>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement<'c>,
        _inputs: &Self::VerifierInputs<'c>,
    ) -> Result<(Self::ReductionInputs, Self::VerifierOutputs), VerifierError>
    where
        'a: 'c,
        H: 'c,
    {
        let rt_0: H::Digest = verifier_state.prover_message()?;
        let mus: Vec<F> = verifier_state.prover_messages_vec(statement.l1_first_fold_factor)?;
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
                rt_0_fresh_merkle_root: rt_0,
            },
        ))
    }
}

//! PESAT Reduction phase.
//!
//! Implements Phase 2 of the Warp prover: encode fresh witnesses into
//! codewords, commit via a multi-vector Merkle tree (one root over all
//! l1 codewords), absorb commitment + code evaluations, and derive the
//! τ zero-check challenges.
//!
//! IOR signature
//! -------------
//! - `Statement`        — `(l1, log_m)`
//! - `Witness`          — `&[Vec<F>]` (fresh witnesses to encode)
//! - `ProverInputs`     — `()`
//! - `VerifierInputs`   — `()`
//! - `ReducedStatement` — `(mus, taus)` — code-eval claims + zero-check randomness
//! - `ProverOutputs`    — full codewords + multi-vector commit
//! - `VerifierOutputs`  — Merkle root only

use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{encode_codewords, warp_scheme, WarpCommitted};
use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;

pub struct PesatStatement {
    pub l1: usize,
    pub log_m: usize,
}

pub struct PesatWitness<'a, F: Field> {
    pub witnesses: &'a [Vec<F>],
}

pub struct PesatReducedStatement<F: Field> {
    pub mus: Vec<F>,
    pub taus: Vec<Vec<F>>,
}

pub struct PesatProverOutputs<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub codewords: Vec<Vec<F>>,
    pub td_0: WarpCommitted<H, F>,
}

pub struct PesatVerifierOutputs<H: MerkleHasher> {
    pub rt_0: H::Digest,
}

/// PESAT phase configuration.
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
    type Statement = PesatStatement;
    type Witness = PesatWitness<'a, F>;
    type ProverInputs = ();
    type VerifierInputs = ();
    type ReducedStatement = PesatReducedStatement<F>;
    type ProverOutputs = PesatProverOutputs<F, H>;
    type VerifierOutputs = PesatVerifierOutputs<H>;

    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = statement.l1, log_m = statement.log_m, n_witnesses = witness.witnesses.len())
    )]
    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        witness: Self::Witness,
        _inputs: Self::ProverInputs,
    ) -> Result<(Self::ReducedStatement, Self::ProverOutputs), ProverError> {
        // a. encode witnesses
        let codewords = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, witness.witnesses.len() as u64);
            encode_codewords(self.code, witness.witnesses)
        };

        // b. evaluation claims
        let mus = codewords.iter().map(|f| f[0]).collect::<Vec<F>>();

        // c. commit to interleaved codewords (multi-vector commitment)
        let td_0 = {
            let _s = tracing::info_span!("pesat.merkle_commit").entered();
            count_ops!(MerkleTreeBuilds);
            let scheme = warp_scheme(self.hasher.clone(), self.code.code_len());
            scheme.commit(&codewords)
        };

        // d. absorb commitment + claims; e/f. derive τ challenges.
        let taus = {
            let _s = tracing::info_span!("pesat.absorb_and_derive").entered();
            prover_state.prover_message(td_0.root());
            prover_state.prover_messages(&mus);

            (0..statement.l1)
                .map(|_| prover_state.verifier_messages_vec::<F>(statement.log_m))
                .collect::<Vec<_>>()
        };

        Ok((
            PesatReducedStatement {
                mus: mus.clone(),
                taus,
            },
            PesatProverOutputs { codewords, td_0 },
        ))
    }

    #[tracing::instrument(
        name = "pesat.verify",
        skip_all,
        fields(l1 = statement.l1, log_m = statement.log_m)
    )]
    fn verify<'b>(
        &self,
        verifier_state: &mut VerifierState<'b>,
        statement: &Self::Statement,
        _inputs: Self::VerifierInputs,
    ) -> Result<(Self::ReducedStatement, Self::VerifierOutputs), VerifierError> {
        // commitment digest
        let rt_0: H::Digest = verifier_state.prover_message()?;

        // mus (l1 evaluation claims)
        let mus: Vec<F> = verifier_state.prover_messages_vec(statement.l1)?;

        // taus (l1 zero-check challenge vectors)
        let taus: Vec<Vec<F>> = (0..statement.l1)
            .map(|_| {
                (0..statement.log_m)
                    .map(|_| verifier_state.verifier_message::<F>())
                    .collect()
            })
            .collect();

        Ok((
            PesatReducedStatement { mus, taus },
            PesatVerifierOutputs { rt_0 },
        ))
    }
}

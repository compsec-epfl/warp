//! PESAT Reduction IOR.
//!
//! Encodes fresh witnesses into codewords, commits via a multi-vector
//! Merkle tree (one root over all `l1` codewords), absorbs commitment +
//! code evaluations, and derives the τ zero-check challenges.
//!
//! IOR ports
//! ---------
//! - input (prover): `{ l1, log_m, witnesses }`
//! - input (verifier): `{ l1, log_m }`
//! - `reduced`: `{ mus, taus }` — same on both sides (verifier reads
//!   from the transcript)
//! - `carry` (prover): `{ codewords, td_0 }` — feeds TwinConstraint /
//!   Proximity
//! - `carry` (verifier): `{ rt_0 }` — feeds Proximity

use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{encode_codewords, warp_scheme, WarpCommitted};
use crate::error::{ProverError, VerifierError};
use crate::protocol::iors::IOR;

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct PesatProverInput<'a, F: Field> {
    pub l1: usize,
    pub log_m: usize,
    pub witnesses: &'a [Vec<F>],
}

pub struct PesatVerifierInput {
    pub l1: usize,
    pub log_m: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// Public reduced claim — same on both sides.
pub struct PesatReduced<F: Field> {
    pub mus: Vec<F>,
    pub taus: Vec<Vec<F>>,
}

pub struct PesatProverCarry<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub codewords: Vec<Vec<F>>,
    pub td_0: WarpCommitted<H, F>,
}

pub struct PesatVerifierCarry<H: MerkleHasher> {
    pub rt_0: H::Digest,
}

pub struct PesatProverOutput<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub reduced: PesatReduced<F>,
    pub carry: PesatProverCarry<F, H>,
}

pub struct PesatVerifierOutput<F: Field, H: MerkleHasher> {
    pub reduced: PesatReduced<F>,
    pub carry: PesatVerifierCarry<H>,
}

// ─── IOR ──────────────────────────────────────────────────────────────────

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

    type ProverInput<'b>
        = PesatProverInput<'b, F>
    where
        Self: 'b;
    type ProverOutput = PesatProverOutput<F, H>;
    type VerifierInput<'b>
        = PesatVerifierInput
    where
        Self: 'b;
    type VerifierOutput = PesatVerifierOutput<F, H>;

    #[tracing::instrument(
        name = "pesat",
        skip_all,
        fields(l1 = input.l1, log_m = input.log_m, n_witnesses = input.witnesses.len())
    )]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        // a. encode witnesses
        let codewords = {
            let _s = tracing::info_span!("pesat.encode").entered();
            count_ops!(EncodeCalls, input.witnesses.len() as u64);
            encode_codewords(self.code, input.witnesses)
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
            transcript.prover_message(td_0.root());
            transcript.prover_messages(&mus);

            (0..input.l1)
                .map(|_| transcript.verifier_messages_vec::<F>(input.log_m))
                .collect::<Vec<_>>()
        };

        Ok(PesatProverOutput {
            reduced: PesatReduced {
                mus: mus.clone(),
                taus,
            },
            carry: PesatProverCarry { codewords, td_0 },
        })
    }

    #[tracing::instrument(name = "pesat.verify", skip_all, fields(l1 = input.l1, log_m = input.log_m))]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        // commitment digest
        let rt_0: H::Digest = transcript.prover_message()?;

        // mus (l1 evaluation claims)
        let mus: Vec<F> = transcript.prover_messages_vec(input.l1)?;

        // taus (l1 zero-check challenge vectors)
        let taus: Vec<Vec<F>> = (0..input.l1)
            .map(|_| {
                (0..input.log_m)
                    .map(|_| transcript.verifier_message::<F>())
                    .collect()
            })
            .collect();

        Ok(PesatVerifierOutput {
            reduced: PesatReduced { mus, taus },
            carry: PesatVerifierCarry { rt_0 },
        })
    }
}

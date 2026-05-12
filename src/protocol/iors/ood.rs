//! Out-of-domain sampling phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`. This phase is a thin
//! composition of point queries on the committed oracle — see
//! [`Oracle::query_at_point`](crate::protocol::oracle::Oracle::query_at_point).
//! The verifier derives the same random points from the transcript.
//!
//! IOR ports
//! ---------
//! - input (prover): `{ oracle, s, log_n }`
//! - input (verifier): `{ s, log_n }`
//! - `reduced`: `{ samples_flat, answers }` — same on both sides (verifier
//!   reads from the transcript)
//! - no `carry` — OOD's outputs all flow through `reduced`

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::iors::IOR;

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct OodProverInput<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
    pub s: usize,
    pub log_n: usize,
}

pub struct OodVerifierInput {
    pub s: usize,
    pub log_n: usize,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// Public reduced claim — same on both sides.
pub struct OodReduced<F: Field> {
    /// Flat challenge vector of length `s · log_n`.
    pub samples_flat: Vec<F>,
    /// Answers `\hat f(ζ_j)` for each of the `s` chunked challenges.
    pub answers: Vec<F>,
}

pub struct OodProverOutput<F: Field> {
    pub reduced: OodReduced<F>,
    pub carry: (),
}

pub struct OodVerifierOutput<F: Field> {
    pub reduced: OodReduced<F>,
    pub carry: (),
}

// ─── IOR ──────────────────────────────────────────────────────────────────

/// OOD phase configuration. Stateless; the lifetime parameter exists only
/// to anchor `ProverInput<'a>` for the trait impl.
pub struct Ood<'a, F: Field> {
    pub _phantom: PhantomData<&'a F>,
}

impl<'a, F: Field> Ood<'a, F> {
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, F: Field> Default for Ood<'a, F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, F> IOR for Ood<'a, F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    const NAME: &'static str = "OOD";

    type ProverInput<'b>
        = OodProverInput<'b, F>
    where
        Self: 'b;
    type ProverOutput = OodProverOutput<F>;
    type VerifierInput<'b>
        = OodVerifierInput
    where
        Self: 'b;
    type VerifierOutput = OodVerifierOutput<F>;

    #[tracing::instrument(name = "ood", skip_all, fields(s = input.s, log_n = input.log_n))]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        let samples_flat = transcript.verifier_messages_vec::<F>(input.s * input.log_n);
        count_ops!(OodPointQueries, input.s as u64);
        let answers = samples_flat
            .chunks(input.log_n)
            .map(|zeta| input.oracle.query_at_point(zeta))
            .collect::<Vec<F>>();
        transcript.prover_messages(&answers);
        Ok(OodProverOutput {
            reduced: OodReduced {
                samples_flat,
                answers,
            },
            carry: (),
        })
    }

    #[tracing::instrument(
        name = "ood.verify",
        skip_all,
        fields(s = input.s, log_n = input.log_n)
    )]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        let samples_flat: Vec<F> = (0..input.s * input.log_n)
            .map(|_| transcript.verifier_message::<F>())
            .collect();
        let answers: Vec<F> = transcript.prover_messages_vec(input.s)?;
        Ok(OodVerifierOutput {
            reduced: OodReduced {
                samples_flat,
                answers,
            },
            carry: (),
        })
    }
}

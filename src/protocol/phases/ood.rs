//! Out-of-domain sampling phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`. This phase is a thin
//! composition of point queries on the committed oracle — see
//! [`Oracle::query_at_point`](crate::protocol::oracle::Oracle::query_at_point).
//! The verifier derives the same random points from the transcript.

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::count_ops;
use crate::error::ProverError;
use crate::protocol::oracle::Oracle;
use crate::protocol::phases::ProverPhase;

/// Output of the OOD phase: the flat challenge vector and the prover's
/// answers at each chunked evaluation point.
pub struct OodOutput<F: Field> {
    /// Flat challenge vector of length `s · log_n`.
    pub samples_flat: Vec<F>,
    /// Answers `\hat f(ζ_j)` for each of the `s` chunked challenges.
    pub answers: Vec<F>,
}

/// OOD phase: sample `s` evaluation points, query the oracle at each, absorb
/// the answers.
pub struct Ood<'a, F: Field> {
    pub oracle: &'a Oracle<F>,
    pub s: usize,
    pub log_n: usize,
}

impl<'a, F> ProverPhase for Ood<'a, F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    type Output = OodOutput<F>;

    #[tracing::instrument(name = "ood", skip_all, fields(s = self.s, log_n = self.log_n))]
    fn prove(self, prover_state: &mut ProverState) -> Result<Self::Output, ProverError> {
        let samples_flat = prover_state.verifier_messages_vec::<F>(self.s * self.log_n);
        count_ops!(OodPointQueries, self.s as u64);
        let answers = samples_flat
            .chunks(self.log_n)
            .map(|zeta| self.oracle.query_at_point(zeta))
            .collect::<Vec<F>>();
        prover_state.prover_messages(&answers);
        Ok(OodOutput {
            samples_flat,
            answers,
        })
    }
}

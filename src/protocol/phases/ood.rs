//! Out-of-domain sampling phase.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`. This phase is a thin
//! composition of point queries on the committed oracle — see
//! [`Oracle::query_at_point`](crate::protocol::oracle::Oracle::query_at_point).
//! The verifier derives the same random points from the transcript.

use ark_ff::{Field, PrimeField};
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};

use crate::protocol::oracle::Oracle;

/// Output of the OOD phase: the flat challenge vector and the prover's
/// answers at each chunked evaluation point.
pub struct OodOutput<F: Field> {
    /// Flat challenge vector of length `s · log_n`.
    pub samples_flat: Vec<F>,
    /// Answers `\hat f(ζ_j)` for each of the `s` chunked challenges.
    pub answers: Vec<F>,
}

/// Run the OOD phase: sample `s` evaluation points, query the oracle at
/// each, absorb the answers.
#[tracing::instrument(name = "ood", skip_all, fields(s = s, log_n = log_n))]
pub fn prove<F>(
    prover_state: &mut ProverState,
    oracle: &Oracle<F>,
    s: usize,
    log_n: usize,
) -> OodOutput<F>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    let samples_flat = prover_state.verifier_messages_vec::<F>(s * log_n);
    let answers = samples_flat
        .chunks(log_n)
        .map(|zeta| oracle.query_at_point(zeta))
        .collect::<Vec<F>>();
    prover_state.prover_messages(&answers);
    OodOutput {
        samples_flat,
        answers,
    }
}

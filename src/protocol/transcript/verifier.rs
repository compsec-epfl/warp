use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Decoding, Encoding, NargDeserialize, VerificationResult, VerifierState};

use crate::warp::AccumulatorInstance;

// (l1 instances, accumulated instance)
pub type ParsedStatement<F, V> = (Vec<Vec<F>>, AccumulatorInstance<F, V>);

// parse l1 plain instances + an AccumulatorInstance from the transcript
pub fn parse_statement<F, V>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    l2: usize,
    instance_len: usize,
    log_n: usize,
    log_m: usize,
) -> VerificationResult<ParsedStatement<F, V>>
where
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Encoding<[u8]> + NargDeserialize,
{
    let l1_xs: Vec<Vec<F>> = (0..l1)
        .map(|_| verifier_state.prover_messages_vec(instance_len))
        .collect::<Result<_, _>>()?;

    let acc =
        AccumulatorInstance::<F, V>::parse_from(verifier_state, l2, log_n, log_m, instance_len)?;

    Ok((l1_xs, acc))
}

// parse an AccumulatorInstance from the verifier transcript
impl<F, V> AccumulatorInstance<F, V>
where
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Encoding<[u8]> + NargDeserialize,
{
    pub fn parse_from(
        verifier_state: &mut VerifierState<'_>,
        l2: usize,
        log_n: usize,
        log_m: usize,
        instance_len: usize,
    ) -> VerificationResult<Self> {
        let rt: Vec<V::Commitment> = (0..l2)
            .map(|_| verifier_state.prover_message::<V::Commitment>())
            .collect::<Result<_, _>>()?;

        let alpha: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(log_n))
            .collect::<Result<_, _>>()?;

        let mu: Vec<F> = verifier_state.prover_messages_vec(l2)?;

        let taus: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(log_m))
            .collect::<Result<_, _>>()?;

        let xs: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(instance_len))
            .collect::<Result<_, _>>()?;

        let beta_twin_pairs: Vec<crate::warp::accumulator::BetaTwinPair<F>> = taus
            .into_iter()
            .zip(xs)
            .map(|(tau, x)| crate::warp::accumulator::BetaTwinPair { tau, x })
            .collect();

        let eta: Vec<F> = verifier_state.prover_messages_vec(l2)?;

        Ok(Self {
            rt_commitments: rt,
            alpha_fold_vectors: alpha,
            mu_claimed_evals: mu,
            beta_twin_pairs,
            eta_predicate_evals: eta,
        })
    }
}

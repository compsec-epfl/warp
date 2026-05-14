//! Warp-specific transcript helpers: `AccumulatorInstance` (de)serialization
//! plus the plain-instance absorber.

use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerificationResult,
    VerifierState,
};

use crate::accumulation_scheme::{accumulator::BetaTwinPair, AccumulatorInstance};

pub type ParsedStatement<F, V> = (Vec<Vec<F>>, AccumulatorInstance<F, V>);

pub fn absorb_instances<F: Field + Encoding<[u8]>>(
    prover_state: &mut ProverState,
    instances: &[Vec<F>],
) {
    for instance in instances {
        for f in instance {
            prover_state.prover_message(f);
        }
    }
}

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

impl<F, V> AccumulatorInstance<F, V>
where
    F: Field + Encoding<[u8]>,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Encoding<[u8]> + NargSerialize,
{
    pub fn absorb_into(&self, prover_state: &mut ProverState) {
        for commitment in &self.rt_commitments {
            prover_state.prover_message(commitment);
        }

        for alpha in &self.alpha_fold_vectors {
            for f in alpha {
                prover_state.prover_message(f);
            }
        }

        for f in &self.mu_claimed_evals {
            prover_state.prover_message(f);
        }

        // Layout: all τ vectors first (l2 of them), then all x vectors.
        // Verifier reads in the same order. Keeping the τ/x halves in
        // separate passes lets the verifier reconstruct the pair list
        // without needing length-prefixes per pair.
        for pair in &self.beta_twin_pairs {
            for f in &pair.tau {
                prover_state.prover_message(f);
            }
        }
        for pair in &self.beta_twin_pairs {
            for f in &pair.x {
                prover_state.prover_message(f);
            }
        }

        for f in &self.eta_predicate_evals {
            prover_state.prover_message(f);
        }
    }
}

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

        let beta_twin_pairs: Vec<BetaTwinPair<F>> = taus
            .into_iter()
            .zip(xs)
            .map(|(tau, x)| BetaTwinPair { tau, x })
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

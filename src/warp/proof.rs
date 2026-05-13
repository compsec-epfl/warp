use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;

use crate::error::ProverError;
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};

/// Proof produced by the WARP accumulation prover. Auth paths and
/// sibling digests now live in the spongefish transcript (the trait's
/// `open_multiple` writes them via `prover_state.prover_message`), so
/// they no longer appear here as separate fields.
pub struct WARPProof<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub rt_0_fresh_commitment: V::Commitment,
    pub mu_i_first_codeword_coords: Vec<F>,
    pub nu_0_oracle_eval: F,
    pub nu_i_oracle_evals: Vec<F>,
    pub shift_query_answers: Vec<Vec<F>>,
}

impl<F, V> Clone for WARPProof<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rt_0_fresh_commitment: self.rt_0_fresh_commitment.clone(),
            mu_i_first_codeword_coords: self.mu_i_first_codeword_coords.clone(),
            nu_0_oracle_eval: self.nu_0_oracle_eval,
            nu_i_oracle_evals: self.nu_i_oracle_evals.clone(),
            shift_query_answers: self.shift_query_answers.clone(),
        }
    }
}

pub type ProveResult<F, V> = Result<
    (
        (AccumulatorInstance<F, V>, AccumulatorWitness<F, V>),
        WARPProof<F, V>,
    ),
    ProverError,
>;

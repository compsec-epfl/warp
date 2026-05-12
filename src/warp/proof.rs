use ark_ff::Field;
use ark_mt::MerkleHasher;

use crate::crypto::merkle::WarpProof;
use crate::error::ProverError;
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};

/// Proof produced by the WARP accumulation prover. Corresponds to
/// `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the paper.
pub struct WARPProof<F: Field, H: MerkleHasher> {
    pub rt_0_fresh_merkle_root: H::Digest,
    pub mu_i_first_codeword_coords: Vec<F>,
    pub nu_0_oracle_eval: F,
    pub nu_i_oracle_evals: Vec<F>,
    pub auth_0: WarpProof<H>,
    pub auth_j: Vec<WarpProof<H>>,
    pub shift_query_answers: Vec<Vec<F>>,
}

impl<F, H> Clone for WARPProof<F, H>
where
    F: Field,
    H: MerkleHasher,
    H::Digest: Clone,
    WarpProof<H>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rt_0_fresh_merkle_root: self.rt_0_fresh_merkle_root.clone(),
            mu_i_first_codeword_coords: self.mu_i_first_codeword_coords.clone(),
            nu_0_oracle_eval: self.nu_0_oracle_eval,
            nu_i_oracle_evals: self.nu_i_oracle_evals.clone(),
            auth_0: self.auth_0.clone(),
            auth_j: self.auth_j.clone(),
            shift_query_answers: self.shift_query_answers.clone(),
        }
    }
}

pub type ProveResult<F, H> = Result<
    (
        (AccumulatorInstance<F, H>, AccumulatorWitness<F, H>),
        WARPProof<F, H>,
    ),
    ProverError,
>;

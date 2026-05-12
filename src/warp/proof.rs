use ark_ff::Field;
use ark_mt::MerkleHasher;

use crate::crypto::merkle::WarpProof;
use crate::error::ProverError;
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};

/// Proof produced by the WARP accumulation prover. Corresponds to
/// `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the paper.
pub struct WARPProof<F: Field, H: MerkleHasher> {
    pub rt_0: H::Digest,
    pub mu_i: Vec<F>,
    pub nu_0: F,
    pub nu_i: Vec<F>,
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
            rt_0: self.rt_0.clone(),
            mu_i: self.mu_i.clone(),
            nu_0: self.nu_0,
            nu_i: self.nu_i.clone(),
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

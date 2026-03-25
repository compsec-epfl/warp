use ark_codes::traits::LinearCode;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;
use std::marker::PhantomData;

use crate::config::WARPConfig;
use crate::error::ProverError;
use crate::relations::BundledPESAT;

// result of a prove call: (new accumulator instance + witness, proof)
pub type ProveResult<F, MT> = Result<
    (
        (AccumulatorInstance<F, MT>, AccumulatorWitness<F, MT>),
        WARPProof<F, MT>,
    ),
    ProverError,
>;

/// Protocol parameters for WARP — the shared configuration used by all IOR phases.
pub struct WARPParams<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    pub _f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    pub mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    pub mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}
/// Accumulator instance — the public part of an accumulated claim.
///
/// Corresponds to `(rt, α, μ, (τ, x), η)` in the paper.
#[derive(Clone)]
pub struct AccumulatorInstance<F: Field, MT: Config> {
    /// Merkle tree root commitments.
    pub rt: Vec<MT::InnerDigest>,
    /// Code evaluation points (one per accumulated oracle).
    pub alpha: Vec<Vec<F>>,
    /// Code evaluation targets (one per accumulated oracle).
    pub mu: Vec<F>,
    /// Circuit evaluation points: `(τ_i, x_i)` pairs.
    pub beta: (Vec<Vec<F>>, Vec<Vec<F>>),
    /// Bundled PESAT evaluation targets.
    pub eta: Vec<F>,
}

impl<F: Field, MT: Config> AccumulatorInstance<F, MT> {
    pub fn empty() -> Self {
        Self {
            rt: vec![],
            alpha: vec![],
            mu: vec![],
            beta: (vec![], vec![]),
            eta: vec![],
        }
    }
}

/// Accumulator witness — the private part of an accumulated claim.
///
/// Corresponds to `(td, f, w)` in the paper.
#[derive(Clone)]
pub struct AccumulatorWitness<F: Field, MT: Config> {
    /// Merkle tree trapdoors (full trees).
    pub td: Vec<MerkleTree<MT>>,
    /// Oracle evaluations (codewords).
    pub f: Vec<Vec<F>>,
    /// R1CS witnesses.
    pub w: Vec<Vec<F>>,
}

impl<F: Field, MT: Config> AccumulatorWitness<F, MT> {
    pub fn empty() -> Self {
        Self {
            td: vec![],
            f: vec![],
            w: vec![],
        }
    }
}

/// Proof produced by the WARP accumulation prover.
///
/// Corresponds to `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the paper.
#[derive(Clone)]
pub struct WARPProof<F: Field, MT: Config> {
    /// Fresh Merkle tree root.
    pub rt_0: MT::InnerDigest,
    /// Fresh code evaluations at 0.
    pub mu_i: Vec<F>,
    /// Evaluation of accumulated oracle at zeta_0.
    pub nu_0: F,
    /// Evaluation claims (OOD + shift query answers).
    pub nu_i: Vec<F>,
    /// Authentication paths for the fresh commitment.
    pub auth_0: Vec<Path<MT>>,
    /// Authentication paths for each accumulated commitment.
    pub auth_j: Vec<Vec<Path<MT>>>,
    /// Shift query answers: `f_i(x_j)` for each query position `j` and oracle `i`.
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Intermediate output of the PESAT reduction phase.
///
/// This data flows from Phase 2 (PESAT Reduction) into Phase 3 (Constrained Code Accumulation).
pub(crate) struct PesatOutput<F: Field, MT: Config> {
    /// Encoded codewords from fresh witnesses.
    pub codewords: Vec<Vec<F>>,
    /// Merkle tree over the interleaved codeword leaves.
    pub td_0: MerkleTree<MT>,
    /// Code evaluation claims: `f_i(0)` for each codeword.
    pub mus: Vec<F>,
    /// PESAT evaluation challenges (one per fresh instance).
    pub taus: Vec<Vec<F>>,
}

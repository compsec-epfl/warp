use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_vc::shape::PerfectBinary;
use ark_vc::{Committed, MerkleCommitment, OpeningProof};
use std::marker::PhantomData;

use crate::config::WARPConfig;
use crate::error::ProverError;
use crate::hasher::WarpHasher;
use crate::relations::BundledPESAT;

// result of a prove call: (new accumulator instance + witness, proof)
pub type ProveResult<F, H> = Result<
    (
        (AccumulatorInstance<F, H>, AccumulatorWitness<F, H>),
        WARPProof<F, H>,
    ),
    ProverError,
>;

/// Protocol parameters for WARP — the shared configuration used by all IOR phases.
///
/// Generic over the Merkle hasher `H`: callers pick Blake3 for prover
/// speed or Poseidon2 for circuit-friendly recursion.
pub struct WARPParams<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, H: WarpHasher<F>>
{
    pub _f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    pub scheme: MerkleCommitment<H, PerfectBinary>,
}

/// Accumulator instance — the public part of an accumulated claim.
///
/// Corresponds to `(rt, α, μ, (τ, x), η)` in the paper. Roots are the
/// hasher's digest type; for Blake3 this is `[u8; 32]`, for Poseidon
/// it's `F`.
#[derive(Clone)]
pub struct AccumulatorInstance<F: Field, H: WarpHasher<F>> {
    /// Merkle roots (one per accumulated oracle).
    pub rt: Vec<H::Digest>,
    /// Code evaluation points (one per accumulated oracle).
    pub alpha: Vec<Vec<F>>,
    /// Code evaluation targets (one per accumulated oracle).
    pub mu: Vec<F>,
    /// Circuit evaluation points: `(τ_i, x_i)` pairs.
    pub beta: (Vec<Vec<F>>, Vec<Vec<F>>),
    /// Bundled PESAT evaluation targets.
    pub eta: Vec<F>,
}

impl<F: Field, H: WarpHasher<F>> AccumulatorInstance<F, H> {
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
/// `td` holds one ark-vc [`Committed`] per accumulated oracle. It
/// still fills the role of the old `MerkleTree<MT>` (opening new paths,
/// re-deriving the root on `decide`), plus it now carries the message
/// via `Committed::leaves()` — fixing arkworks issue #144 where users
/// had to keep a parallel `Vec<Leaf>`.
pub struct AccumulatorWitness<F: Field, H: WarpHasher<F>> {
    pub td: Vec<Committed<H, PerfectBinary>>,
    /// Oracle evaluations (codewords). Kept alongside `td` for convenience
    /// — `Committed::leaves()` also returns them, but having the
    /// raw `Vec<F>` avoids an extra clone in the prover hot path where we
    /// concat accumulated with fresh codewords to produce
    /// `shift_query_answers`.
    pub f: Vec<Vec<F>>,
    /// R1CS witnesses.
    pub w: Vec<Vec<F>>,
}

impl<F: Field, H: WarpHasher<F>> AccumulatorWitness<F, H> {
    pub fn empty() -> Self {
        Self {
            td: vec![],
            f: vec![],
            w: vec![],
        }
    }
}

// AccumulatorWitness deliberately does NOT implement `Clone` —
// ark-vc's `Committed<H, S>` has no Clone impl, and faking one by
// re-committing would require `H: Default` (which excludes hashers
// that take parameters, e.g. `Poseidon2Hasher`). Callers that need to
// call `decide` after measuring witness size use `AccWitnessSerializer`
// by reference instead (see `src/serialize.rs`).

/// Proof produced by the WARP accumulation prover.
///
/// Corresponds to `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the
/// paper. Opening proofs are path-pruned, one per committed tree.
#[derive(Clone)]
pub struct WARPProof<F: Field, H: WarpHasher<F>> {
    /// Fresh commitment root.
    pub rt_0: H::Digest,
    /// Fresh code evaluations at 0.
    pub mu_i: Vec<F>,
    /// Evaluation of accumulated oracle at zeta_0.
    pub nu_0: F,
    /// Evaluation claims (OOD + shift query answers).
    pub nu_i: Vec<F>,
    /// Pruned authentication proof for the fresh PESAT commitment.
    pub auth_0: OpeningProof<H>,
    /// Pruned authentication proofs for each accumulated commitment.
    pub auth_j: Vec<OpeningProof<H>>,
    /// Shift query answers: `f_i(x_j)` for each query position `j` and oracle `i`.
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Intermediate output of the PESAT reduction phase.
///
/// This data flows from Phase 2 (PESAT Reduction) into Phase 3
/// (Constrained Code Accumulation).
pub struct PesatOutput<F: Field, H: WarpHasher<F>> {
    pub codewords: Vec<Vec<F>>,
    pub td_0: Committed<H, PerfectBinary>,
    pub mus: Vec<F>,
    pub taus: Vec<Vec<F>>,
}

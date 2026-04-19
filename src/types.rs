use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use std::marker::PhantomData;

use crate::config::WARPConfig;
use ark_vc::blake3::binary::{scheme, Committed, Proof, Scheme, DIGEST_BYTES};
use crate::error::ProverError;
use crate::relations::BundledPESAT;

// result of a prove call: (new accumulator instance + witness, proof)
pub type ProveResult<F> = Result<
    ((AccumulatorInstance<F>, AccumulatorWitness<F>), WARPProof<F>),
    ProverError,
>;

/// Protocol parameters for WARP — the shared configuration used by all IOR phases.
///
/// Post ark-vc migration: the two-parameter Merkle CRH bundle
/// (`mt_leaf_hash_params` + `mt_two_to_one_hash_params`) is gone. The
/// `ark-vc` hasher is stateless (Blake3 over `Vec<F>`), and the scheme
/// is constructed once here with `code.code_len()` leaves.
pub struct WARPParams<F: PrimeField, P: BundledPESAT<F>, C: LinearCode<F> + Clone> {
    pub _f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    pub scheme: Scheme<F>,
}

/// Accumulator instance — the public part of an accumulated claim.
///
/// Corresponds to `(rt, α, μ, (τ, x), η)` in the paper. Roots are raw
/// Blake3 digests (`[u8; 32]`); the `ark_crypto_primitives` generic
/// `InnerDigest` is gone.
#[derive(Clone)]
pub struct AccumulatorInstance<F: Field> {
    /// Merkle roots (one per accumulated oracle), each a 32-byte Blake3 digest.
    pub rt: Vec<[u8; DIGEST_BYTES]>,
    /// Code evaluation points (one per accumulated oracle).
    pub alpha: Vec<Vec<F>>,
    /// Code evaluation targets (one per accumulated oracle).
    pub mu: Vec<F>,
    /// Circuit evaluation points: `(τ_i, x_i)` pairs.
    pub beta: (Vec<Vec<F>>, Vec<Vec<F>>),
    /// Bundled PESAT evaluation targets.
    pub eta: Vec<F>,
}

impl<F: Field> AccumulatorInstance<F> {
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
pub struct AccumulatorWitness<F: PrimeField> {
    pub td: Vec<Committed<F>>,
    /// Oracle evaluations (codewords). Kept alongside `td` for convenience
    /// — `Committed::leaves()` also returns them, but having the
    /// raw `Vec<F>` avoids an extra clone in the prover hot path where we
    /// concat accumulated with fresh codewords to produce
    /// `shift_query_answers`.
    pub f: Vec<Vec<F>>,
    /// R1CS witnesses.
    pub w: Vec<Vec<F>>,
}

impl<F: PrimeField> AccumulatorWitness<F> {
    pub fn empty() -> Self {
        Self {
            td: vec![],
            f: vec![],
            w: vec![],
        }
    }
}

// AccumulatorWitness can't be #[derive(Clone)] because ark-vc's
// Committed<H, S> isn't currently Clone (its Trapdoor stores Vec<Salt>
// + Vec<Digest> + Vec<Symbol>, all of which are trivially Clone, but
// the struct itself wasn't annotated). We only need a clone in two test
// sites; provide it manually so we don't depend on upstream changes.
impl<F: PrimeField> Clone for AccumulatorWitness<F> {
    fn clone(&self) -> Self {
        // SAFETY of the commit: `td` holds the full tree plus the
        // message; we clone it by re-committing the stored leaves. Cost
        // is one extra Merkle build per accumulator, incurred only by
        // callers that actually need a clone (tests + the accumulation
        // loop fixture).
        //
        // This is intentionally not efficient — if a hot path ever
        // needs AccumulatorWitness::clone, we'd either derive Clone
        // upstream in ark-vc or thread a shared-pointer wrapper.
        let sch = scheme::<F>(self.td.first().map(|c| c.leaves().len()).unwrap_or(1));
        let td = self
            .td
            .iter()
            .map(|c| sch.commit(c.leaves()))
            .collect::<Vec<_>>();
        Self {
            td,
            f: self.f.clone(),
            w: self.w.clone(),
        }
    }
}

/// Proof produced by the WARP accumulation prover.
///
/// Corresponds to `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the
/// paper. The old `Vec<Path<MT>>` (one path per shift query) is gone;
/// ark-vc's `OpeningProof` is path-pruned by construction, so one proof
/// covers all `t` queries.
#[derive(Clone)]
pub struct WARPProof<F: PrimeField> {
    /// Fresh commitment root.
    pub rt_0: [u8; DIGEST_BYTES],
    /// Fresh code evaluations at 0.
    pub mu_i: Vec<F>,
    /// Evaluation of accumulated oracle at zeta_0.
    pub nu_0: F,
    /// Evaluation claims (OOD + shift query answers).
    pub nu_i: Vec<F>,
    /// Pruned authentication proof for the fresh PESAT commitment.
    pub auth_0: Proof<F>,
    /// Pruned authentication proofs for each accumulated commitment.
    pub auth_j: Vec<Proof<F>>,
    /// Shift query answers: `f_i(x_j)` for each query position `j` and oracle `i`.
    pub shift_query_answers: Vec<Vec<F>>,
}

/// Intermediate output of the PESAT reduction phase.
///
/// This data flows from Phase 2 (PESAT Reduction) into Phase 3 (Constrained Code Accumulation).
pub struct PesatOutput<F: PrimeField> {
    /// Encoded codewords from fresh witnesses.
    pub codewords: Vec<Vec<F>>,
    /// Committed ark-vc state for the interleaved codeword tree.
    pub td_0: Committed<F>,
    /// Code evaluation claims: `f_i(0)` for each codeword.
    pub mus: Vec<F>,
    /// PESAT evaluation challenges (one per fresh instance).
    pub taus: Vec<Vec<F>>,
}

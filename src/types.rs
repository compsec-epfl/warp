use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_mt::MerkleHasher;
use std::marker::PhantomData;

use crate::config::WARPConfig;
use crate::crypto::merkle::{WarpCommitted, WarpProof};
use crate::error::ProverError;
use crate::relations::BundledPESAT;

/// Prover key — the relation index plus dimensions `(M, N, k)`.
#[derive(Clone)]
pub struct WARPProverKey<P> {
    pub index: P,
    pub m: usize,
    pub n: usize,
    pub k: usize,
}

/// Verifier key — dimensions only `(M, N, k)`.
#[derive(Clone, Copy)]
pub struct WARPVerifierKey {
    pub m: usize,
    pub n: usize,
    pub k: usize,
}

// result of a prove call: (new accumulator instance + witness, proof)
pub type ProveResult<F, H> = Result<
    (
        (AccumulatorInstance<F, H>, AccumulatorWitness<F, H>),
        WARPProof<F, H>,
    ),
    ProverError,
>;

/// Protocol parameters for WARP — the shared configuration used by all IOR phases.
pub struct WARPParams<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, H: MerkleHasher> {
    pub _f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub p: P,
    /// The hasher value (replaces the old leaf-hash + two-to-one-hash parameter pair).
    pub hasher: H,
}

/// Accumulator instance — the public part of an accumulated claim.
///
/// Corresponds to `(rt, α, μ, (τ, x), η)` in the paper.
#[derive(Clone)]
pub struct AccumulatorInstance<F: Field, H: MerkleHasher> {
    /// Merkle tree root commitments.
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

impl<F: Field, H: MerkleHasher> AccumulatorInstance<F, H> {
    pub fn empty() -> Self {
        Self {
            rt: vec![],
            alpha: vec![],
            mu: vec![],
            beta: (vec![], vec![]),
            eta: vec![],
        }
    }

    /// Number of accumulated entries.
    pub fn len(&self) -> usize {
        self.rt.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rt.is_empty()
    }

    /// Builder-style merge: append every field of `other` to `self`. Used
    /// by callers that fold per-round single-entry outputs into a
    /// multi-entry input for the next round.
    pub fn extend(mut self, other: Self) -> Self {
        self.rt.extend(other.rt);
        self.alpha.extend(other.alpha);
        self.mu.extend(other.mu);
        self.beta.0.extend(other.beta.0);
        self.beta.1.extend(other.beta.1);
        self.eta.extend(other.eta);
        self
    }

    /// Push a single typed entry. Pivots `AccumulatorEntry` (AoS) into the
    /// internal parallel-Vec (SoA) layout.
    pub fn push_entry(&mut self, entry: AccumulatorEntry<F, H>)
    where
        H::Digest: Clone,
    {
        self.rt.push(entry.rt);
        self.alpha.push(entry.alpha);
        self.mu.push(entry.mu);
        self.beta.0.push(entry.tau);
        self.beta.1.push(entry.x);
        self.eta.push(entry.eta);
    }

    /// Construct from an explicit list of typed entries.
    pub fn from_entries(entries: Vec<AccumulatorEntry<F, H>>) -> Self
    where
        H::Digest: Clone,
    {
        let mut acc = Self::empty();
        for entry in entries {
            acc.push_entry(entry);
        }
        acc
    }
}

/// One accumulated claim, AoS view of `AccumulatorInstance`. Use this
/// when constructing entries one at a time; pipe through
/// [`AccumulatorInstance::push_entry`] / [`AccumulatorInstance::from_entries`].
pub struct AccumulatorEntry<F: Field, H: MerkleHasher> {
    pub rt: H::Digest,
    pub alpha: Vec<F>,
    pub mu: F,
    pub tau: Vec<F>,
    pub x: Vec<F>,
    pub eta: F,
}

/// Accumulator witness — the private part of an accumulated claim.
///
/// Corresponds to `(td, w)` in the paper. The codewords are stored
/// inside `td[i].codewords()` so we don't carry a parallel `f` field.
pub struct AccumulatorWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    /// Committed multi-vector trees (with the codewords cached inside).
    pub td: Vec<WarpCommitted<H, F>>,
    /// R1CS witnesses.
    pub w: Vec<Vec<F>>,
}

impl<F, H> Clone for AccumulatorWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
    WarpCommitted<H, F>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            td: self.td.clone(),
            w: self.w.clone(),
        }
    }
}

impl<F, H> AccumulatorWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn empty() -> Self {
        Self {
            td: vec![],
            w: vec![],
        }
    }

    pub fn len(&self) -> usize {
        self.td.len()
    }

    pub fn is_empty(&self) -> bool {
        self.td.is_empty()
    }

    /// Builder-style merge — counterpart of [`AccumulatorInstance::extend`].
    pub fn extend(mut self, other: Self) -> Self {
        self.td.extend(other.td);
        self.w.extend(other.w);
        self
    }

    pub fn push_entry(&mut self, entry: AccumulatorWitnessEntry<F, H>) {
        self.td.push(entry.td);
        self.w.push(entry.w);
    }

    pub fn from_entries(entries: Vec<AccumulatorWitnessEntry<F, H>>) -> Self {
        let mut acc = Self::empty();
        for entry in entries {
            acc.push_entry(entry);
        }
        acc
    }
}

/// One witness entry for an accumulated claim — AoS counterpart of
/// `AccumulatorWitness`.
pub struct AccumulatorWitnessEntry<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub td: crate::crypto::merkle::WarpCommitted<H, F>,
    pub w: Vec<F>,
}

/// Proof produced by the WARP accumulation prover.
///
/// Corresponds to `(rt₀, μᵢ, ν₀, νᵢ, auth₀, authⱼ, f_i(x_j))` in the paper.
pub struct WARPProof<F: Field, H: MerkleHasher> {
    /// Fresh Merkle tree root.
    pub rt_0: H::Digest,
    /// Fresh code evaluations at 0.
    pub mu_i: Vec<F>,
    /// Evaluation of accumulated oracle at zeta_0.
    pub nu_0: F,
    /// Evaluation claims (OOD + shift query answers).
    pub nu_i: Vec<F>,
    /// Single multi-opening proof for the fresh PESAT commitment, covering
    /// all queried indices across all `l1` interleaved codewords.
    pub auth_0: WarpProof<H>,
    /// One multi-opening proof per accumulated oracle (each is a single
    /// codeword tree, opened at the same `t` query positions).
    pub auth_j: Vec<WarpProof<H>>,
    /// Shift query answers: `f_i(x_j)` for each query position `j` and oracle `i`.
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

/// Intermediate output of the PESAT reduction phase.
///
/// This data flows from Phase 2 (PESAT Reduction) into Phase 3 (Constrained Code Accumulation).
pub struct PesatOutput<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    /// Encoded codewords from fresh witnesses.
    pub codewords: Vec<Vec<F>>,
    /// Multi-vector commitment over the `l1` codewords.
    pub td_0: WarpCommitted<H, F>,
    /// Code evaluation claims: `f_i(0)` for each codeword.
    pub mus: Vec<F>,
    /// PESAT evaluation challenges (one per fresh instance).
    pub taus: Vec<Vec<F>>,
}

use ark_ff::Field;
use ark_mt::MerkleHasher;

use crate::crypto::merkle::WarpCommitted;

/// Public part of an accumulated claim: `(rt, α, μ, (τ, x), η)` in the paper.
#[derive(Clone)]
pub struct AccumulatorInstance<F: Field, H: MerkleHasher> {
    pub rt: Vec<H::Digest>,
    pub alpha: Vec<Vec<F>>,
    pub mu: Vec<F>,
    pub beta: (Vec<Vec<F>>, Vec<Vec<F>>),
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

    pub fn len(&self) -> usize {
        self.rt.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rt.is_empty()
    }

    pub fn extend(mut self, other: Self) -> Self {
        self.rt.extend(other.rt);
        self.alpha.extend(other.alpha);
        self.mu.extend(other.mu);
        self.beta.0.extend(other.beta.0);
        self.beta.1.extend(other.beta.1);
        self.eta.extend(other.eta);
        self
    }
}

/// Private part of an accumulated claim: `(td, w)` in the paper.
/// Codewords live inside `td[i].codewords()`.
pub struct AccumulatorWitness<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub td: Vec<WarpCommitted<H, F>>,
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

    pub fn extend(mut self, other: Self) -> Self {
        self.td.extend(other.td);
        self.w.extend(other.w);
        self
    }
}

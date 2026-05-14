use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;

use crate::crypto::vc::CommittedCodewords;

/// Per-instance β coordinates absorbed into the accumulator: the `(τ, x)`
/// twin pair. Replaces the old parallel-`Vec` tuple shape which let callers
/// accidentally swap or desync the two halves.
#[derive(Clone, Debug)]
pub struct BetaTwinPair<F: Field> {
    pub tau: Vec<F>,
    pub x: Vec<F>,
}

/// Public part of an accumulated claim: `(rt, α, μ, (τ, x), η)` in the paper.
pub struct AccumulatorInstance<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub rt_commitments: Vec<V::Commitment>,
    pub alpha_fold_vectors: Vec<Vec<F>>,
    pub mu_claimed_evals: Vec<F>,
    pub beta_twin_pairs: Vec<BetaTwinPair<F>>,
    pub eta_predicate_evals: Vec<F>,
}

impl<F, V> Clone for AccumulatorInstance<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rt_commitments: self.rt_commitments.clone(),
            alpha_fold_vectors: self.alpha_fold_vectors.clone(),
            mu_claimed_evals: self.mu_claimed_evals.clone(),
            beta_twin_pairs: self.beta_twin_pairs.clone(),
            eta_predicate_evals: self.eta_predicate_evals.clone(),
        }
    }
}

impl<F, V> AccumulatorInstance<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub fn empty() -> Self {
        Self {
            rt_commitments: vec![],
            alpha_fold_vectors: vec![],
            mu_claimed_evals: vec![],
            beta_twin_pairs: vec![],
            eta_predicate_evals: vec![],
        }
    }

    pub fn extend(mut self, other: Self) -> Self {
        self.rt_commitments.extend(other.rt_commitments);
        self.alpha_fold_vectors.extend(other.alpha_fold_vectors);
        self.mu_claimed_evals.extend(other.mu_claimed_evals);
        self.beta_twin_pairs.extend(other.beta_twin_pairs);
        self.eta_predicate_evals.extend(other.eta_predicate_evals);
        self
    }
}

/// Private part of an accumulated claim: `(td, w)` in the paper.
pub struct AccumulatorWitness<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub td_committed_codewords: Vec<CommittedCodewords<F, V>>,
    pub w_witnesses: Vec<Vec<F>>,
}

impl<F, V> Clone for AccumulatorWitness<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Clone,
    V::CommitmentState: Clone,
{
    fn clone(&self) -> Self {
        Self {
            td_committed_codewords: self.td_committed_codewords.clone(),
            w_witnesses: self.w_witnesses.clone(),
        }
    }
}

impl<F, V> AccumulatorWitness<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub fn empty() -> Self {
        Self {
            td_committed_codewords: vec![],
            w_witnesses: vec![],
        }
    }

    pub fn extend(mut self, other: Self) -> Self {
        self.td_committed_codewords
            .extend(other.td_committed_codewords);
        self.w_witnesses.extend(other.w_witnesses);
        self
    }
}

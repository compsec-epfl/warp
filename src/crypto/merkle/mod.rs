//! Vector-commitment plumbing for warp.
//!
//! Protocol code is generic over `ark_vc::mvc::MultiVectorCommitment`.
//! This module's only job is the [`CommittedCodewords`] helper that
//! pairs `(Commitment, CommitmentState)` from the trait with the
//! original column-codewords — the trait's `State` exposes leaves as
//! row-tuples, but warp threads codewords back for proximity opens
//! and the decider's recompute check.

use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;

pub struct CommittedCodewords<F: Field, V: MultiVectorCommitment<Alphabet = F>> {
    pub commitment: V::Commitment,
    pub state: V::CommitmentState,
    pub codewords: Vec<Vec<F>>,
}

impl<F, V> Clone for CommittedCodewords<F, V>
where
    F: Field,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Clone,
    V::CommitmentState: Clone,
{
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment.clone(),
            state: self.state.clone(),
            codewords: self.codewords.clone(),
        }
    }
}

//! [`CommittedCodewords`] keeps the column-codewords alongside the
//! opaque `V::CommitmentState` so warp can re-encode them in the decider.

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

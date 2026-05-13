use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Encoding, ProverState};

use crate::warp::AccumulatorInstance;

// absorb a list of plain instances into the transcript
pub fn absorb_instances<F: Field + Encoding<[u8]>>(
    prover_state: &mut ProverState,
    instances: &[Vec<F>],
) {
    for instance in instances {
        for f in instance {
            prover_state.prover_message(f);
        }
    }
}

// absorb an AccumulatorInstance into the transcript
impl<F, V> AccumulatorInstance<F, V>
where
    F: Field + Encoding<[u8]>,
    V: MultiVectorCommitment<Alphabet = F>,
    V::Commitment: Encoding<[u8]> + spongefish::NargSerialize,
{
    pub fn absorb_into(&self, prover_state: &mut ProverState) {
        for commitment in &self.rt_commitments {
            prover_state.prover_message(commitment);
        }

        for alpha in &self.alpha_fold_vectors {
            for f in alpha {
                prover_state.prover_message(f);
            }
        }

        for f in &self.mu_claimed_evals {
            prover_state.prover_message(f);
        }

        // Layout: all τ vectors first (l2 of them), then all x vectors.
        // Verifier reads in the same order. Keeping the τ/x halves in
        // separate passes lets the verifier reconstruct the pair list
        // without needing length-prefixes per pair.
        for pair in &self.beta_twin_pairs {
            for f in &pair.tau {
                prover_state.prover_message(f);
            }
        }
        for pair in &self.beta_twin_pairs {
            for f in &pair.x {
                prover_state.prover_message(f);
            }
        }

        for f in &self.eta_predicate_evals {
            prover_state.prover_message(f);
        }
    }
}

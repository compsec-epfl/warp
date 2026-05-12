use ark_ff::Field;
use ark_mt::MerkleHasher;
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
impl<F, H> AccumulatorInstance<F, H>
where
    F: Field + Encoding<[u8]>,
    H: MerkleHasher,
    H::Digest: Encoding<[u8]>,
{
    pub fn absorb_into(&self, prover_state: &mut ProverState) {
        for digest in &self.rt_merkle_roots {
            prover_state.prover_message(digest);
        }

        for alpha in &self.alpha_fold_vectors {
            for f in alpha {
                prover_state.prover_message(f);
            }
        }

        for f in &self.mu_claimed_evals {
            prover_state.prover_message(f);
        }

        for tau in &self.beta_twin_pairs.0 {
            for f in tau {
                prover_state.prover_message(f);
            }
        }

        for x in &self.beta_twin_pairs.1 {
            for f in x {
                prover_state.prover_message(f);
            }
        }

        for f in &self.eta_predicate_evals {
            prover_state.prover_message(f);
        }
    }
}

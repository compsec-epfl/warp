use ark_ff::Field;
use spongefish::{Encoding, ProverState};

use crate::types::AccumulatorInstance;
use ark_crypto_primitives::merkle_tree::Config;

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
impl<
        F: Field + Encoding<[u8]>,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > AccumulatorInstance<F, MT>
{
    pub fn absorb_into(&self, prover_state: &mut ProverState) {
        for digest in &self.rt {
            let bytes: [u8; 32] = digest.as_ref().try_into().expect("digest must be 32 bytes");
            prover_state.prover_message(&bytes);
        }

        for alpha in &self.alpha {
            for f in alpha {
                prover_state.prover_message(f);
            }
        }

        for f in &self.mu {
            prover_state.prover_message(f);
        }

        for tau in &self.beta.0 {
            for f in tau {
                prover_state.prover_message(f);
            }
        }

        for x in &self.beta.1 {
            for f in x {
                prover_state.prover_message(f);
            }
        }

        for f in &self.eta {
            prover_state.prover_message(f);
        }
    }
}

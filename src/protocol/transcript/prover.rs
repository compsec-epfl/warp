use ark_ff::Field;
use spongefish::{Encoding, ProverState};

use crate::types::AccumulatorInstance;

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
impl<F: Field + Encoding<[u8]>> AccumulatorInstance<F> {
    pub fn absorb_into(&self, prover_state: &mut ProverState) {
        for digest in &self.rt {
            // ark-vc roots are already `[u8; 32]`; no conversion needed.
            prover_state.prover_message(digest);
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

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;

use crate::{linear_code::MultiConstrainedCode, WARPError};

use super::IOR;
use spongefish::{DuplexSpongeInterface, ProverState, Unit as SpongefishUnit};

pub struct BatchCodewordsIOR<const R: usize, const L: usize> {}

impl<
        F: Field + SpongefishUnit,
        MC: MultiConstrainedCode<F, Config: Sync>,
        MT: Config,
        S: DuplexSpongeInterface<F>,
        const R: usize,
        const L: usize,
    > IOR<F, MC, MT, S> for BatchCodewordsIOR<R, L>
{
    // r \gamma, \mu pairs
    // (\mathbf{\gamma}, (\mathbf{\alpha_i}, \mu_i)_{i \in [r]}, \beta, \eta)
    type Instance<'a> = (&'a [F], [(&'a [F], F); R]);

    // l codewords to be batched together
    type Witness<'a> = &'a [&'a [F]; L];

    // TODO
    type OutputInstance<'a> = &'a [&'a Vec<F>; L];
    type OutputWitness<'a> = &'a [&'a Vec<F>; L];

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState<S, F>,
        instance: Self::Instance<'a>,
        witness: Self::Witness<'a>,
    ) -> Result<(Self::OutputInstance<'a>, Self::OutputWitness<'a>), WARPError> {
        todo!()
    }

    fn verify() {
        todo!()
    }
}

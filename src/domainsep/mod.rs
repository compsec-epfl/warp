use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{codecs::arkworks_algebra::FieldDomainSeparator, ByteDomainSeparator, Unit};

use crate::{
    iors::{codeword_batching::PseudoBatchingIORConfig, pesat::TwinConstraintIORConfig},
    linear_code::LinearCode,
    utils::DigestDomainSeparator,
};

// TODO
pub trait WARPDomainSeparator<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self;
    fn pseudo_batching_ior(self, conf: &PseudoBatchingIORConfig<F, C, MT>) -> Self;
}

impl<
        F: Field + Unit,
        C: LinearCode<F>,
        MT: Config,
        DomainSeparator: ByteDomainSeparator + FieldDomainSeparator<F> + DigestDomainSeparator<MT>,
    > WARPDomainSeparator<F, C, MT> for DomainSeparator
{
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self {
        self.add_digest("root")
            .add_scalars(conf.l, "mu")
            .challenge_scalars(conf.log_m * conf.l, "tau")
    }

    fn pseudo_batching_ior(self, conf: &PseudoBatchingIORConfig<F, C, MT>) -> Self {
        self.add_scalars(1, "root")
            .add_scalars(1, "mu")
            .add_scalars(1, "eta")
            .challenge_scalars(conf.s * conf.log_n as usize, "alpha")
            .add_scalars(conf.s, "mus")
            .challenge_bytes((conf.t * conf.log_n).div_ceil(8), "x")
    }
}

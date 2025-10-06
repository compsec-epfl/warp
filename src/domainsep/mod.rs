use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{codecs::arkworks_algebra::FieldDomainSeparator, ByteDomainSeparator, Unit};

use crate::{iors::pesat::TwinConstraintIORConfig, linear_code::LinearCode};

// TODO
pub trait WARPDomainSeparator<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self;
}

impl<
        F: Field + Unit,
        C: LinearCode<F>,
        MT: Config,
        DomainSeparator: ByteDomainSeparator + FieldDomainSeparator<F>,
    > WARPDomainSeparator<F, C, MT> for DomainSeparator
{
    fn pesat_ior(self, conf: &TwinConstraintIORConfig<F, C, MT>) -> Self {
        self.add_scalars(1, "root")
            .add_scalars(conf.l, "mu")
            .challenge_scalars(conf.log_m * conf.l, "tau")
    }
}

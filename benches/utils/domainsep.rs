use ark_codes::traits::LinearCode;
use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{DomainSeparator, Unit};
use warp::config::WARPConfig;
use warp::protocol::domainsep::WARPDomainSeparator;
use warp::relations::BundledPESAT;

pub fn init_domain_sep<
    F: Field + Unit,
    C: LinearCode<F>,
    MT: Config,
    P: BundledPESAT<F, Config = (usize, usize, usize)>,
>(
    session_identifier: &str,
    warp_config: WARPConfig<F, P>,
) -> DomainSeparator
where
    DomainSeparator: WARPDomainSeparator<F, C, MT>,
{
    let domainsep = DomainSeparator::new(session_identifier);
    WARPDomainSeparator::<F, C, MT>::warp(domainsep, warp_config)
}

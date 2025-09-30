use ark_ff::Field;
use spongefish::{
    duplex_sponge::{DuplexSponge, Permutation},
    DomainSeparator, Unit as SpongefishUnit,
};

// TODO: remove once domain separator for PESAT IOR is clear
pub fn initialize_pesat_ior_domain_separator<F: Field + SpongefishUnit, C: Permutation<U = F>>(
    l1: usize,
    log_m: usize,
) -> DomainSeparator<DuplexSponge<C>, F> {
    DomainSeparator::<DuplexSponge<C>, F>::new("bench::ior::pesat")
        .absorb(1, "root")
        .absorb(l1, "mu")
        .squeeze(log_m * l1, "tau")
}

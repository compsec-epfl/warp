use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use spongefish::{
    duplex_sponge::{DuplexSponge, Permutation},
    DomainSeparator, Unit as SpongefishUnit,
};

// TODO
pub trait PESATIORDomainSeparator<F: Field + SpongefishUnit, MT: Config, C: Permutation<U = F>> {
    fn new(l1: usize, log_m: usize) -> DomainSeparator<DuplexSponge<C>, F>;
}

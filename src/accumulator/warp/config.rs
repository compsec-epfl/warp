use ark_ff::Field;

use crate::relations::BundledPESAT;

#[derive(Clone)]
pub struct WARPConfig<F: Field, P: BundledPESAT<F>> {
    pub l: usize,
    pub l1: usize,
    pub s: usize,
    pub t: usize,
    pub p_conf: P::Config,
    pub n: usize,
}

impl<F: Field, P: BundledPESAT<F>> WARPConfig<F, P> {
    pub fn new(l: usize, l1: usize, s: usize, t: usize, p_conf: P::Config, n: usize) -> Self {
        Self {
            l,
            l1,
            s,
            t,
            p_conf,
            n,
        }
    }
}

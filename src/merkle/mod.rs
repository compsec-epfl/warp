// {blake3, digest, parameters, mod}.rs have been copied from whir
// https://github.com/WizardOfMenlo/whir
use std::sync::atomic::{AtomicUsize, Ordering};

pub mod blake3;
pub mod digest;
pub mod parameters;
pub mod poseidon;

#[derive(Debug, Default)]
pub struct HashCounter;

static HASH_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl HashCounter {
    pub fn reset() {
        HASH_COUNTER.store(0, Ordering::SeqCst);
    }

    pub fn get() -> usize {
        HASH_COUNTER.load(Ordering::SeqCst)
    }
}

use std::sync::atomic::{AtomicUsize, Ordering};

use ark_std::rand::RngCore;
pub use poseidon::poseidon_test_params;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, DigestConverter},
    Error,
};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use spongefish::{
    ByteDomainSeparator, BytesToUnitSerialize, DomainSeparator, ProofError, ProofResult,
    ProverState,
};
use whir::crypto::merkle_tree::parameters::MerkleTreeParams;

pub mod poseidon;

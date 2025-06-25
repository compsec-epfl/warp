mod is_prime;
mod merkle_inclusion;
mod relation;

pub use is_prime::{IsPrimeInstance, IsPrimeRelation, IsPrimeWitness};
pub use merkle_inclusion::{MerkleInclusionRelation, MerkleInclusionWitness};
pub use relation::Relation;

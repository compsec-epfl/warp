mod description;
mod relation;

use ark_ff::Field;
pub use description::SerializableConstraintMatrices;
pub use relation::{BundledPESAT, Relation};

use crate::WARPError;

use super::r1cs::R1CS;

pub trait ToPolySystem<F: Field>: Relation<F> {
    // generate an r1cs polynomial system ((A, B, C), M, N, k) for a relation
    fn into_r1cs(config: &Self::Config) -> Result<R1CS<F>, WARPError>;
}

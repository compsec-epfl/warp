mod description;
pub mod r1cs;

pub use description::SerializableConstraintMatrices;

use ark_ff::Field;
use r1cs::R1CS;

use crate::WARPError;

pub trait Relation<F: Field> {
    type Instance;
    type Witness;
    type Config;
    fn constraints(&self) -> usize;
    fn description(config: &Self::Config) -> Vec<u8>;
    fn instance(&self) -> Self::Instance;
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self;
    fn public_config(&self) -> Vec<u8>;
    fn public_inputs(&self) -> Vec<u8>;
    fn private_inputs(&self) -> Vec<u8>;
    fn verify(&self) -> bool;
    fn witness(&self) -> Self::Witness;
}

pub trait BundledPESAT<F: Field> {
    type Config;
    type Constraints;
    fn evaluate_bundled(&self, zero_evader_evals: &[F], z: &[F]) -> Result<F, WARPError>;
    fn config(&self) -> Self::Config;
    fn description(&self) -> Vec<u8>;
    fn constraints(&self) -> &Self::Constraints;
}

pub trait ToPolySystem<F: Field>: Relation<F> {
    // generate an r1cs polynomial system ((A, B, C), M, N, k) for a relation
    fn into_r1cs(config: &Self::Config) -> Result<R1CS<F>, WARPError>;
}

mod description;
pub mod r1cs;

pub use description::SerializableConstraintMatrices;

use ark_ff::Field;

use crate::error::WARPError;

pub trait Relation<F: Field> {
    type Instance;
    type Witness;
    type Config;
    fn constraints(&self) -> usize;
    fn describe_from_config(config: &Self::Config) -> Vec<u8>;
    fn instance(&self) -> Self::Instance;
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self;
    fn public_config(&self) -> Vec<u8>;
    fn public_inputs(&self) -> Vec<u8>;
    fn private_inputs(&self) -> Vec<u8>;
    fn verify(&self) -> bool;
    fn witness(&self) -> Self::Witness;
}

pub trait PolyPredicate<F: Field> {
    type Config;
    fn evaluate_bundled(&self, zero_evader_evals: &[F], z: &[F]) -> Result<F, WARPError>;
    fn config(&self) -> Self::Config;
    fn description(&self) -> Vec<u8>;
    fn constraints(&self) -> &r1cs::R1CSConstraints<F>;
}

pub trait Arithmetize<F: Field> {
    type Config;
    type Predicate;
    fn arithmetize(config: &Self::Config) -> Result<Self::Predicate, WARPError>;
}

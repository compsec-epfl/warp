use ark_ff::Field;

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

    fn evaluate_bundled(&self, zero_evader_evals: &Vec<F>, z: &Vec<F>) -> Result<F, WARPError>;

    // returns (M, N, k)
    fn config(&self) -> Self::Config;

    fn description(&self) -> Vec<u8>;
}

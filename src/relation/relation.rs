use ark_ff::Field;

pub trait Relation<F: Field> {
    type Instance;
    type Witness;
    type Config;
    fn constraints(&self) -> usize;
    fn description(config: &Self::Config) -> Vec<u8>;
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self;
    fn public_inputs(&self) -> Vec<u8>;
    fn verify(&self) -> bool;
}

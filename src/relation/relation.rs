use ark_ff::Field;

pub trait Relation<F: Field> {
    type Instance;
    type Witness;
    type Config; // for many relations this is empty, but sometimes needed for hash parameters etc
    fn description(config: &Self::Config) -> Vec<u8>;
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self;
    fn verify(&self) -> bool;
}

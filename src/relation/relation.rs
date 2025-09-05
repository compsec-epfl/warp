use ark_ff::Field;

// pub trait Instance<F: Field> {
//     fn vec_f(&self) -> Vec<F>;
// }

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

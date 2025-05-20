use ark_ff::Field;

pub trait Relation<F: Field> {
    type Instance;
    type Witness;
    fn new(instance: Self::Instance, witness: Self::Witness) -> Self;
    fn verify(&self) -> bool;
}

use ark_ff::Field;

pub trait Relation<F: Field> {
    type Witness;
    fn assign_witness(witness: Self::Witness) -> Self;
    fn verify(&self) -> bool;
}

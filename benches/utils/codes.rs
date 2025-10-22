use ark_ff::Field;
use warp::{
    linear_code::{MultiConstrainedReedSolomon, ReedSolomon},
    relations::r1cs::R1CS,
};

// type for a twin constrained rs code over R1CS
pub type TwinConstraintRS<F: Field> = MultiConstrainedReedSolomon<F, ReedSolomon<F>, R1CS<F>>;

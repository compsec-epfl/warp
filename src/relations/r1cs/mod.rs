pub mod identity;
pub mod is_prime;
pub mod merkle_inclusion;
pub mod preimage;
use std::collections::HashMap;

use ark_ff::Field;
use ark_relations::r1cs::ConstraintSystemRef;
pub use identity::{IdentityInstance, IdentityRelation, IdentitySynthesizer, IdentityWitness};
pub use is_prime::{
    IsPrimeInstance, IsPrimeRelation, IsPrimeSynthesizer, IsPrimeWitness, PrattCertificate,
};
pub use merkle_inclusion::{MerkleInclusionRelation, MerkleInclusionWitness};
pub use preimage::{PreimageConfig, PreimageInstance, PreimageRelation, PreimageWitness};
use whir::poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint};

use crate::WARPError;

pub struct R1CS<F: Field> {
    // we access linear combinations using binary hypercube points
    // point -> (a_i, b_i, c_i)
    // point is encoded viat the n least significant bits of a usize
    pub p: HashMap<usize, (Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>)>,
    pub m: usize,
    pub n: usize,
    pub k: usize,
    pub log_m: usize,
}

impl<F: Field> TryFrom<ConstraintSystemRef<F>> for R1CS<F> {
    type Error = WARPError;

    fn try_from(cs: ConstraintSystemRef<F>) -> Result<Self, Self::Error> {
        let matrices = cs.to_matrices().unwrap();

        // number of constraints should be to be power of 2
        let m = matrices.num_constraints.next_power_of_two();
        let n = matrices.num_instance_variables + matrices.num_witness_variables;
        let k = matrices.num_witness_variables;
        let log_m = m.ilog2().try_into().unwrap(); // safe since warp/lib.rs forbids compiling on platforms
                                                   // with 16-bits pointers width
        let mut a = matrices.a.into_iter();
        let mut b = matrices.b.into_iter();
        let mut c = matrices.c.into_iter();
        let mut p = HashMap::new();
        let hypercube = BinaryHypercube::new(log_m);
        for point in hypercube {
            // when there are no constraints left, we store an empty one
            let a_i = a.next().unwrap_or(Vec::with_capacity(0));
            let b_i = b.next().unwrap_or(Vec::with_capacity(0));
            let c_i = c.next().unwrap_or(Vec::with_capacity(0));
            p.insert(point.0, (a_i, b_i, c_i));
        }
        Ok(R1CS { p, m, n, k, log_m })
    }
}

impl<F: Field> R1CS<F> {
    // evaluate the given sparse linear combination over the provided z vector
    fn eval_lc(lc: &Vec<(F, usize)>, z: &Vec<F>) -> Result<F, WARPError> {
        let mut acc = F::zero();
        for (coeff, var) in lc.iter() {
            acc += *coeff
                * z.get(*var)
                    .ok_or(WARPError::R1CSWitnessSize(z.len(), *var))?;
        }
        Ok(acc)
    }

    // eval the R1CS i-th linear combination, where i is represented as an hypercube point
    pub fn eval_p_i(&self, z: &Vec<F>, i: &BinaryHypercubePoint) -> Result<F, WARPError> {
        let (a_i, b_i, c_i) = self.p.get(&i.0).ok_or(WARPError::R1CSNonExistingLC)?;
        let eval_a_i = Self::eval_lc(a_i, z)?;
        let eval_b_i = Self::eval_lc(b_i, z)?;
        let eval_c_i = Self::eval_lc(c_i, z)?;
        Ok(eval_a_i * eval_b_i - eval_c_i)
    }
}

pub mod hashchain;

use ark_ff::Field;
use ark_relations::gr1cs::ConstraintSystemRef;
use rayon::prelude::*;

use crate::error::WARPError;
use crate::relations::SerializableConstraintMatrices;

use super::BundledPESAT;

pub type R1CSConstraints<F> = Vec<(Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>)>;

#[derive(Clone)]
pub struct R1CS<F: Field> {
    // we access linear combinations using binary hypercube points
    // point -> (a_i, b_i, c_i)
    // point is encoded via the n least significant bits of a usize
    pub p: R1CSConstraints<F>,
    pub m: usize,
    pub n: usize,
    pub k: usize,
    pub log_m: usize,
    pub log_n: usize,
}

impl<F: Field> TryFrom<ConstraintSystemRef<F>> for R1CS<F> {
    type Error = WARPError;

    fn try_from(cs: ConstraintSystemRef<F>) -> Result<Self, Self::Error> {
        use ark_relations::gr1cs::R1CS_PREDICATE_LABEL;

        let inner = cs.into_inner().unwrap();
        let all_matrices = inner.to_matrices().unwrap();
        let r1cs_matrices = all_matrices
            .get(R1CS_PREDICATE_LABEL)
            .expect("R1CS predicate must exist");

        let num_constraints = inner
            .get_predicate_num_constraints(R1CS_PREDICATE_LABEL)
            .unwrap_or(0);

        // number of constraints should be to be power of 2
        let m = num_constraints.next_power_of_two();
        let n = inner.num_instance_variables() + inner.num_witness_variables();
        let k = inner.num_witness_variables();

        // both `unwrap()` calls below are safe since warp/lib.rs forbids compiling on platforms
        // with 16-bits pointers width
        let log_m = m.ilog2().try_into().unwrap();
        let log_n = n.ilog2().try_into().unwrap();

        let mut a = r1cs_matrices[0].clone().into_iter();
        let mut b = r1cs_matrices[1].clone().into_iter();
        let mut c = r1cs_matrices[2].clone().into_iter();
        let mut p = vec![];
        for _ in 0..m {
            // when there are no constraints left, we store an empty one
            let a_i = a.next().unwrap_or(Vec::with_capacity(0));
            let b_i = b.next().unwrap_or(Vec::with_capacity(0));
            let c_i = c.next().unwrap_or(Vec::with_capacity(0));
            p.push((a_i, b_i, c_i));
        }

        Ok(R1CS {
            p,
            m,
            n,
            k,
            log_m,
            log_n,
        })
    }
}

impl<F: Field> R1CS<F> {
    // evaluate the given sparse linear combination over the provided z vector
    fn eval_lc(lc: &[(F, usize)], z: &[F]) -> Result<F, WARPError> {
        let mut acc = F::zero();
        for (coeff, var) in lc.iter() {
            acc += *coeff
                * z.get(*var)
                    .ok_or(WARPError::R1CSWitnessSize(z.len(), *var))?;
        }
        Ok(acc)
    }

    // eval the R1CS i-th linear combination, where i is represented as an hypercube point
    pub fn eval_p_i(&self, z: &[F], i: usize) -> Result<F, WARPError> {
        let (a_i, b_i, c_i) = self.p.get(i).ok_or(WARPError::R1CSNonExistingLC)?;
        let eval_a_i = Self::eval_lc(a_i, z)?;
        let eval_b_i = Self::eval_lc(b_i, z)?;
        let eval_c_i = Self::eval_lc(c_i, z)?;
        Ok(eval_a_i * eval_b_i - eval_c_i)
    }
}

impl<F: Field> BundledPESAT<F> for R1CS<F> {
    type Config = (usize, usize, usize);
    type Constraints = R1CSConstraints<F>;

    fn evaluate_bundled(&self, zero_evader_evals: &[F], z: &[F]) -> Result<F, WARPError> {
        if zero_evader_evals.len() < self.m {
            return Err(WARPError::ZeroEvaderSize(
                zero_evader_evals.len(),
                self.m - 1,
            ));
        }
        (0..self.m)
            .into_par_iter()
            .map(|i| -> Result<F, WARPError> {
                let p_i = self.eval_p_i(z, i)?;
                Ok(zero_evader_evals[i] * p_i)
            })
            .try_reduce(|| F::ZERO, |acc, x| Ok(acc + x))
    }

    fn config(&self) -> Self::Config {
        (self.m, self.n, self.k)
    }

    fn description(&self) -> Vec<u8> {
        // Serializes the *concrete matrix triple* so two R1CS systems with
        // identical (m, n, k) but different constraints absorb to different
        // bytes (and therefore distinct transcripts). Without this,
        // `WARP::index` would only commit to dimensions — a soundness hole
        // in any downstream protocol that trusts `index()` to bind the
        // relation.
        let a: Vec<Vec<(F, usize)>> = self.p.iter().map(|(a, _, _)| a.clone()).collect();
        let b: Vec<Vec<(F, usize)>> = self.p.iter().map(|(_, b, _)| b.clone()).collect();
        let c: Vec<Vec<(F, usize)>> = self.p.iter().map(|(_, _, c)| c.clone()).collect();
        let serializable = SerializableConstraintMatrices {
            num_instance_variables: self.n - self.k,
            num_witness_variables: self.k,
            num_constraints: self.m,
            a: SerializableConstraintMatrices::serialize_nested_field(a),
            b: SerializableConstraintMatrices::serialize_nested_field(b),
            c: SerializableConstraintMatrices::serialize_nested_field(c),
        };
        serde_json::to_string(&serializable)
            .expect("matrix serialization is infallible")
            .into_bytes()
    }

    fn constraints(&self) -> &Self::Constraints {
        &self.p
    }
}

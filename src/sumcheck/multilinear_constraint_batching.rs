use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
};

use ark_ff::Field;
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};

pub type UsizeMap<V> = HashMap<usize, V, BuildHasherDefault<IdentityHasher>>;

#[derive(Default)]
pub struct IdentityHasher(usize);

impl Hasher for IdentityHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }

    fn write_usize(&mut self, n: usize) {
        self.0 = n
    }

    fn finish(&self) -> u64 {
        self.0 as u64
    }
}

use super::{
    vsbw_reduce_evaluations, Sumcheck, WARPSumcheckProverError, WARPSumcheckVerifierError,
};

pub struct MultilinearConstraintBatchingSumcheck {}

impl<F: Field> Sumcheck<F> for MultilinearConstraintBatchingSumcheck {
    type Evaluations = (Vec<F>, Vec<Vec<F>>, UsizeMap<F>);
    type ProverAuxiliary<'a> = ();
    type VerifierAuxiliary<'a> = ();
    type Target = F;
    type Challenge = F;

    fn prove_round(
        prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
        (f_evals, ood_evals_vec, id_non_0_eval_sums): &mut Self::Evaluations,
        _aux: &Self::ProverAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckProverError> {
        let (sum_00, sum_11, sum_0110) = (0..f_evals.len())
            .step_by(2)
            .map(|a| {
                let p0 = f_evals[a];
                let p1 = f_evals[a + 1];
                let q0 = ood_evals_vec.iter().map(|v| v[a]).sum::<F>()
                    + id_non_0_eval_sums.get(&a).unwrap_or(&F::zero());
                let q1 = ood_evals_vec.iter().map(|v| v[a + 1]).sum::<F>()
                    + id_non_0_eval_sums.get(&(a + 1)).unwrap_or(&F::zero());
                (p0 * q0, p1 * q1, p0 * q1 + p1 * q0)
            })
            .fold((F::zero(), F::zero(), F::zero()), |acc, x| {
                (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2)
            });

        prover_state.add_scalars(&[sum_00, sum_11, sum_0110])?;
        // get challenge
        let [c] = prover_state.challenge_scalars::<1>()?;

        // update evaluation tables
        *f_evals = vsbw_reduce_evaluations(f_evals, c);
        ood_evals_vec.iter_mut().for_each(|e| {
            *e = vsbw_reduce_evaluations(e, c);
        });
        let mut map = UsizeMap::default();
        for (&i, &eval) in id_non_0_eval_sums.iter() {
            *map.entry(i >> 1).or_insert(F::zero()) +=
                eval * if i & 1 == 1 { c } else { F::one() - c };
        }
        *id_non_0_eval_sums = map;
        Ok(c)
    }

    fn verify_round(
        verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
        target: &mut Self::Target,
        _aux: &Self::VerifierAuxiliary<'_>,
    ) -> Result<Self::Challenge, WARPSumcheckVerifierError> {
        let [sum_00, sum_11, sum_0110]: [F; 3] = verifier_state.next_scalars()?;
        if sum_00 + sum_11 != *target {
            return Err(WARPSumcheckVerifierError::SumcheckRound);
        }

        // get challenge
        let [c]: [F; 1] = verifier_state.challenge_scalars()?;
        // update sumcheck target for next round
        *target =
            (*target - sum_0110) * c.square() + sum_00 * (F::one() - c.double()) + sum_0110 * c;
        Ok(c)
    }
}

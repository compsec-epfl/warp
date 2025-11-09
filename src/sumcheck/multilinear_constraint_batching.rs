use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
};

use ark_ff::Field;
use efficient_sumcheck::{
    multilinear::{reductions::pairwise, ReduceMode},
    multilinear_product::{TimeProductProver, TimeProductProverConfig},
    prover::Prover,
    streams::{MemoryStream, Stream},
};
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

use super::{Sumcheck, WARPSumcheckProverError, WARPSumcheckVerifierError};

fn sum_columns<F: Field>(matrix: &Vec<Vec<F>>) -> Vec<F> {
    if matrix.is_empty() {
        return vec![];
    }
    let mut result = vec![F::ZERO; matrix[0].len()];
    for row in matrix {
        for (i, &val) in row.iter().enumerate() {
            result[i] += val;
        }
    }
    result
}

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
        let mut preprocessed_g = sum_columns(ood_evals_vec);
        for (i, v) in preprocessed_g.iter_mut().enumerate() {
            *v += id_non_0_eval_sums.get(&i).unwrap_or(&F::ZERO);
        }

        // round evaluation
        let f = MemoryStream::new(f_evals.to_vec());
        let g = MemoryStream::new(preprocessed_g.clone());
        let config =
            TimeProductProverConfig::new(f.num_variables(), vec![f, g], ReduceMode::Pairwise);
        let mut time_product_prover = TimeProductProver::new(config);
        let message = time_product_prover.next_message(None).unwrap();

        prover_state.add_scalars(&[message.0, message.1, message.2])?;
        // get challenge
        let [c] = prover_state.challenge_scalars::<1>()?;

        // update evaluation tables
        pairwise::reduce_evaluations(f_evals, c);
        ood_evals_vec.iter_mut().for_each(|e| {
            pairwise::reduce_evaluations(e, c);
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

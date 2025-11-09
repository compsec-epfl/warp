use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    log2,
};
use efficient_sumcheck::{
    multilinear::{reductions::pairwise, ReduceMode},
    multilinear_product::{TimeProductProver, TimeProductProverConfig},
    prover::Prover,
    streams::{MemoryStream, Stream},
};
use spongefish::codecs::arkworks_algebra::{
    FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField,
};

use crate::{sumcheck::Sumcheck, utils::poly::eq_poly, WARPError};

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
    ) -> Result<Self::Challenge, WARPError> {
        // preprocess g so that we get a product sumcheck f * g
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
        // let (sum_00, sum_11, sum_0110) = (0..f_evals.len())
        //     .step_by(2)
        //     .map(|a| {
        //         let p0 = f_evals[a];
        //         let p1 = f_evals[a + 1];
        //         let q0 = preprocessed_g[a];
        //         let q1 = preprocessed_g[a + 1];
        //         (p0 * q0, p1 * q1, p0 * q1 + p1 * q0)
        //     })
        //     .fold((F::zero(), F::zero(), F::zero()), |acc, x| {
        //         (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2)
        //     });


        // absorb
        prover_state.add_scalars(&[message.0, message.1, message.2]).unwrap();

        // squeeze
        let [c] = prover_state.challenge_scalars::<1>().unwrap();

        // reduce
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
    ) -> Result<Self::Challenge, WARPError> {
        let [sum_00, sum_11, sum_0110]: [F; 3] = verifier_state.next_scalars()?;
        if sum_00 + sum_11 != *target {
            return Err(WARPError::VerificationFailed(
                "Evaluations of the claimed polynomial do not sum to the target".to_string(),
            ));
        }

        // get challenge
        let [c]: [F; 1] = verifier_state.challenge_scalars()?;
        // update sumcheck target for next round
        *target =
            (*target - sum_0110) * c.square() + sum_00 * (F::one() - c.double()) + sum_0110 * c;
        Ok(c)
    }
}

pub fn prover<F: Field, const S: usize, const R: usize, const N: usize>(
    prover_state: &mut (impl FieldToUnitSerialize<F> + UnitToField<F>),
    alpha_vec: Vec<Vec<F>>,
    _mu_vec: Vec<F>,
    beta: Vec<F>,
    eta: F,
    u: Vec<F>,
) -> Result<((Vec<F>, F, Vec<F>, F), Vec<F>), WARPError> {
    let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);

    // 8.1 step 1, sample challenge \xi
    let mut xi = vec![F::zero(); log2(R) as usize];
    prover_state.fill_challenge_scalars(&mut xi)?;
    let xi_eq_evals = (0..R).map(|i| eq_poly(&xi, i)).collect::<Vec<_>>();

    // 8.1 step 2, initialize evaluation tables
    let f_evals = u.clone();
    let ood_evals_vec = (0..1 + S)
        .map(|i| {
            (0..N)
                .map(|a| eq_poly(&alpha_vec[i], a) * xi_eq_evals[i])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    // Optimization from Hyperplonk
    let mut id_non_0_eval_sums = UsizeMap::default();
    for i in 1 + S..R {
        let a = alpha_vec[i]
            .iter()
            .enumerate()
            .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
            .sum::<usize>();
        *id_non_0_eval_sums.entry(a).or_insert(F::zero()) += &xi_eq_evals[i];
    }

    // TODO (z-tech): we can preprocess ood_evals_vec, id_non_0_eval_sums to g and then we have
    // product sumcheck f * g
    // can probably pass sponge state to function in efficient-sumcheck and return new sponge
    // 8.1 step 2, sumcheck starts

    let alpha = MultilinearConstraintBatchingSumcheck::prove(
        prover_state,
        &mut (f_evals, ood_evals_vec, id_non_0_eval_sums),
        &(),
        log2(N) as usize,
    )?;

    let mu = u_mle.evaluate(&alpha);

    prover_state.add_scalars(&[mu])?;

    Ok(((alpha, mu, beta, eta), u))
}

pub fn verifier<F: Field, const R: usize, const N: usize>(
    verifier_state: &mut (impl FieldToUnitDeserialize<F> + UnitToField<F>),
    alpha_vec: Vec<Vec<F>>,
    mu_vec: Vec<F>,
    beta: Vec<F>,
    eta: F,
) -> Result<(Vec<F>, F, Vec<F>, F), WARPError> {
    // 8.1 step 1, sample challenge \xi
    let mut xi = vec![F::zero(); log2(R) as usize];
    verifier_state.fill_challenge_scalars(&mut xi)?;
    let xi_eq_evals = (0..R).map(|i| eq_poly(&xi, i)).collect::<Vec<_>>();

    // 8.1 step 2, RHS of the equation (sumcheck target)
    let mut sigma = (0..R).map(|i| mu_vec[i] * xi_eq_evals[i]).sum::<F>();

    // 8.1 step 2, initialize evaluation tables
    let alpha = MultilinearConstraintBatchingSumcheck::verify(
        verifier_state,
        &mut sigma,
        &(),
        log2(N) as usize,
    )?;

    let [mu]: [F; 1] = verifier_state.next_scalars()?;

    if mu
        * (0..R)
            .map(|i| {
                xi_eq_evals[i]
                    * alpha
                        .iter()
                        .zip(&alpha_vec[i])
                        .map(|(a, b)| a.double() * b - a - b + F::one())
                        .product::<F>()
            })
            .sum::<F>()
        != sigma
    {
        return Err(WARPError::VerificationFailed(
            "eq^*(alpha) * mu does not match the sumcheck target".to_string(),
        ));
    }

    Ok((alpha, mu, beta, eta))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use ark_poly::{DenseMultilinearExtension, Polynomial};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };
    use ark_std::{log2, test_rng};
    use efficient_sumcheck::{hypercube::Hypercube, order_strategy::AscendingOrder};
    use spongefish::{duplex_sponge::DuplexSponge, DomainSeparator};
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;

    use super::*;

    use crate::{
        linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig},
        relations::{r1cs::R1CS, BundledPESAT},
        utils::poly::eq_poly,
    };

    struct C<F: PrimeField> {
        v: Vec<F>,
        x: F,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for C<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let v = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(self.v))?;
            let x = FpVar::new_input(cs.clone(), || Ok(self.x))?;

            let mut r = FpVar::one();

            for i in v.iter().take(15) {
                r *= i;
            }

            r.enforce_equal(&x)?;

            Ok(())
        }
    }

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        const S: usize = 8;
        const T: usize = 7;
        const R: usize = 1 + S + T;

        let rng = &mut test_rng();

        let cs = ConstraintSystem::new_ref();

        let witness = (0..15).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let instance = witness.iter().product::<Fr>();
        let circuit = C {
            v: witness.clone(),
            x: instance,
        };
        circuit.generate_constraints(cs.clone())?;
        let r1cs = R1CS::try_from(cs)?;
        const N: usize = 64;
        assert_eq!(N, (r1cs.k * 2).next_power_of_two());

        let code = ReedSolomon::new(ReedSolomonConfig::default(r1cs.k, N));

        // Prepare the instance and witness for multi-evaluation relation with R evaluations
        let cs = ConstraintSystem::new_ref();

        let witness = (0..15).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let instance = witness.iter().product::<Fr>();
        let circuit = C {
            v: witness.clone(),
            x: instance,
        };
        circuit.generate_constraints(cs.clone())?;

        let cs = cs.into_inner().unwrap();
        let (x, w) = (cs.instance_assignment, cs.witness_assignment);
        let z = [&x[..], &w].concat();

        let beta = (0..r1cs.log_m).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

        let mut beta_eq_evals = vec![];
        let hypercube = Hypercube::<AscendingOrder>::new(r1cs.log_m);

        for (index, _point) in hypercube {
            beta_eq_evals.push(eq_poly(&beta, index));
        }

        let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

        let u = code.encode(&w);
        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);

        let alpha_vec = [
            (0..1 + S)
                .map(|_| <[Fr; log2(N) as usize]>::rand(rng).to_vec())
                .collect::<Vec<_>>(),
            (0..T)
                .map(|_| {
                    <[bool; log2(N) as usize]>::rand(rng)
                        .into_iter()
                        .map(Fr::from)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        ]
        .concat();
        let mu_vec = alpha_vec
            .iter()
            .map(|alpha| u_mle.evaluate(alpha))
            .collect::<Vec<_>>();

        // Now impl the IOR from multi-evaluation relation with R evaluations to twin constraint relation
        let mut domain_separator = DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new(
            "ior::multilinear_constraint_batching",
        )
        .squeeze(log2(R) as usize, "xi");
        for i in 0..log2(N) {
            domain_separator = domain_separator
                .absorb(3, &format!("h_{i}"))
                .squeeze(1, &format!("challenge_{i}"));
        }
        domain_separator = domain_separator.absorb(1, "mu");

        let mut prover_state = domain_separator.to_prover_state();

        let (prover_instance, _prover_witness) = prover::<Fr, S, R, N>(
            &mut prover_state,
            alpha_vec.clone(),
            mu_vec.clone(),
            beta.clone(),
            eta,
            u,
        )?;
        let mut verifier_state = domain_separator.to_verifier_state(prover_state.narg_string());
        let verifier_instance =
            verifier::<Fr, R, N>(&mut verifier_state, alpha_vec, mu_vec, beta, eta)?;

        assert_eq!(prover_instance, verifier_instance);

        Ok(())
    }
}

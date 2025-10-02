#[cfg(test)]
mod tests {
    use std::{error::Error};

    use ark_bls12_381::Fr;
    use ark_ff::{AdditiveGroup, Field, One, PrimeField, UniformRand, Zero};
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
    use spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        duplex_sponge::DuplexSponge,
        DomainSeparator,
    };
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;
    use whir::poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint};

    use crate::{
        linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig},
        relations::{r1cs::R1CS, relation::BundledPESAT},
        utils::poly::eq_poly,
    };

    pub fn vsbw_reduce_evaluations<F: Field>(evals: &[F], c: F) -> Vec<F> {
        evals.chunks(2).map(|e| e[0] + c * (e[1] - e[0])).collect()
    }

    struct C<F: PrimeField> {
        v: Vec<F>,
        x: F,
    }

    impl<F: PrimeField> ConstraintSynthesizer<F> for C<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let v = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(self.v))?;
            let x = FpVar::new_input(cs.clone(), || Ok(self.x))?;

            let mut r = FpVar::one();

            for i in 0..15 {
                r *= &v[i];
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
        let hypercube = BinaryHypercube::new(r1cs.log_m);

        for point in hypercube {
            beta_eq_evals.push(eq_poly(&beta, point));
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
                .absorb(3, &format!("h_{}", i))
                .squeeze(1, &format!("challenge_{}", i));
        }

        let mut prover_state = domain_separator.to_prover_state();
        // 8.1 step 1, sample challenge \xi
        let xi = prover_state.challenge_scalars::<{ log2(R) as usize }>()?;
        let xi_eq_evals = (0..R)
            .map(|i| eq_poly(&xi, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        // 8.1 step 2, RHS of the equation (sumcheck target)
        let mut sigma = (0..R).map(|i| mu_vec[i] * xi_eq_evals[i]).sum::<Fr>();

        let mut alpha = vec![];
        // 8.1 step 2, initialize evaluation tables
        let mut f_evals = u;
        let mut ood_evals_vec = (0..1 + S)
            .map(|i| {
                (0..N)
                    .map(|a| eq_poly(&alpha_vec[i], BinaryHypercubePoint(a)) * xi_eq_evals[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // Optimization from Hyperplonk
        let mut id_non_0_evals_vec = (1 + S..R)
            .map(|i| {
                (
                    alpha_vec[i]
                        .iter()
                        .enumerate()
                        .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
                        .sum::<usize>(),
                    xi_eq_evals[i],
                )
            })
            .collect::<Vec<_>>();
        // 8.1 step 2, sumcheck starts
        for _ in 0..log2(N) {
            // compute prover message
            let (sum_00, sum_11, sum_0110) = (0..f_evals.len())
                .step_by(2)
                .map(|a| {
                    let p0 = f_evals[a];
                    let p1 = f_evals[a + 1];
                    let q0 = ood_evals_vec.iter().map(|v| v[a]).sum::<Fr>()
                        + id_non_0_evals_vec
                            .iter()
                            .filter_map(|&(j, v)| (j == a).then_some(v))
                            .sum::<Fr>();
                    let q1 = ood_evals_vec.iter().map(|v| v[a + 1]).sum::<Fr>()
                        + id_non_0_evals_vec
                            .iter()
                            .filter_map(|&(j, v)| (j == a + 1).then_some(v))
                            .sum::<Fr>();
                    (p0 * q0, p1 * q1, p0 * q1 + p1 * q0)
                })
                .fold((Fr::zero(), Fr::zero(), Fr::zero()), |acc, x| {
                    (acc.0 + x.0, acc.1 + x.1, acc.2 + x.2)
                });
            assert_eq!(sum_00 + sum_11, sigma);

            prover_state.add_scalars(&[sum_00, sum_11, sum_0110])?;
            // get challenge
            let [c] = prover_state.challenge_scalars::<1>()?;
            alpha.push(c);
            // update sumcheck target for next round
            sigma =
                (sigma - sum_0110) * c.square() + sum_00 * (Fr::one() - c.double()) + sum_0110 * c;

            // update evaluation tables
            f_evals = vsbw_reduce_evaluations(&f_evals, c);
            ood_evals_vec.iter_mut().for_each(|e| {
                *e = vsbw_reduce_evaluations(e, c);
            });
            id_non_0_evals_vec.iter_mut().for_each(|(i, eval)| {
                *eval *= if *i & 1 == 1 { c } else { Fr::one() - c };
                *i >>= 1;
            });
        }
        // 8.1 step 3, compute \mu as part of twin constraint relation instance
        let mu = u_mle.evaluate(&alpha);
        assert_eq!(
            sigma,
            mu * (0..R)
                .map(|i| xi_eq_evals[i]
                    * alpha
                        .iter()
                        .zip(&alpha_vec[i])
                        .map(|(a, b)| a * b + (Fr::one() - a) * (Fr::one() - b))
                        .product::<Fr>())
                .sum::<Fr>()
        );

        let output = (alpha, mu, beta, eta);

        Ok(())
    }
}

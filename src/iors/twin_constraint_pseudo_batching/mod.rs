#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
    use ark_poly::{
        univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial, Polynomial,
    };
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };
    use ark_std::{log2, test_rng};
    use rayon::prelude::*;
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

    pub fn vsbw_reduce_vec_evaluations<F: Field>(evals: &[Vec<F>], c: F) -> Vec<Vec<F>> {
        evals
            .chunks(2)
            .map(|e| {
                e[0].par_iter()
                    .zip(&e[1])
                    .map(|(&a, &b)| a + c * (b - a))
                    .collect()
            })
            .collect()
    }

    fn protogalaxy_trick<F: Field>(
        c: impl Iterator<Item = (F, F)>,
        mut q: Vec<DensePolynomial<F>>,
    ) -> DensePolynomial<F> {
        for (a, b) in c {
            q = q
                .par_chunks(2)
                .map(|p| {
                    &p[0]
                        + DensePolynomial::from_coefficients_vec(vec![a, b])
                            .naive_mul(&(&p[1] - &p[0]))
                })
                .collect();
        }
        assert_eq!(q.len(), 1);
        q.pop().unwrap()
    }

    struct C<F: PrimeField, const M: usize> {
        v: Vec<F>,
        x: F,
    }

    impl<F: PrimeField, const M: usize> ConstraintSynthesizer<F> for C<F, M> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let v = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(self.v))?;
            let x = FpVar::new_input(cs.clone(), || Ok(self.x))?;

            let mut r = FpVar::one();

            for i in 0..M - 1 {
                r *= &v[i];
            }

            r.enforce_equal(&x)?;

            Ok(())
        }
    }

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        const L: usize = 2;
        const M: usize = 1 << 10;

        let rng = &mut test_rng();

        let cs = ConstraintSystem::new_ref();

        let witness = (0..M - 1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let instance = witness.iter().product::<Fr>();
        let circuit = C::<_, M> {
            v: witness.clone(),
            x: instance,
        };
        circuit.generate_constraints(cs.clone())?;
        let r1cs = R1CS::try_from(cs)?;
        const N: usize = M * 4;
        assert_eq!(N, (r1cs.k * 2).next_power_of_two());

        let code = ReedSolomon::new(ReedSolomonConfig::default(r1cs.k, N));

        // Prepare for l instances and witnesses for twin constraint relation
        let mut alpha_vec = vec![];
        let mut mu_vec = vec![];
        let mut beta_vec = vec![];
        let mut eta_vec = vec![];
        let mut x_vec = vec![];
        let mut z_vec = vec![];
        let mut u_vec = vec![];

        for _ in 0..L {
            let cs = ConstraintSystem::new_ref();

            let witness = (0..M - 1).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let instance = witness.iter().product::<Fr>();
            let circuit = C::<_, M> {
                v: witness.clone(),
                x: instance,
            };
            circuit.generate_constraints(cs.clone())?;

            let cs = cs.into_inner().unwrap();
            let (x, w) = (cs.instance_assignment, cs.witness_assignment);
            let z = [&x[..], &w].concat();

            let beta = (0..r1cs.log_m).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

            let mut beta_eq_evals = Vec::<Fr>::new();
            let hypercube = BinaryHypercube::new(r1cs.log_m);

            for point in hypercube {
                beta_eq_evals.push(eq_poly(&beta, point));
            }

            let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

            let u = code.encode(&w);
            let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
            let alpha = (0..log2(N)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mu = u_mle.evaluate(&alpha);

            alpha_vec.push(alpha);
            mu_vec.push(mu);
            beta_vec.push(beta);
            eta_vec.push(eta);
            x_vec.push(x);
            z_vec.push(z);
            u_vec.push(u);
        }

        // Now impl the IOR from l twin constraint relations to pseudo-batching accumulation relation
        let mut domain_separator = DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new(
            "ior::twin_constraint_pseudo_batching",
        )
        .squeeze(log2(L) as usize, "tau")
        .squeeze(1, "xi");
        for i in 0..log2(L) {
            domain_separator = domain_separator
                .absorb(
                    2 + (log2(N) as usize + 1).max(r1cs.log_m + 2),
                    &format!("h_{}", i),
                )
                .squeeze(1, &format!("challenge_{}", i));
        }

        let mut prover_state = domain_separator.to_prover_state();

        // 6.1 step 1, sample challenge \tau and \xi
        let tau = prover_state.challenge_scalars::<{ log2(L) as usize }>()?;
        let tau_eq_evals = (0..L)
            .map(|i| eq_poly(&tau, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();
        let [xi] = prover_state.challenge_scalars::<1>()?;

        // 6.1 step 2, RHS of the equation (sumcheck target)
        let mut sigma = (0..L)
            .map(|i| tau_eq_evals[i] * (mu_vec[i] + xi * eta_vec[i]))
            .sum::<Fr>();
        let mut gamma = vec![];

        // 6.1 step 2, initialize evaluation tables
        let mut u_evals = u_vec;
        let mut z_evals = z_vec;
        let mut a_evals = alpha_vec;
        let mut b_evals = beta_vec;
        let mut tau_evals = tau_eq_evals;

        // 6.1 step 2, sumcheck starts
        for _ in 0..log2(L) as usize {
            // compute prover message `h`
            let f_iter = u_evals.chunks(2).zip(a_evals.chunks(2)).map(|(u, a)| {
                protogalaxy_trick(
                    a[0].iter().zip(&a[1]).map(|(&l, &r)| (l, r - l)),
                    u[0].par_iter()
                        .zip(&u[1])
                        .map(|(&l, &r)| DensePolynomial::from_coefficients_vec(vec![l, r - l]))
                        .collect::<Vec<_>>(),
                )
            });
            let p_iter = b_evals.chunks(2).zip(z_evals.chunks(2)).map(|(b, z)| {
                protogalaxy_trick(
                    b[0].iter().zip(&b[1]).map(|(&l, &r)| (l, r - l)),
                    r1cs.p
                        .par_iter()
                        .map(|(a, b, c)| {
                            let a0 = a.iter().map(|(t, i)| z[0][*i] * t).sum::<Fr>();
                            let a1 = a.iter().map(|(t, i)| z[1][*i] * t).sum::<Fr>() - a0;
                            let b0 = b.iter().map(|(t, i)| z[0][*i] * t).sum::<Fr>();
                            let b1 = b.iter().map(|(t, i)| z[1][*i] * t).sum::<Fr>() - b0;
                            let c0 = c.iter().map(|(t, i)| z[0][*i] * t).sum::<Fr>();
                            let c1 = c.iter().map(|(t, i)| z[1][*i] * t).sum::<Fr>() - c0;
                            vec![a0 * b0 - c0, a0 * b1 + a1 * b0 - c1, a1 * b1]
                        })
                        .map(DensePolynomial::from_coefficients_vec)
                        .collect::<Vec<_>>(),
                )
            });
            let t_iter = tau_evals
                .chunks(2)
                .map(|t| DensePolynomial::from_coefficients_vec(vec![t[0], t[1] - t[0]]));
            let h = f_iter
                .zip(p_iter)
                .zip(t_iter)
                .map(|((f, p), t)| (f + p * xi).naive_mul(&t))
                .fold(DensePolynomial::zero(), |acc, r| acc + r);

            assert_eq!(h.evaluate(&Fr::zero()) + h.evaluate(&Fr::one()), sigma);

            assert_eq!(
                h.coeffs.len(),
                2 + (log2(N) as usize + 1).max(r1cs.log_m + 2)
            );
            prover_state.add_scalars(&h.coeffs)?;
            // get challenge
            let [c] = prover_state.challenge_scalars::<1>()?;
            gamma.push(c);
            // update sumcheck target for next round
            sigma = h.evaluate(&c);

            // update evaluation tables
            u_evals = vsbw_reduce_vec_evaluations(&u_evals, c);
            z_evals = vsbw_reduce_vec_evaluations(&z_evals, c);
            a_evals = vsbw_reduce_vec_evaluations(&a_evals, c);
            b_evals = vsbw_reduce_vec_evaluations(&b_evals, c);
            tau_evals = vsbw_reduce_evaluations(&tau_evals, c);
        }

        // 6.1 step 3, compute new instance and witness for pseudo-batching accumulation relation
        let alpha = a_evals.pop().unwrap();

        let u = u_evals.pop().unwrap();
        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
        let mu = u_mle.evaluate(&alpha);

        let beta = b_evals.pop().unwrap();

        let z = z_evals.pop().unwrap();

        let beta_eq_evals = (0..r1cs.m)
            .map(|i| eq_poly(&beta, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

        // New target decision
        assert_eq!(
            sigma,
            (mu + xi * eta)
                * tau
                    .iter()
                    .zip(&gamma)
                    .map(|(a, b)| a * b + (Fr::one() - a) * (Fr::one() - b))
                    .product::<Fr>()
        );

        Ok(())
    }
}

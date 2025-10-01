#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error};

    use ark_bls12_381::Fr;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_ff::{One, PrimeField, UniformRand, Zero};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
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
        ByteDomainSeparator, DomainSeparator, UnitToBytes,
    };
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;
    use whir::poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint};

    use crate::{
        linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig},
        merkle::{poseidon::PoseidonMerkleConfig, poseidon_test_params},
        relations::{r1cs::R1CS, relation::BundledPESAT},
        utils::poly::eq_poly,
    };

    struct C<F: PrimeField> {
        v: Vec<F>,
        x: F,
    }

    // A test circuit with 16 constraints
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
        let l = 10;
        const S: usize = 8;
        const T: usize = 7;

        let leaf_hash_param: PoseidonConfig<Fr> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<Fr> = poseidon_test_params();

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

        // Prepare for l instances and witnesses for twin constraint relation
        let mut alpha_vec = vec![];
        let mut mu_vec = vec![];
        let mut beta_vec = vec![];
        let mut eta_vec = vec![];
        let mut x_vec = vec![];
        let mut w_vec = vec![];
        let mut u_vec = vec![];

        for _ in 0..l {
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
            w_vec.push(w);
            u_vec.push(u);
        }

        // Generate `gamma` for pseudo-batching accumulation relation
        let gamma_vec = (0..log2(l)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let gamma_eq_evals = (0..l)
            .map(|i| eq_poly(&gamma_vec, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        // Compute the pseudo-batching accumulation relation according to sec 6
        let mut alpha = vec![Fr::zero(); log2(N) as usize];
        for i in 0..l {
            for j in 0..log2(N) as usize {
                alpha[j] += gamma_eq_evals[i] * alpha_vec[i][j];
            }
        }

        let mut u = vec![Fr::zero(); N];
        for i in 0..l {
            for j in 0..N {
                u[j] += gamma_eq_evals[i] * u_vec[i][j];
            }
        }
        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
        let mu = u_mle.evaluate(&alpha);

        let mut beta = vec![Fr::zero(); r1cs.log_m];
        for i in 0..l {
            for j in 0..r1cs.log_m {
                beta[j] += gamma_eq_evals[i] * beta_vec[i][j];
            }
        }

        let mut x = vec![Fr::zero(); r1cs.n - r1cs.k];
        for i in 0..l {
            for j in 0..r1cs.n - r1cs.k {
                x[j] += gamma_eq_evals[i] * x_vec[i][j];
            }
        }

        let mut w = vec![Fr::zero(); r1cs.k];
        for i in 0..l {
            for j in 0..r1cs.k {
                w[j] += gamma_eq_evals[i] * w_vec[i][j];
            }
        }

        let mut beta_eq_evals = Vec::<Fr>::new();
        let hypercube = BinaryHypercube::new(r1cs.log_m);
        for point in hypercube {
            beta_eq_evals.push(eq_poly(&beta, point));
        }

        let z = [&x[..], &w].concat();

        let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

        // Now impl the IOR from pseudo-batching accumulation relation to multi-evaluation relation with 1 + S + T evaluations
        let domain_separator =
            DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new("ior::pesat")
                .absorb(1, "root")
                .absorb(1, "mu")
                .absorb(1, "eta")
                .squeeze(S * log2(N) as usize, "alpha")
                .absorb(S, "mus")
                .challenge_bytes((T * log2(N) as usize).div_ceil(8), "x");
        let mut prover_state = domain_separator.to_prover_state();

        // 7.1 step 1, send witness oracle `u` (in non-interactive version, this is a commitment)
        let mt = MerkleTree::<PoseidonMerkleConfig<Fr>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            u.iter().map(|v| vec![*v]).collect::<Vec<_>>(),
        )?;
        prover_state.add_scalars(&[mt.root()])?;
        prover_state.add_scalars(&[mu])?;
        prover_state.add_scalars(&[eta])?;

        // 7.1 step 2, get OOD challenges `alpha_i` for i in [S]
        let alpha_vec = prover_state
            .challenge_scalars::<{ S * log2(N) as usize }>()?
            .chunks(log2(N) as usize)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        // 7.1 step 3, compute OOD answers
        let mu_vec = alpha_vec
            .iter()
            .map(|c| u_mle.fix_variables(c)[0])
            .collect::<Vec<_>>();
        prover_state.add_scalars(&mu_vec)?;

        // 7.1 step 4, get shift query points `x_i` for i in [T]
        // Note that `x_i` should be in range 0..N, not in Fr
        let x_vec = prover_state
            .challenge_bytes::<{ (T * log2(N) as usize).div_ceil(8) }>()?
            .iter()
            .flat_map(|x| (0..8).map(|i| (x >> i) & 1 == 1).collect::<Vec<_>>())
            .take(T * log2(N) as usize)
            .collect::<Vec<_>>()
            .chunks(log2(N) as usize)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        // 7.1 step 5, output new alpha_vec
        let alpha_vec = [
            &[alpha][..],
            &alpha_vec,
            &x_vec
                .iter()
                .map(|x| {
                    x.iter()
                        .map(|&x| if x { Fr::one() } else { Fr::zero() })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        ]
        .concat();
        // 7.1 step 5, output new mu_vec
        let mu_vec = [
            &[mu][..],
            &mu_vec,
            &x_vec
                .iter()
                .map(|x| {
                    let x = x
                        .iter()
                        .enumerate()
                        .map(|(i, &b)| if b { 1 << i } else { 0 })
                        .sum::<usize>();
                    (0..l).map(|i| gamma_eq_evals[i] * u_vec[i][x]).sum()
                })
                .collect::<Vec<_>>(),
        ]
        .concat();

        // The new `mu`s should be exactly the evaluations of u_mle at the new `alpha`s
        for i in 0..1 + S + T {
            assert_eq!(mu_vec[i], u_mle.fix_variables(&alpha_vec[i])[0]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error};

    use ark_bls12_381::Fr;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };
    use ark_std::{cfg_into_iter, log2, rand::Rng, test_rng};
    use rayon::prelude::*;
    use spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        duplex_sponge::DuplexSponge,
        ByteDomainSeparator, DomainSeparator, UnitToBytes, UnitTranscript,
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

        let mut beta_eq_evals = HashMap::<usize, Fr>::new();
        let hypercube = BinaryHypercube::new(r1cs.log_m);

        for point in hypercube {
            beta_eq_evals.insert(point.0, eq_poly(&beta, point));
        }

        let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

        let code = ReedSolomon::new(ReedSolomonConfig::default(r1cs.k, N));

        let mut alpha_vec = vec![];
        let mut mu_vec = vec![];

        let u = code.encode(&w);
        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);

        for i in 0..1 + S {
            let alpha = (0..log2(N)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mu = u_mle.evaluate(&alpha.iter().cloned().collect::<Vec<_>>());

            alpha_vec.push(alpha);
            mu_vec.push(mu);
        }
        for i in 0..T {
            let alpha = (0..log2(N))
                .map(|_| Fr::from(rng.gen_range(0..N) as u64))
                .collect::<Vec<_>>();
            let mu = u_mle.evaluate(&alpha.iter().cloned().collect::<Vec<_>>());

            alpha_vec.push(alpha);
            mu_vec.push(mu);
        }

        let mut domain_separator =
            DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new("ior::pesat")
                .squeeze(log2(R) as usize, "xi");

        let mut prover_state = domain_separator.to_prover_state();
        let xi = prover_state.challenge_scalars::<{ log2(R) as usize }>()?;
        let xi_eq_evals = (0..R)
            .map(|i| eq_poly(&xi, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        let lhs = (0..N)
            .map(|a| {
                u[a] * (0..R)
                    .map(|i| eq_poly(&alpha_vec[i], BinaryHypercubePoint(a)) * xi_eq_evals[i])
                    .sum::<Fr>()
            })
            .sum::<Fr>();
        let rhs = (0..R).map(|i| mu_vec[i] * xi_eq_evals[i]).sum::<Fr>();

        assert_eq!(lhs, rhs);
        Ok(())
    }
}

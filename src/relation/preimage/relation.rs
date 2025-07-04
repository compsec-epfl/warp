use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_std::marker::PhantomData;

use crate::relation::constraint_matrices::SerializableConstraintMatrices;
use crate::relation::preimage::synthesizer::PreimageSynthesizer;
use crate::relation::preimage::PreimageInstance;
use crate::relation::{PreimageWitness, Relation};

#[derive(Clone)]
pub struct PreimageRelation<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    constraint_system: ConstraintSystemRef<F>,
    _crhs_scheme: PhantomData<H>,
    _crhs_scheme_gadget: PhantomData<HG>,
}

impl<F, H, HG> Relation<F> for PreimageRelation<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    type Instance = PreimageInstance<F>;
    type Witness = PreimageWitness<F, H>;
    type Config = H::Parameters;
    fn description(config: &Self::Config) -> Vec<u8> {
        let zero_instance = PreimageInstance::<F> { digest: F::zero() };
        let zero_witness = PreimageWitness::<F, H> {
            preimage: vec![F::zero()],
            _crhs_scheme: PhantomData,
        };
        let constraint_synthesizer = PreimageSynthesizer::<F, H, HG> {
            instance: zero_instance,
            witness: zero_witness,
            config: config.clone(),
            _crhs_scheme_gadget: PhantomData,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let constraint_synthesizer = PreimageSynthesizer::<F, H, HG> {
            instance,
            witness,
            config: config.clone(),
            _crhs_scheme_gadget: PhantomData,
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
            _crhs_scheme: PhantomData,
            _crhs_scheme_gadget: PhantomData,
        }
    }
    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::{
        poseidon::{constraints::CRHGadget, CRH},
        CRHScheme,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::UniformRand;
    use ark_std::{marker::PhantomData, test_rng};

    use crate::merkle::poseidon_test_params;
    use crate::relation::preimage::{PreimageInstance, PreimageRelation, PreimageWitness};
    use crate::relation::Relation;

    type TestCRHScheme = CRH<BLS12_381>;
    type TestCRHSchemeGadget = CRHGadget<BLS12_381>;

    #[test]
    fn sanity_0() {
        let mut rng = test_rng();
        let parameters: PoseidonConfig<BLS12_381> = poseidon_test_params();

        let preimage: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
        let digest = TestCRHScheme::evaluate(&parameters, preimage.clone()).unwrap();

        let relation = PreimageRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            PreimageInstance { digest },
            PreimageWitness {
                preimage,
                _crhs_scheme: PhantomData,
            },
            parameters.clone(),
        );
        assert!(relation.verify());
    }

    #[test]
    fn sanity_1() {
        let mut rng = test_rng();
        let parameters: PoseidonConfig<BLS12_381> = poseidon_test_params();

        let preimage_0: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
        let preimage_1: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
        let digest = TestCRHScheme::evaluate(&parameters, preimage_0.clone()).unwrap();

        let relation = PreimageRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            PreimageInstance { digest },
            PreimageWitness {
                preimage: preimage_1,
                _crhs_scheme: PhantomData,
            },
            parameters.clone(),
        );
        assert!(!relation.verify());
    }
}

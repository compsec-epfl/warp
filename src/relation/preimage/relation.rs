use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

use crate::relation::description::SerializableConstraintMatrices;
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
    config: H::Parameters,
    instance: PreimageInstance<F>,
    witness: PreimageWitness<F, H>,
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

    fn constraints(&self) -> usize {
        self.constraint_system.num_constraints()
    }

    fn description(config: &Self::Config) -> Vec<u8> {
        let zero_witness = PreimageWitness::<F, H> {
            preimage: vec![F::zero()],
            _crhs_scheme: PhantomData,
        };
        let zero_instance = PreimageInstance::<F> {
            digest: H::evaluate(&config, zero_witness.preimage.clone()).unwrap(),
        };
        let constraint_synthesizer = PreimageSynthesizer::<F, H, HG> {
            instance: zero_instance,
            witness: zero_witness,
            config: config.clone(),
            _crhs_scheme_gadget: PhantomData,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }

    fn instance(&self) -> Self::Instance {
        self.instance.clone()
    }

    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let constraint_synthesizer = PreimageSynthesizer::<F, H, HG> {
            instance: instance.clone(),
            witness: witness.clone(),
            config: config.clone(),
            _crhs_scheme_gadget: PhantomData,
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
            config,
            instance,
            witness,
            _crhs_scheme: PhantomData,
            _crhs_scheme_gadget: PhantomData,
        }
    }

    fn public_config(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.config.serialize_uncompressed(&mut inputs).unwrap();
        inputs
    }

    fn public_inputs(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.instance.serialize_uncompressed(&mut inputs).unwrap();
        inputs
    }

    fn private_inputs(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.witness.serialize_uncompressed(&mut inputs).unwrap();
        inputs
    }

    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }

    fn witness(&self) -> Self::Witness {
        self.witness.clone()
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
    use ark_ff::{UniformRand, Zero};
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

    #[test]
    fn description() {
        let zero_witness = PreimageWitness::<BLS12_381, TestCRHScheme> {
            preimage: vec![BLS12_381::zero()],
            _crhs_scheme: PhantomData,
        };
        let zero_instance = PreimageInstance::<BLS12_381> {
            digest: TestCRHScheme::evaluate(&poseidon_test_params(), zero_witness.preimage.clone())
                .unwrap(),
        };
        let relation = PreimageRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            zero_instance,
            zero_witness,
            poseidon_test_params(),
        );
        assert!(relation.verify());
        let description: Vec<u8> =
            PreimageRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::description(
                &poseidon_test_params(),
            );
        let description_hash = blake3::hash(&description).to_hex();
        assert_eq!(
            description_hash,
            *"354223328d1f52c726b1e8e23fb5537d8df968b18e57f8f8169563dbf3dbe54d"
        );
    }
}

use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::marker::PhantomData;

use crate::relation::constraint_matrices::SerializableConstraintMatrices;
use crate::relation::Relation;

#[derive(Clone)]
pub struct PreimageInstance<F>
where
    F: Field + PrimeField,
{
    digest: F,
}

#[derive(Clone)]
pub struct PreimageWitness<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
{
    preimage: Vec<F>,
    _crhs_scheme: PhantomData<H>,
}

#[derive(Clone)]
pub struct PreimageConstraintSynthesizer<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>]>,
{
    instance: PreimageInstance<F>,
    witness: PreimageWitness<F, H>,
    config: H::Parameters,
    _crhs_scheme_gadget: PhantomData<HG>,
}

impl<F, H, HG> ConstraintSynthesizer<F> for PreimageConstraintSynthesizer<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let preimage_var: Vec<FpVar<F>> = self
            .witness
            .preimage
            .iter()
            .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()
            .unwrap();
        let digest_var = FpVar::new_input(cs.clone(), || Ok(self.instance.digest))?;
        let params_var = HG::ParametersVar::new_constant(cs.clone(), &self.config)?;

        let computed_hash = HG::evaluate(&params_var, &preimage_var)?;
        computed_hash.enforce_equal(&digest_var)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PreimageRelation<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    constraint_system: ConstraintSystemRef<F>,
    config: H::Parameters,
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
        let constraint_synthesizer = PreimageConstraintSynthesizer::<F, H, HG> {
            instance: zero_instance,
            witness: zero_witness,
            config: config.clone(),
            _crhs_scheme_gadget: PhantomData,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let constraint_synthesizer = PreimageConstraintSynthesizer::<F, H, HG> {
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
            config: config.clone(),
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
    fn relation_sanity_0() {
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
    fn relation_sanity_1() {
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

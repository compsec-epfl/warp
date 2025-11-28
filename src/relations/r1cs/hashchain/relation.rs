use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    sponge::Absorb,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;

use crate::relations::{
    r1cs::hashchain::{HashChainInstance, HashChainSynthesizer, HashChainWitness},
    Relation, SerializableConstraintMatrices,
};

pub fn compute_hash_chain<F: PrimeField + Absorb, C: CRHScheme<Input = [F], Output = F>>(
    params: &<C as CRHScheme>::Parameters,
    preimage: &[F],
    hash_chain_size: usize,
) -> F {
    let mut digest = C::evaluate(params, preimage).unwrap();
    for _ in 0..hash_chain_size - 1 {
        digest = C::evaluate(params, [digest]).unwrap();
    }
    digest
}

#[derive(Clone)]
pub struct HashChainRelation<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    constraint_system: ConstraintSystemRef<F>,
    config: H::Parameters,
    instance: HashChainInstance<F>,
    witness: HashChainWitness<F, H>,
    pub w: Vec<F>,
    pub x: Vec<F>,
    _crhs_scheme: PhantomData<H>,
    _crhs_scheme_gadget: PhantomData<HG>,
}

impl<F, H, HG> Relation<F> for HashChainRelation<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    type Instance = HashChainInstance<F>;
    type Witness = HashChainWitness<F, H>;
    type Config = (H::Parameters, usize);

    fn constraints(&self) -> usize {
        self.constraint_system.num_constraints()
    }

    fn description(config: &Self::Config) -> Vec<u8> {
        let (hash_config, hash_chain_size) = (config.0.clone(), config.1);
        let zero_witness = HashChainWitness::<F, H> {
            preimage: vec![F::zero()],
            _crhs_scheme: PhantomData,
        };
        let zero_instance = HashChainInstance::<F> {
            digest: H::evaluate(&hash_config, zero_witness.preimage.clone()).unwrap(),
        };
        let constraint_synthesizer = HashChainSynthesizer::<F, H, HG> {
            instance: zero_instance,
            witness: zero_witness,
            config: hash_config,
            size: hash_chain_size,
            _crhs_scheme_gadget: PhantomData,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }

    fn instance(&self) -> Self::Instance {
        self.instance.clone()
    }

    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let (hash_config, hash_chain_size) = (config.0.clone(), config.1);
        let constraint_synthesizer = HashChainSynthesizer::<F, H, HG> {
            instance: instance.clone(),
            witness: witness.clone(),
            config: hash_config.clone(),
            size: hash_chain_size,
            _crhs_scheme_gadget: PhantomData,
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();

        let cs = constraint_system.into_inner().unwrap();
        Self {
            constraint_system: ConstraintSystemRef::new(cs.clone()),
            config: hash_config,
            instance,
            witness,
            x: cs.instance_assignment,
            w: cs.witness_assignment,
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
    use crate::{
        relations::r1cs::hashchain::{relation::compute_hash_chain, HashChainInstance},
        utils::poseidon::initialize_poseidon_config,
    };
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::{
        poseidon::{constraints::CRHGadget, CRH},
        CRHScheme,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::{UniformRand, Zero};
    use ark_std::{marker::PhantomData, test_rng};

    use crate::relations::r1cs::hashchain::relation::HashChainRelation;
    use crate::relations::r1cs::hashchain::HashChainWitness;
    use crate::relations::Relation;

    type TestCRHScheme = CRH<BLS12_381>;
    type TestCRHSchemeGadget = CRHGadget<BLS12_381>;

    #[test]
    fn sanity_0() {
        let hash_chain_size = 10;
        let mut rng = test_rng();
        let parameters: PoseidonConfig<BLS12_381> = initialize_poseidon_config();
        let preimage: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];

        let digest =
            compute_hash_chain::<BLS12_381, CRH<_>>(&parameters, &preimage, hash_chain_size);

        let relation = HashChainRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            HashChainInstance { digest },
            HashChainWitness {
                preimage,
                _crhs_scheme: PhantomData,
            },
            (parameters.clone(), hash_chain_size),
        );
        assert!(relation.verify());
    }

    #[test]
    fn sanity_1() {
        let hash_chain_size = 10;
        let mut rng = test_rng();
        let params: PoseidonConfig<BLS12_381> = initialize_poseidon_config();

        let preimage_0: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
        let preimage_1: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];

        let digest = compute_hash_chain::<BLS12_381, CRH<_>>(&params, &preimage_0, hash_chain_size);

        let relation = HashChainRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            HashChainInstance { digest },
            HashChainWitness {
                preimage: preimage_1,
                _crhs_scheme: PhantomData,
            },
            (params.clone(), hash_chain_size),
        );
        assert!(!relation.verify());
    }

    #[test]
    fn description() {
        let hash_chain_size = 1;
        let zero_witness = HashChainWitness::<BLS12_381, TestCRHScheme> {
            preimage: vec![BLS12_381::zero()],
            _crhs_scheme: PhantomData,
        };

        let zero_instance = HashChainInstance::<BLS12_381> {
            digest: TestCRHScheme::evaluate(
                &initialize_poseidon_config(),
                zero_witness.preimage.clone(),
            )
            .unwrap(),
        };
        let relation = HashChainRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            zero_instance,
            zero_witness,
            (initialize_poseidon_config(), hash_chain_size),
        );
        assert!(relation.verify());
        let description: Vec<u8> =
            HashChainRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::description(&(
                initialize_poseidon_config(),
                hash_chain_size,
            ));
        let description_hash = blake3::hash(&description).to_hex();

        // when hash_chain_size is 1, we get the same description as the PreimageRelation
        assert_eq!(
            description_hash,
            *"2501f57f175c1f0e5e44679419a86c8b08eb6a38d987a133e15ef0269b8eca57"
        );
    }
}

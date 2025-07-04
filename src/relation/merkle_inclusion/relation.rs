use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config as MerkleConfig, Path};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_std::marker::PhantomData;

use crate::relation::{
    constraint_matrices::SerializableConstraintMatrices,
    merkle_inclusion::{
        synthesizer::MerkleInclusionSynthesizer, MerkleInclusionConfig, MerkleInclusionInstance,
    },
    MerkleInclusionWitness, Relation,
};

pub struct MerkleInclusionRelation<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    constraint_system: ConstraintSystemRef<F>,
    _merkle_config: PhantomData<M>,
    _merkle_config_gadget: PhantomData<MG>,
}

impl<F, M, MG> Relation<F> for MerkleInclusionRelation<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    type Instance = MerkleInclusionInstance<F, M, MG>;
    type Witness = MerkleInclusionWitness<F, M, MG>;
    type Config = MerkleInclusionConfig<F, M, MG>;
    fn description(config: &Self::Config) -> Vec<u8> {
        let zero_instance = MerkleInclusionInstance::<F, M, MG> {
            root: M::InnerDigest::default(),
            leaf: vec![F::zero()],
            _merkle_config_gadget: PhantomData,
        };
        let zero_witness = MerkleInclusionWitness::<F, M, MG> {
            proof: Path::<M>::default(),
            _merkle_config_gadget: PhantomData,
        };
        let zero_config = MerkleInclusionConfig::<F, M, MG> {
            leaf_hash_param: config.leaf_hash_param.clone(),
            two_to_one_hash_param: config.two_to_one_hash_param.clone(),
            _merkle_config_gadget: PhantomData,
        };
        let constraint_synthesizer = MerkleInclusionSynthesizer::<F, M, MG> {
            instance: zero_instance,
            witness: zero_witness,
            config: zero_config,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let constraint_synthesizer = MerkleInclusionSynthesizer::<F, M, MG> {
            instance: instance.clone(),
            witness: witness.clone(),
            config: config.clone(),
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
            _merkle_config: PhantomData,
            _merkle_config_gadget: PhantomData,
        }
    }
    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_std::marker::PhantomData;

    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relation::{
            merkle_inclusion::{
                MerkleInclusionConfig, MerkleInclusionInstance, MerkleInclusionRelation,
                MerkleInclusionWitness,
            },
            Relation,
        },
    };

    #[test]
    fn relation_sanity() {
        // Create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // Commit to the Merkle tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // Get root and proof
        let root = mt.root();
        let proof0 = mt.generate_proof(0).unwrap();

        // Construct the instance and witness
        let instance = MerkleInclusionInstance::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            root,
            leaf: leaf0,
            _merkle_config_gadget: PhantomData,
        };
        let witness = MerkleInclusionWitness::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            proof: proof0,
            _merkle_config_gadget: PhantomData,
        };
        let config = MerkleInclusionConfig::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_hash_param,
            two_to_one_hash_param,
            _merkle_config_gadget: PhantomData,
        };

        // Create and verify the relation
        let relation = MerkleInclusionRelation::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        >::new(instance, witness, config);

        assert!(relation.verify());
    }
}

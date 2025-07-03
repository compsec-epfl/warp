use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config as MerkleConfig, LeafParam, Path, TwoToOneParam,
    },
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_std::marker::PhantomData;

use crate::relation::{constraint_matrices::SerializableConstraintMatrices, Relation};

#[derive(Clone)]
pub struct MerkleInclusionConfig<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    leaf_hash_param: LeafParam<M>,
    two_to_one_hash_param: TwoToOneParam<M>,
    _merkle_config_gadget: PhantomData<MG>,
}

#[derive(Clone)]
pub struct MerkleInclusionInstance<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F>,
    MG: Clone,
{
    leaf: Vec<F>,
    root: M::InnerDigest,
    _merkle_config_gadget: PhantomData<MG>,
}

#[derive(Clone)]
pub struct MerkleInclusionWitness<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F>,
    MG: Clone,
{
    proof: Path<M>,
    _config_gadget: PhantomData<MG>,
}

#[derive(Clone)]
pub struct MerkleInclusionConstraintSynthesizer<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    instance: MerkleInclusionInstance<F, M, MG>,
    witness: MerkleInclusionWitness<F, M, MG>,
    config: MerkleInclusionConfig<F, M, MG>,
}

impl<F, M, MG> ConstraintSynthesizer<F> for MerkleInclusionConstraintSynthesizer<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // public
        let root_var: <MG as ConfigGadget<M, F>>::InnerDigest =
            MG::InnerDigest::new_input(ark_relations::ns!(cs, "root"), || Ok(self.instance.root))
                .unwrap();

        // constants
        let leaf_hash_var = <<MG as ConfigGadget<M, F>>::LeafHash as CRHSchemeGadget<
            <M as MerkleConfig>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_hash_param"),
            &self.config.leaf_hash_param,
        )
        .unwrap();
        let two_one_hash_var =
            <<MG as ConfigGadget<M, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <M as MerkleConfig>::TwoToOneHash,
                F,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_hash_param"),
                &self.config.two_to_one_hash_param,
            )
            .unwrap();

        // private
        let path_var: PathVar<M, F, MG> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || {
                Ok(&self.witness.proof)
            })
            .unwrap();
        let leaf_var: Vec<FpVar<F>> = self
            .instance
            .leaf
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();

        let is_satisfied = path_var
            .verify_membership(&leaf_hash_var, &two_one_hash_var, &root_var, &leaf_var)
            .unwrap();
        is_satisfied.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

pub struct MerkleInclusionRelation<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    config: MerkleInclusionConfig<F, M, MG>,
    instance: MerkleInclusionInstance<F, M, MG>,
    witness: MerkleInclusionWitness<F, M, MG>,
    constraint_system: ConstraintSystemRef<F>,
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
            _config_gadget: PhantomData,
        };
        let zero_config = MerkleInclusionConfig::<F, M, MG> {
            leaf_hash_param: config.leaf_hash_param.clone(),
            two_to_one_hash_param: config.two_to_one_hash_param.clone(),
            _merkle_config_gadget: PhantomData,
        };
        let constraint_synthesizer = MerkleInclusionConstraintSynthesizer::<F, M, MG> {
            instance: zero_instance,
            witness: zero_witness,
            config: zero_config,
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }
    fn new(instance: Self::Instance, witness: Self::Witness, config: Self::Config) -> Self {
        let constraint_synthesizer = MerkleInclusionConstraintSynthesizer::<F, M, MG> {
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
            instance,
            witness,
            config,
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
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::marker::PhantomData;

    use crate::relation::merkle_inclusion::MerkleInclusionConfig;
    use crate::relation::merkle_inclusion::MerkleInclusionConstraintSynthesizer;
    use crate::relation::merkle_inclusion::MerkleInclusionInstance;
    use crate::relation::merkle_inclusion::MerkleInclusionRelation;
    use crate::relation::Relation;
    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relation::MerkleInclusionWitness,
    };

    #[test]
    fn witness_sanity() {
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // commit to the tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // get root and proof
        let root = mt.root();
        let proof0 = mt.generate_proof(0).unwrap();

        let constraint_synthesizer = MerkleInclusionConstraintSynthesizer::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            instance: MerkleInclusionInstance::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                root,
                leaf: leaf0,
                _merkle_config_gadget: PhantomData,
            },
            witness: MerkleInclusionWitness::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                proof: proof0,
                _config_gadget: PhantomData,
            },
            config: MerkleInclusionConfig::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                leaf_hash_param,
                two_to_one_hash_param,
                _merkle_config_gadget: PhantomData,
            },
        };

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }

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
            _config_gadget: PhantomData,
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

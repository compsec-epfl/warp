use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config as MerkleConfig,
    },
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::relations::r1cs::merkle_inclusion::{
    MerkleInclusionConfig, MerkleInclusionInstance, MerkleInclusionWitness,
};

#[derive(Clone)]
pub struct MerkleInclusionSynthesizer<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    M: Clone,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    pub instance: MerkleInclusionInstance<F, M, MG>,
    pub witness: MerkleInclusionWitness<F, M, MG>,
    pub config: MerkleInclusionConfig<F, M, MG>,
}

impl<F, M, MG> ConstraintSynthesizer<F> for MerkleInclusionSynthesizer<F, M, MG>
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

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::marker::PhantomData;

    use super::MerkleInclusionSynthesizer;
    use crate::utils::poseidon::initialize_poseidon_config;
    use crate::{
        crypto::merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget},
        relations::r1cs::merkle_inclusion::{
            MerkleInclusionConfig, MerkleInclusionInstance, MerkleInclusionWitness,
        },
    };

    #[test]
    fn sanity() {
        let height = 2;
        let leaf_len = 2;
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // commit to the tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = initialize_poseidon_config();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = initialize_poseidon_config();
        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // get root and proof
        let root = mt.root();
        let proof0 = mt.generate_proof(0).unwrap();

        let constraint_synthesizer = MerkleInclusionSynthesizer::<
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
                _merkle_config_gadget: PhantomData,
            },
            config: MerkleInclusionConfig::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                leaf_len,
                height,
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
}

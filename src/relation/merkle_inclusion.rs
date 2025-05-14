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

use crate::relation::Relation;

#[derive(Clone)]
pub struct MerkleInclusionWitness<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F>,
{
    leaf_hash_param: LeafParam<M>,
    two_to_one_hash_param: TwoToOneParam<M>,
    root: M::InnerDigest,
    leaf: Vec<F>,
    proof: Path<M>,
    _config_gadget: PhantomData<MG>,
}

impl<F, M, MG> ConstraintSynthesizer<F> for MerkleInclusionWitness<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // public
        let root_var: <MG as ConfigGadget<M, F>>::InnerDigest =
            MG::InnerDigest::new_input(ark_relations::ns!(cs, "root"), || Ok(self.root)).unwrap();

        // constants
        let leaf_hash_var = <<MG as ConfigGadget<M, F>>::LeafHash as CRHSchemeGadget<
            <M as MerkleConfig>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_hash_param"),
            &self.leaf_hash_param,
        )
        .unwrap();
        let two_one_hash_var =
            <<MG as ConfigGadget<M, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <M as MerkleConfig>::TwoToOneHash,
                F,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_hash_param"),
                &self.two_to_one_hash_param,
            )
            .unwrap();

        // private
        let path_var: PathVar<M, F, MG> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&self.proof))
                .unwrap();
        let leaf_var: Vec<FpVar<F>> = self
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
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
{
    constraint_system: ConstraintSystemRef<F>,
    _field: PhantomData<F>,
    _merkle_config: PhantomData<M>,
    _merkle_config_gadget: PhantomData<MG>,
}

impl<F, M, MG> Relation<F> for MerkleInclusionRelation<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
{
    type Witness = MerkleInclusionWitness<F, M, MG>;
    fn assign_witness(witness: Self::Witness) -> Self {
        let constraint_system = ConstraintSystem::<F>::new_ref();
        witness
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
            _field: PhantomData,
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
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::marker::PhantomData;

    use crate::relation::merkle_inclusion::MerkleInclusionRelation;
    use crate::relation::Relation;
    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relation::MerkleInclusionWitness,
    };

    #[test]
    fn sanity_merkle_inclusion_witness() {
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

        let circuit = MerkleInclusionWitness::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_hash_param,
            two_to_one_hash_param,
            root,
            leaf: leaf0,
            proof: proof0,
            _config_gadget: PhantomData,
        };

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        circuit
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }

    #[test]
    fn sanity_merkle_inclusion_relation() {
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

        // Construct the witness
        let witness = MerkleInclusionWitness::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_hash_param,
            two_to_one_hash_param,
            root,
            leaf: leaf0,
            proof: proof0,
            _config_gadget: PhantomData,
        };

        // Create and verify the relation
        let relation = MerkleInclusionRelation::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        >::assign_witness(witness);

        assert!(relation.verify());
    }
}

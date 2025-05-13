use ark_crypto_primitives::{
    crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config as MerkleConfig, LeafParam, Path, TwoToOneParam,
    },
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

#[derive(Clone)]
pub struct MerkleInclusionCircuit<F, M, MG>
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

impl<F, M, MG> ConstraintSynthesizer<F> for MerkleInclusionCircuit<F, M, MG>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let root: <MG as ConfigGadget<M, F>>::InnerDigest =
            MG::InnerDigest::new_input(ark_relations::ns!(cs, "root"), || Ok(self.root)).unwrap();

        let leaf_g: Vec<_> = self
            .leaf
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)).unwrap())
            .collect();

        let leaf_hash_var = <<MG as ConfigGadget<M, F>>::LeafHash as CRHSchemeGadget<
            <M as MerkleConfig>::LeafHash,
            F,
        >>::ParametersVar::new_input(
            ark_relations::ns!(cs, "leaf_hash_param"),
            || Ok(&self.leaf_hash_param),
        )
        .unwrap();

        let two_one_hash_var =
            <<MG as ConfigGadget<M, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <M as MerkleConfig>::TwoToOneHash,
                F,
            >>::ParametersVar::new_input(
                ark_relations::ns!(cs, "two_to_one_hash_param"),
                || Ok(&self.two_to_one_hash_param),
            )?;

        let path_var: PathVar<M, F, MG> =
            PathVar::new_witness(ark_relations::ns!(cs, "new_witness"), || Ok(&self.proof))
                .unwrap();

        let a = path_var
            .verify_membership(&leaf_hash_var, &two_one_hash_var, &root, &leaf_g)
            .unwrap();

        a.enforce_equal(&Boolean::constant(true))?;

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

    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relations::MerkleInclusionCircuit,
    };

    #[test]
    fn sanity() {
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // commit to the tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let one_two_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &one_two_hash_param,
            &leaves,
        )
        .unwrap();

        // get proofs
        let proof0 = mt.generate_proof(0).unwrap();

        // --- instantiate our circuit with the *correct* root ---
        let circuit = MerkleInclusionCircuit::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_hash_param,
            two_to_one_hash_param: one_two_hash_param,
            root: mt.root(),
            leaf: leaf0,
            proof: proof0,
            _config_gadget: PhantomData,
        };

        // --- synthesize and check satisfiability ---
        let cs = ConstraintSystem::<BLS12_381>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}

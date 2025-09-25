use std::collections::HashMap;

use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct SerializableConstraintMatrices {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a: Vec<Vec<(Vec<u8>, usize)>>,
    pub b: Vec<Vec<(Vec<u8>, usize)>>,
    pub c: Vec<Vec<(Vec<u8>, usize)>>,
}

impl SerializableConstraintMatrices {
    fn serialize_nested_field<F: Field>(
        original: Vec<Vec<(F, usize)>>,
    ) -> Vec<Vec<(Vec<u8>, usize)>> {
        original
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(coeff, col_idx)| {
                        let mut buf = Vec::new();
                        coeff.serialize_uncompressed(&mut buf).unwrap();
                        (buf, col_idx)
                    })
                    .collect()
            })
            .collect()
    }
    pub fn generate_description<F: Field>(
        constraint_synthesizer: impl ConstraintSynthesizer<F>,
    ) -> Vec<u8> {
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();
        let matrices: ConstraintMatrices<F> = constraint_system.to_matrices().unwrap();
        let serializable = SerializableConstraintMatrices::from(matrices);
        let serialized = serde_json::to_string(&serializable).unwrap();
        serialized.into_bytes()
    }
}

impl<F: Field> From<ConstraintMatrices<F>> for SerializableConstraintMatrices {
    fn from(m: ConstraintMatrices<F>) -> Self {
        Self {
            num_instance_variables: m.num_instance_variables,
            num_witness_variables: m.num_witness_variables,
            num_constraints: m.num_constraints,
            a: SerializableConstraintMatrices::serialize_nested_field(m.a),
            b: SerializableConstraintMatrices::serialize_nested_field(m.b),
            c: SerializableConstraintMatrices::serialize_nested_field(m.c),
        }
    }
}

#[cfg(test)]
pub mod tests {

    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_ec::AdditiveGroup;
    use ark_std::marker::PhantomData;
    use whir::poly_utils::hypercube::BinaryHypercube;

    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relations::{
            r1cs::merkle_inclusion::{
                MerkleInclusionConfig, MerkleInclusionInstance, MerkleInclusionRelation,
                MerkleInclusionWitness,
            },
            relation::ToPolySystem,
            Relation,
        },
    };

    // extract r1cs and witness, check that all eval to 0
    #[test]
    pub fn test_r1cs_p_i_evals() {
        let height = 3; // n_leaves := 1 << (height - 1)
        let leaf_len = 2;
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let config = MerkleInclusionConfig::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_len,
            height,
            leaf_hash_param: leaf_hash_param.clone(),
            two_to_one_hash_param: two_to_one_hash_param.clone(),
            _merkle_config_gadget: PhantomData,
        };

        // extract R1CS matrices
        let r1cs = MerkleInclusionRelation::into_r1cs(&config).unwrap();

        // Create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaf2: Vec<BLS12_381> = vec![BLS12_381::from(5u64), BLS12_381::from(6u64)];
        let leaf3: Vec<BLS12_381> = vec![BLS12_381::from(7u64), BLS12_381::from(8u64)];

        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1, &leaf2, &leaf3];

        // Commit to the Merkle tree
        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // Get root and proof
        let root = mt.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = mt.generate_proof(i).unwrap();
            // Construct the instance and witness
            let instance = MerkleInclusionInstance::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                root,
                leaf: (*leaf).to_vec(),
                _merkle_config_gadget: PhantomData,
            };
            let witness = MerkleInclusionWitness::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                proof,
                _merkle_config_gadget: PhantomData,
            };

            // build relation, along with z vector
            let relation = MerkleInclusionRelation::new(instance, witness, config.clone());

            // assert p_i(z) == 0
            for p in BinaryHypercube::new(r1cs.log_m) {
                let eval = r1cs.eval_p_i(&relation.z, &p).unwrap();
                assert_eq!(BLS12_381::ZERO, eval);
            }

            // change z to incorrect assignment
            let wrong_z = relation.z.clone();
        }
    }
}

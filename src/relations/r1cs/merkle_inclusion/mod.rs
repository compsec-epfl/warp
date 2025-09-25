mod config;
mod instance;
mod relation;
mod synthesizer;
mod witness;

use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config, MerkleTree};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::CanonicalSerialize;
pub use config::MerkleInclusionConfig;
pub use instance::MerkleInclusionInstance;
pub use relation::MerkleInclusionRelation;
use std::marker::PhantomData;
pub use synthesizer::MerkleInclusionSynthesizer;
pub use witness::MerkleInclusionWitness;

use crate::{relations::relation::ToPolySystem, WARPError};

use super::R1CS;

impl<F, M, MG> ToPolySystem<F> for MerkleInclusionRelation<F, M, MG>
where
    F: Field + PrimeField,
    M: Config<Leaf = [F], LeafDigest = F>,
    M: Clone,
    M::InnerDigest: CanonicalSerialize,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    MG: Clone,
{
    fn into_r1cs(config: &Self::Config) -> Result<R1CS<F>, WARPError> {
        let zero_config = MerkleInclusionConfig::<F, M, MG> {
            leaf_len: config.leaf_len,
            height: config.height,
            leaf_hash_param: config.leaf_hash_param.clone(),
            two_to_one_hash_param: config.two_to_one_hash_param.clone(),
            _merkle_config_gadget: PhantomData,
        };
        let leaf0 = vec![F::default(); config.leaf_len];
        let leaves = vec![&leaf0; 1 << (config.height - 1)];
        let tree = MerkleTree::<M>::new(
            &config.leaf_hash_param,
            &config.two_to_one_hash_param,
            leaves,
        )?;
        let proof = tree.generate_proof(0).unwrap();
        let root = tree.root();
        let zero_instance = MerkleInclusionInstance::<F, M, MG> {
            root,
            leaf: leaf0,
            _merkle_config_gadget: PhantomData,
        };
        let zero_witness = MerkleInclusionWitness::<F, M, MG> {
            proof,
            _merkle_config_gadget: PhantomData,
        };
        let constraint_synthesizer = MerkleInclusionSynthesizer::<F, M, MG> {
            instance: zero_instance,
            witness: zero_witness,
            config: zero_config,
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();
        R1CS::try_from(constraint_system)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::relations::relation::ToPolySystem;
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::{merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig};
    use ark_ec::AdditiveGroup;
    use ark_ff::UniformRand;
    use ark_std::{marker::PhantomData, test_rng};
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
            Relation,
        },
    };

    pub fn get_test_merkle_tree(
        height: usize,
    ) -> (
        MerkleInclusionConfig<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        >,
        Vec<Vec<BLS12_381>>,
        MerkleTree<PoseidonMerkleConfig<BLS12_381>>,
    ) {
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
        let n_leaves = 1 << (height - 1);
        let mut leaves = Vec::<Vec<BLS12_381>>::new();
        let mut rng = test_rng();
        for i in 0..n_leaves {
            let leaf = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
            leaves.push(leaf);
        }

        // Commit to the Merkle tree
        let mt = MerkleTree::new(&leaf_hash_param, &two_to_one_hash_param, &leaves).unwrap();

        (config, leaves, mt)
    }
    // extract r1cs and witness, check that all eval to 0
    #[test]
    pub fn test_merkle_r1cs() {
        let height = 3; // n_leaves := 1 << (height - 1)
        let (config, leaves, mt) = get_test_merkle_tree(height);

        // extract R1CS matrices
        let r1cs = MerkleInclusionRelation::into_r1cs(&config).unwrap();

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
            let mut z = relation.x;
            z.extend(relation.w);

            // assert p_i(z) == 0
            for p in BinaryHypercube::new(r1cs.log_m) {
                let eval = r1cs.eval_p_i(&z, &p).unwrap();
                assert_eq!(BLS12_381::ZERO, eval);
            }

            // change z to incorrect assignment
            z[10] = BLS12_381::from(42);
            let mut is_0 = true;
            for p in BinaryHypercube::new(r1cs.log_m) {
                let eval = r1cs.eval_p_i(&z, &p).unwrap();
                if eval != BLS12_381::ZERO {
                    is_0 = false;
                    break;
                }
            }
            assert_eq!(is_0, false);
        }
    }
}

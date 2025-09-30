use std::marker::PhantomData;

use ark_crypto_primitives::{
    merkle_tree::{Config, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_std::{
    rand::{thread_rng, Rng},
    test_rng,
};
use warp::{
    merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget},
    relations::{
        r1cs::{
            merkle_inclusion::{MerkleInclusionConfig, MerkleInclusionInstance},
            MerkleInclusionRelation, MerkleInclusionWitness,
        },
        Relation,
    },
};

pub fn initialize_merkle_tree<F: PrimeField + Absorb>(
    height: usize,
    poseidon_config: PoseidonConfig<F>,
    mut rng: impl Rng,
) -> (
    MerkleInclusionConfig<F, PoseidonMerkleConfig<F>, PoseidonMerkleConfigGadget<F>>,
    Vec<Vec<F>>,
    MerkleTree<PoseidonMerkleConfig<F>>,
) {
    let leaf_len = 2;
    let config = MerkleInclusionConfig::<F, PoseidonMerkleConfig<F>, PoseidonMerkleConfigGadget<F>> {
        leaf_len,
        height,
        leaf_hash_param: poseidon_config.clone(),
        two_to_one_hash_param: poseidon_config.clone(),
        _merkle_config_gadget: PhantomData,
    };

    // sample some leaves
    let n_leaves = 1 << (height - 1);
    let leaves = (0..n_leaves)
        .map(|_| vec![F::rand(&mut rng), F::rand(&mut rng)])
        .collect();

    // commit to the Merkle tree
    let mt = MerkleTree::new(&poseidon_config, &poseidon_config, &leaves).unwrap();

    (config, leaves, mt)
}

pub fn generate_merkle_instance_witness_pair<F: PrimeField + Absorb>(
    mt_config: &MerkleInclusionConfig<F, PoseidonMerkleConfig<F>, PoseidonMerkleConfigGadget<F>>,
    mt: &MerkleTree<PoseidonMerkleConfig<F>>,
    index: usize,
    leaf: &Vec<F>,
) -> (Vec<F>, Vec<F>) {
    let proof = mt.generate_proof(index).unwrap();
    let instance =
        MerkleInclusionInstance::<F, PoseidonMerkleConfig<F>, PoseidonMerkleConfigGadget<F>> {
            root: mt.root(),
            leaf: leaf.clone(),
            _merkle_config_gadget: PhantomData,
        };
    let witness =
        MerkleInclusionWitness::<F, PoseidonMerkleConfig<F>, PoseidonMerkleConfigGadget<F>> {
            proof,
            _merkle_config_gadget: PhantomData,
        };
    let relation = MerkleInclusionRelation::new(instance, witness, mt_config.clone());
    (relation.x, relation.w)
}

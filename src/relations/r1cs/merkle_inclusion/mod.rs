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

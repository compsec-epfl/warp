use ark_crypto_primitives::{
    merkle_tree::{Config as MerkleConfig, LeafParam, MerkleTree, Path, TwoToOneParam},
    Error,
};
use ark_ff::Field;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::marker::PhantomData;

use crate::relation_accumulator::relation_accumulator::RelationAccumulator;

#[derive(Clone)]
pub struct MerkleTreeRelationAccumulatorConfig<M: MerkleConfig> {
    leaf_hash_param: LeafParam<M>,
    one_two_hash_param: TwoToOneParam<M>,
    _merkle_config: PhantomData<M>,
}

pub struct MerkleTreeRelationAccumulator<F: Field, M: MerkleConfig, R: ConstraintSynthesizer<F>> {
    merkle_tree: MerkleTree<M>,
    _field: PhantomData<F>,
    _merkle_config: PhantomData<M>,
    _relation: PhantomData<R>,
}

impl<F, M, R> RelationAccumulator<F> for MerkleTreeRelationAccumulator<F, M, R>
where
    F: Field,
    M: MerkleConfig<Leaf = [F]>,
    R: ConstraintSynthesizer<F>,
{
    type Config = MerkleTreeRelationAccumulatorConfig<M>;
    type Commitment = M::InnerDigest;
    type Instance = Vec<F>;
    type Proof = Path<M>;
    type Relation = R;

    fn commit(config: Self::Config, instances: &[Self::Instance]) -> Self {
        Self {
            merkle_tree: MerkleTree::<M>::new(
                &config.leaf_hash_param,
                &config.one_two_hash_param,
                instances,
            )
            .unwrap(),
            _field: PhantomData,
            _merkle_config: PhantomData,
            _relation: PhantomData,
        }
    }

    fn commitment(&self) -> Self::Commitment {
        self.merkle_tree.root()
    }

    fn open(&self, index: usize) -> Result<Self::Proof, Error> {
        self.merkle_tree.generate_proof(index)
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> bool {
        proof
            .verify(
                &config.leaf_hash_param,
                &config.one_two_hash_param,
                commitment,
                instance.as_ref(),
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_std::marker::PhantomData;

    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relation_accumulator::{
            merkle::relation_accumulator::{
                MerkleTreeRelationAccumulator, MerkleTreeRelationAccumulatorConfig,
            },
            RelationAccumulator,
        },
        relations::MerkleInclusionCircuit,
    };

    type ExampleRelationAccumulator = MerkleTreeRelationAccumulator<
        BLS12_381,
        PoseidonMerkleConfig<BLS12_381>,
        MerkleInclusionCircuit<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        >,
    >;

    #[test]
    fn sanity_instantiation() {
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<Vec<BLS12_381>> = vec![leaf0.clone(), leaf1.clone()];

        // make config
        let config = MerkleTreeRelationAccumulatorConfig::<PoseidonMerkleConfig<BLS12_381>> {
            leaf_hash_param: poseidon_test_params(),
            one_two_hash_param: poseidon_test_params(),
            _merkle_config: PhantomData,
        };

        // create the relation accumulator
        let relation_accumulator = ExampleRelationAccumulator::commit(config.clone(), &leaves);

        // get proofs
        let proof0 = relation_accumulator.open(0).unwrap();
        let proof1 = relation_accumulator.open(1).unwrap();

        // verify proofs
        assert!(ExampleRelationAccumulator::verify(
            &config,
            &relation_accumulator.commitment(),
            &leaf0,
            &proof0
        ));
        assert!(ExampleRelationAccumulator::verify(
            &config,
            &relation_accumulator.commitment(),
            &leaf1,
            &proof1
        ));

        // verify invalid proofs
        assert!(!ExampleRelationAccumulator::verify(
            &config,
            &relation_accumulator.commitment(),
            &leaf0,
            &proof1
        ));
        assert!(!ExampleRelationAccumulator::verify(
            &config,
            &relation_accumulator.commitment(),
            &leaf1,
            &proof0
        ));
    }
}

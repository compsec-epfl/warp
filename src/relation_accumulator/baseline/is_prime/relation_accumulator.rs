use ark_crypto_primitives::{
    merkle_tree::{
        constraints::ConfigGadget, Config as MerkleConfig, LeafParam, MerkleTree, Path,
        TwoToOneParam,
    },
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::marker::PhantomData;

use crate::{
    relation::{IsPrimeInstance, IsPrimeRelation, PrattCertificate, Relation},
    relation_accumulator::RelationAccumulator,
};

#[derive(Clone)]
pub struct IsPrimeRelationAccumulatorConfig<M: MerkleConfig> {
    leaf_hash_param: LeafParam<M>,
    two_to_one_hash_param: TwoToOneParam<M>,
    _merkle_config: PhantomData<M>,
}

pub struct IsPrimeRelationAccumulator<
    F: Field + PrimeField,
    M: MerkleConfig,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    R: Relation<F>,
> {
    merkle_tree: MerkleTree<M>,
    relations: Vec<R>,
    _field: PhantomData<F>,
    _merkle_config: PhantomData<M>,
    _merkle_config_gadget: PhantomData<MG>,
}

impl<F, M, MG> RelationAccumulator<F> for IsPrimeRelationAccumulator<F, M, MG, IsPrimeRelation<F>>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
{
    type Config = IsPrimeRelationAccumulatorConfig<M>;
    type Relation = IsPrimeRelation<F>;
    type Commitment = M::InnerDigest;
    type Instance = IsPrimeInstance<F>;
    type Witness = PrattCertificate<F>;
    type Proof = Path<M>;

    fn commit(config: &Self::Config, relations: &[Self::Relation]) -> Self {
        let instances: Vec<Vec<F>> = relations.iter().map(|r| vec![r.instance().prime]).collect();
        Self {
            merkle_tree: MerkleTree::<M>::new(
                &config.leaf_hash_param,
                &config.two_to_one_hash_param,
                &instances,
            )
            .unwrap(),
            relations: relations.to_vec(),
            _field: PhantomData,
            _merkle_config: PhantomData,
            _merkle_config_gadget: PhantomData,
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
                &config.two_to_one_hash_param,
                commitment,
                vec![instance.prime],
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
        relation::{IsPrimeInstance, IsPrimeRelation, IsPrimeWitness, PrattCertificate, Relation},
        relation_accumulator::{
            baseline::is_prime::{IsPrimeRelationAccumulator, IsPrimeRelationAccumulatorConfig},
            RelationAccumulator,
        },
    };

    type ExampleRelationAccumulator = IsPrimeRelationAccumulator<
        BLS12_381,
        PoseidonMerkleConfig<BLS12_381>,
        PoseidonMerkleConfigGadget<BLS12_381>,
        IsPrimeRelation<BLS12_381>,
    >;

    #[test]
    fn example_is_prime_usage() {
        // p = 293, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}]
        let instance = IsPrimeInstance::<BLS12_381> {
            prime: BLS12_381::from(293u64),
        };
        let witness = IsPrimeWitness::<BLS12_381> {
            pratt_certificates: vec![
                PrattCertificate {
                    prime: BLS12_381::from(3u64),
                    generator: BLS12_381::from(2u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64)],
                    prime_factors_p_minus_one_exponents: vec![1],
                },
                PrattCertificate {
                    prime: BLS12_381::from(73u64),
                    generator: BLS12_381::from(5u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64), BLS12_381::from(3u64)],
                    prime_factors_p_minus_one_exponents: vec![3, 2],
                },
                PrattCertificate {
                    prime: BLS12_381::from(293u64),
                    generator: BLS12_381::from(2u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64), BLS12_381::from(73u64)],
                    prime_factors_p_minus_one_exponents: vec![2, 1],
                },
            ],
        };
        // Create the relation
        let relation = IsPrimeRelation::<BLS12_381>::new(instance, witness, ());

        // make accumulator config
        let config = IsPrimeRelationAccumulatorConfig::<PoseidonMerkleConfig<BLS12_381>> {
            leaf_hash_param: poseidon_test_params(),
            two_to_one_hash_param: poseidon_test_params(),
            _merkle_config: PhantomData,
        };

        // create the relation accumulator
        let relation_accumulator = ExampleRelationAccumulator::commit(&config, &[relation]);

        // // get proofs
        // let proof0 = relation_accumulator.open(0).unwrap();
        // let proof1 = relation_accumulator.open(1).unwrap();

        // // verify proofs
        // assert!(ExampleRelationAccumulator::verify(
        //     &config,
        //     &relation_accumulator.commitment(),
        //     &leaf0,
        //     &proof0
        // ));
        // assert!(ExampleRelationAccumulator::verify(
        //     &config,
        //     &relation_accumulator.commitment(),
        //     &leaf1,
        //     &proof1
        // ));

        // // verify invalid proofs
        // assert!(!ExampleRelationAccumulator::verify(
        //     &config,
        //     &relation_accumulator.commitment(),
        //     &leaf0,
        //     &proof1
        // ));
        // assert!(!ExampleRelationAccumulator::verify(
        //     &config,
        //     &relation_accumulator.commitment(),
        //     &leaf1,
        //     &proof0
        // ));
    }
}

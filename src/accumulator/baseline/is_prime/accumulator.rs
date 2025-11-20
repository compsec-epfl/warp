use ark_crypto_primitives::snark::SNARK;
use ark_crypto_primitives::{
    merkle_tree::{
        constraints::ConfigGadget, Config as MerkleConfig, LeafParam, MerkleTree, Path,
        TwoToOneParam,
    },
    Error,
};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof as G16Proof, ProvingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::{
    marker::PhantomData,
    rand::{rngs::StdRng, SeedableRng},
};

use crate::{
    accumulator::RelationAccumulator,
    relations::{
        r1cs::{IsPrimeInstance, IsPrimeRelation, IsPrimeSynthesizer, PrattCertificate},
        Relation,
    },
};

#[derive(Clone)]
pub struct IsPrimeRelationAccumulatorConfig<F, M, P>
where
    F: Field + PrimeField,
    M: MerkleConfig,
    P: Pairing<ScalarField = F>,
{
    leaf_hash_param: LeafParam<M>,
    two_to_one_hash_param: TwoToOneParam<M>,
    proving_key: ProvingKey<P>,
    prepared_vk: PreparedVerifyingKey<P>,
    _merkle_config: PhantomData<M>,
}
pub struct IsPrimeRelationProof<F, M, P>
where
    F: Field + PrimeField,
    M: MerkleConfig,
    P: Pairing<ScalarField = F>,
{
    pub inclusion: Path<M>,
    pub in_language: G16Proof<P>,
}

pub struct IsPrimeRelationAccumulator<F, M, MG, R, P>
where
    F: Field + PrimeField,
    M: MerkleConfig,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    R: Relation<F>,
    P: Pairing<ScalarField = F>,
{
    merkle_tree: MerkleTree<M>,
    relations: Vec<R>,
    proving_key: ProvingKey<P>,
    _field: PhantomData<F>,
    _merkle_config: PhantomData<M>,
    _merkle_config_gadget: PhantomData<MG>,
}

impl<F, M, MG, P> RelationAccumulator<F>
    for IsPrimeRelationAccumulator<F, M, MG, IsPrimeRelation<F>, P>
where
    F: Field + PrimeField,
    M: MerkleConfig<Leaf = [F]>,
    MG: ConfigGadget<M, F, Leaf = [FpVar<F>]>,
    P: Pairing<ScalarField = F>,
{
    type Config = IsPrimeRelationAccumulatorConfig<F, M, P>;
    type Relation = IsPrimeRelation<F>;
    type Commitment = M::InnerDigest;
    type Instance = IsPrimeInstance<F>;
    type Witness = PrattCertificate<F>;
    type Proof = IsPrimeRelationProof<F, M, P>;

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
            proving_key: config.proving_key.clone(),
            _field: PhantomData,
            _merkle_config: PhantomData,
            _merkle_config_gadget: PhantomData,
        }
    }

    fn commitment(&self) -> Self::Commitment {
        self.merkle_tree.root()
    }

    fn open(&self, index: usize) -> Result<Self::Proof, Error> {
        Ok(IsPrimeRelationProof {
            inclusion: self.merkle_tree.generate_proof(index).unwrap(),
            in_language: Groth16::<P>::prove(
                &self.proving_key,
                IsPrimeSynthesizer::<F> {
                    instance: self.relations[index].instance().clone(),
                    witness: self.relations[index].witness().clone(),
                },
                &mut StdRng::seed_from_u64(0), // TODO: from where should this randomness come?
            )
            .unwrap(),
        })
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> bool {
        proof
            .inclusion
            .verify(
                &config.leaf_hash_param,
                &config.two_to_one_hash_param,
                commitment,
                vec![instance.prime],
            )
            .unwrap()
            && Groth16::<P>::verify_with_processed_vk(
                &config.prepared_vk,
                &[instance.prime],
                &proof.in_language,
            )
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381 as BLS12_381_PAIRING;
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    use ark_groth16::PreparedVerifyingKey;
    use ark_std::marker::PhantomData;
    use ark_std::rand::rngs::OsRng;

    use crate::utils::poseidon::initialize_poseidon_config;
    use crate::{
        accumulator::{
            baseline::is_prime::{IsPrimeRelationAccumulator, IsPrimeRelationAccumulatorConfig},
            RelationAccumulator,
        },
        crypto::merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget},
        relations::{
            r1cs::{IsPrimeInstance, IsPrimeRelation, IsPrimeWitness, PrattCertificate},
            Relation,
        },
    };

    type ExampleRelationAccumulator = IsPrimeRelationAccumulator<
        BLS12_381,
        PoseidonMerkleConfig<BLS12_381>,
        PoseidonMerkleConfigGadget<BLS12_381>,
        IsPrimeRelation<BLS12_381>,
        BLS12_381_PAIRING,
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
        let relation = IsPrimeRelation::<BLS12_381>::new(instance.clone(), witness.clone(), ());

        // Generate groth16 keys
        let (pk, vk) = Groth16::<BLS12_381_PAIRING>::circuit_specific_setup(
            crate::relations::r1cs::IsPrimeSynthesizer::<BLS12_381> {
                instance: instance.clone(),
                witness: witness.clone(),
            },
            &mut OsRng,
        )
        .unwrap();
        let pvk = PreparedVerifyingKey::from(vk);

        // make accumulator config
        let config = IsPrimeRelationAccumulatorConfig::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            BLS12_381_PAIRING,
        > {
            leaf_hash_param: initialize_poseidon_config(),
            two_to_one_hash_param: initialize_poseidon_config(),
            proving_key: pk,
            prepared_vk: pvk,
            _merkle_config: PhantomData,
        };

        // commit
        let relation_accumulator =
            ExampleRelationAccumulator::commit(&config, &[relation.clone(), relation.clone()]);

        // get proof
        let proof0 = relation_accumulator.open(0).unwrap();

        // verify proof
        assert!(ExampleRelationAccumulator::verify(
            &config,
            &relation_accumulator.commitment(),
            &relation.instance(),
            &proof0
        ));
    }
}

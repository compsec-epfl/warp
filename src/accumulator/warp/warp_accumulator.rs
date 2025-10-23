use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    // merkle_tree::{Path, Config as MerkleConfig}
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;
use spongefish::{DuplexSpongeInterface, Unit as SpongefishUnit};

use crate::{
    accumulator::RelationAccumulator,
    linear_code::LinearCode,
    relations::{r1cs::PreimageRelation, Relation},
    utils::bytes_to_vec_f,
};

#[derive(Clone, CanonicalSerialize)]
pub struct PreimageRelationAccumulatorConfig<F, H, C>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    C: LinearCode<F> + CanonicalSerialize,
    C::Config: CanonicalSerialize,
{
    code_config: C::Config,
    hash_parameters: H::Parameters,
    initialization_vector: [u8; 32],
    max_num_constraints: u64,
    previous_accumulations: Vec<F>,
}

// struct PreimageRelationProof<F, M>
// where
//     F: Field + PrimeField,
//     M: MerkleConfig,
// {
//     root_witness: F,
//     root_constraint: F,
//     final_accumulator: Vec<F>,
//     openings: Vec<Path<M>>,
//     opened_values: Vec<F>,
// }

#[allow(dead_code)] // this is WIP anyway
pub struct PreimageRelationAccumulator<F, H, HG, R, S, C>
where
    F: Field + PrimeField + SpongefishUnit,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
    C: LinearCode<F> + CanonicalSerialize,
    C::Config: Clone + CanonicalSerialize,
{
    code_config: C::Config,
    circuit_description: Vec<u8>,
    max_num_constraints: u64,
    spongefish: S,
    _crhs_scheme: PhantomData<H>,
    _crhs_scheme_gadget: PhantomData<HG>,
    _relation: PhantomData<R>,
    _sponge: PhantomData<S>,
}

impl<F, H, HG, R, S, C> RelationAccumulator<F> for PreimageRelationAccumulator<F, H, HG, R, S, C>
where
    F: Field + PrimeField + SpongefishUnit,
    H: CRHScheme<Input = [F], Output = F>,
    H::Parameters: Clone + CanonicalSerialize,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
    C: LinearCode<F> + CanonicalSerialize,
    C::Config: Clone + CanonicalSerialize,
{
    type Config = PreimageRelationAccumulatorConfig<F, H, C>;
    type Relation = PreimageRelation<F, H, HG>;
    type Commitment = F;
    type Instance = F;
    type Witness = Vec<F>;
    type Proof = Vec<F>; // TODO(z-tech)

    fn commit(config: &Self::Config, _relations: &[Self::Relation]) -> Self {
        // initialize st_FS by absorbing: p, M, N, k
        let mut spongefish = S::new(config.initialization_vector);
        let circuit_description = Self::Relation::description(&config.hash_parameters);
        spongefish.absorb_unchecked(&bytes_to_vec_f(&circuit_description));
        let mut public_config: Vec<u8> = Vec::new();
        config.serialize_uncompressed(&mut public_config).unwrap();
        spongefish.absorb_unchecked(&bytes_to_vec_f(&public_config));

        // now we have the keys:
        // pk_ACC = (st_FS, p, M, N, k)
        // vk_ACC = (st_FS, M, N, k)

        // Would be nice to call helpers in separate files for chunks of work maybe like:
        // parse
        // reduce
        // accumulate

        Self {
            code_config: config.code_config.clone(),
            circuit_description,
            max_num_constraints: config.max_num_constraints,
            spongefish,
            _crhs_scheme: PhantomData,
            _crhs_scheme_gadget: PhantomData,
            _relation: PhantomData,
            _sponge: PhantomData,
        }
    }

    fn commitment(&self) -> Self::Commitment {
        // TODO(z-tech)
        F::zero()
    }

    fn open(&self, index: usize) -> Result<Self::Proof, Error> {
        // TODO(z-tech)
        Ok(vec![F::from(index as u64)])
    }

    fn verify(
        _config: &Self::Config,
        _commitment: &Self::Commitment,
        _instance: &Self::Instance,
        _proof: &Self::Proof,
    ) -> bool {
        // TODO(z-tech)
        false
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::UniformRand;
    use ark_std::{
        marker::PhantomData,
        rand::{Rng, RngCore},
        test_rng,
    };
    use spongefish::duplex_sponge::DuplexSponge;
    use spongefish_poseidon::PoseidonPermutation;

    use super::{PreimageRelationAccumulator, PreimageRelationAccumulatorConfig};
    use crate::accumulator::RelationAccumulator;
    use crate::linear_code::{Brakedown, BrakedownConfig};
    use crate::merkle::poseidon::PoseidonMerkleConfig;
    use crate::merkle::poseidon_test_params;
    use crate::relations::{
        r1cs::{PreimageInstance, PreimageRelation, PreimageWitness},
        Relation,
    };

    type TestCRHScheme = CRH<BLS12_381>;
    type TestCRHSchemeGadget = CRHGadget<BLS12_381>;
    type TestMerkleTreeConfig = PoseidonMerkleConfig<BLS12_381>;
    type TestRelation = PreimageRelation<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>;
    type TestSponge = DuplexSponge<PoseidonPermutation<255, BLS12_381, 2, 3>>;
    type TestAccumulator = PreimageRelationAccumulator<
        BLS12_381,
        TestCRHScheme,
        TestCRHSchemeGadget,
        TestRelation,
        TestSponge,
        Brakedown<BLS12_381, TestMerkleTreeConfig, TestCRHScheme>,
    >;

    fn next_power_of_two(n: usize) -> usize {
        if n == 0 {
            return 1;
        }
        let num_leading_zeros = n.leading_zeros();
        let index_of_most_significant_bit = usize::BITS - num_leading_zeros;
        1 << index_of_most_significant_bit
    }

    #[test]
    fn new() {
        let mut rng = test_rng();
        let parameters: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let preimage_0: Vec<BLS12_381> = vec![BLS12_381::rand(&mut rng), BLS12_381::rand(&mut rng)];
        let digest = TestCRHScheme::evaluate(&parameters, preimage_0.clone()).unwrap();
        let relation = PreimageRelation::<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>::new(
            PreimageInstance { digest },
            PreimageWitness {
                preimage: preimage_0,
                _crhs_scheme: PhantomData,
            },
            parameters.clone(),
        );

        // derive sizes
        let max_num_constraints = next_power_of_two(relation.constraints()) as u64;
        let message_len = next_power_of_two(relation.private_inputs().len());

        // TODO (z-tech): works like this, but probably these can be optimized
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let one_two_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let column_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        // generate seed
        let mut rng = ark_std::test_rng();
        let mut rng_seed = [0u8; 32];
        rng.fill_bytes(&mut rng_seed);

        let brakedown_config =
            BrakedownConfig::<BLS12_381, PoseidonMerkleConfig<BLS12_381>, TestCRHScheme> {
                message_len,
                leaf_hash_param,
                one_two_hash_param,
                column_hash_param,
                rng_seed,
                _f: PhantomData::<BLS12_381>,
            };

        // config
        let config: PreimageRelationAccumulatorConfig<
            BLS12_381,
            TestCRHScheme,
            Brakedown<BLS12_381, PoseidonMerkleConfig<BLS12_381>, TestCRHScheme>,
        > = PreimageRelationAccumulatorConfig {
            code_config: brakedown_config,
            hash_parameters: poseidon_test_params(), // CRH parameters
            initialization_vector: test_rng().gen::<[u8; 32]>(),
            max_num_constraints,
            previous_accumulations: vec![],
        };

        // commit
        let _accumulator =
            <TestAccumulator as RelationAccumulator<BLS12_381>>::commit(&config, &[relation]);
    }
}

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::marker::PhantomData;
use spongefish::{DuplexSpongeInterface, Unit as SpongefishUnit};

use crate::{
    relation::{description::vec_field_elements_from_bytes, PreimageRelation, Relation},
    relation_accumulator::relation_accumulator::RelationAccumulator,
};

#[derive(Clone)]
pub struct PreimageRelationAccumulatorConfig<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
{
    codeword_len: u64,
    witness_len: u64,
    hash_parameters: H::Parameters,
    initialization_vector: [u8; 32],
    max_num_constraints: u64,
}

pub struct PreimageRelationAccumulator<F, H, HG, R, S>
where
    F: Field + PrimeField + SpongefishUnit,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
{
    codeword_len: u64,
    witness_len: u64,
    circuit_description: Vec<u8>,
    max_num_constraints: u64,
    spongefish: S,
    _crhs_scheme: PhantomData<H>,
    _crhs_scheme_gadget: PhantomData<HG>,
    _relation: PhantomData<R>,
    _sponge: PhantomData<S>,
}

impl<F, H, HG, R, S> RelationAccumulator<F> for PreimageRelationAccumulator<F, H, HG, R, S>
where
    F: Field + PrimeField + SpongefishUnit,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
{
    type Config = PreimageRelationAccumulatorConfig<F, H>;
    type Relation = PreimageRelation<F, H, HG>;
    type Commitment = F;
    type Instance = F;
    type Witness = Vec<F>;
    type Proof = Vec<F>;

    fn commit(&mut self, relations: &[Self::Relation]) {
        // for new relations
        for relation in relations {
            self.spongefish
                .absorb_unchecked(&vec_field_elements_from_bytes(&relation.public_inputs()));
        }
    }

    fn commitment(&self) -> Self::Commitment {
        F::zero()
    }

    fn new(config: Self::Config) -> Self {
        // fs_state from i = (p, M, N, k)
        let circuit_description = Self::Relation::description(&config.hash_parameters);
        let mut spongefish = S::new(config.initialization_vector);
        spongefish.absorb_unchecked(&vec_field_elements_from_bytes(&circuit_description));
        spongefish.absorb_unchecked(&[F::from(config.max_num_constraints)]);
        spongefish.absorb_unchecked(&[F::from(config.codeword_len)]);
        spongefish.absorb_unchecked(&[F::from(config.witness_len)]);
        Self {
            codeword_len: config.codeword_len,
            witness_len: config.witness_len,
            circuit_description,
            max_num_constraints: config.max_num_constraints,
            spongefish,
            _crhs_scheme: PhantomData,
            _crhs_scheme_gadget: PhantomData,
            _relation: PhantomData,
            _sponge: PhantomData,
        }
    }

    fn open(&self, index: usize) -> Result<Self::Proof, Error> {
        Ok(vec![F::from(index as u64)])
    }

    fn verify(
        config: &Self::Config,
        commitment: &Self::Commitment,
        instance: &Self::Instance,
        proof: &Self::Proof,
    ) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use ark_std::marker::PhantomData;

    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::UniformRand;
    use ark_std::{rand::Rng, test_rng};
    use spongefish::duplex_sponge::DuplexSponge;
    use spongefish_poseidon::PoseidonPermutation;

    use super::{PreimageRelationAccumulator, PreimageRelationAccumulatorConfig};
    use crate::merkle::poseidon_test_params;
    use crate::relation::{PreimageInstance, PreimageRelation, PreimageWitness, Relation};
    use crate::relation_accumulator::RelationAccumulator;

    type TestCRHScheme = CRH<BLS12_381>;
    type TestCRHSchemeGadget = CRHGadget<BLS12_381>;
    type TestRelation = PreimageRelation<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>;
    type TestSponge = DuplexSponge<PoseidonPermutation<255, BLS12_381, 2, 3>>;
    type TestAccumulator = PreimageRelationAccumulator<
        BLS12_381,
        TestCRHScheme,
        TestCRHSchemeGadget,
        TestRelation,
        TestSponge,
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
        // relation
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
        let max_num_constraints = next_power_of_two(relation.constraints()) as u64;

        // config
        let config = PreimageRelationAccumulatorConfig {
            codeword_len: 64,
            witness_len: 32,
            hash_parameters: poseidon_test_params(),
            initialization_vector: test_rng().gen(),
            max_num_constraints,
        };

        // commit
        let accumulator: TestAccumulator = RelationAccumulator::new(config);

        // sanity
        assert_eq!(accumulator.codeword_len, 64);
        assert_eq!(accumulator.witness_len, 32);
        assert_eq!(accumulator.max_num_constraints, 512);
        assert!(!accumulator.circuit_description.is_empty());
    }
}

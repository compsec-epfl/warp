use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;
use spongefish::{DuplexSpongeInterface, Unit as SpongefishUnit};

use crate::{
    linear_code::LinearCode,
    relation::{description::vec_field_elements_from_bytes, PreimageRelation, Relation},
    relation_accumulator::relation_accumulator::RelationAccumulator,
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

pub struct PreimageRelationAccumulator<F, H, HG, R, S, C>
where
    F: Field + PrimeField + SpongefishUnit,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
    C: LinearCode<F> + CanonicalSerialize,
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
    H::Parameters: CanonicalSerialize,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface<F>,
    C: LinearCode<F> + CanonicalSerialize,
    C::Config: Clone + CanonicalSerialize,
{
    type Config = PreimageRelationAccumulatorConfig<F, H, C>;
    type Relation = PreimageRelation<F, H, HG>; // the constraint system
    type Commitment = F; // the state of the accumulator
    type Instance = F; // the output of the hash
    type Witness = Vec<F>; // the input of the hash
    type Proof = Vec<F>;

    fn commit(&mut self, relations: &[Self::Relation]) {
        // NOTE: Ignoring previous states for now

        // Parse new relations
        // for relation in relations {
        //     self.spongefish
        //         .absorb_unchecked(&vec_field_elements_from_bytes(&relation.public_inputs()));
        // }

        // Reduce
        let encoder = C::new(self.code_config.clone());
        let mut encodings = Vec::new();
        for relation in relations {
            println!("private_inputs: {:?}", relation.private_inputs());
            encodings
                .push(encoder.encode(&vec_field_elements_from_bytes(&relation.private_inputs())));
        }
    }

    fn commitment(&self) -> Self::Commitment {
        F::zero()
    }

    fn new(config: Self::Config) -> Self {
        // fs_state from i = (p, M, N, k)
        let mut spongefish = S::new(config.initialization_vector);
        let circuit_description = Self::Relation::description(&config.hash_parameters);
        spongefish.absorb_unchecked(&vec_field_elements_from_bytes(&circuit_description));
        let mut public_config: Vec<u8> = Vec::new();
        config.serialize_uncompressed(&mut public_config).unwrap();
        spongefish.absorb_unchecked(&vec_field_elements_from_bytes(&mut public_config));
        Self {
            code_config: config.code_config,
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
    use crate::linear_code::{ReedSolomon, ReedSolomonConfig};
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
        ReedSolomon<BLS12_381>,
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
        let message_len = next_power_of_two(relation.private_inputs().len());
        let code_len = next_power_of_two(message_len as usize);

        // config
        let config = PreimageRelationAccumulatorConfig {
            code_config: ReedSolomonConfig::<BLS12_381>::default(message_len, code_len),
            hash_parameters: poseidon_test_params(),
            initialization_vector: test_rng().gen(),
            max_num_constraints,
            previous_accumulations: vec![],
        };

        // commit
        let accumulator: TestAccumulator = RelationAccumulator::new(config);

        // sanity
        // assert_eq!(accumulator.config.codeword_len, 256);
        // assert_eq!(accumulator.config.witness_len, 128);
        assert_eq!(accumulator.max_num_constraints, 512);
        assert!(!accumulator.circuit_description.is_empty());
    }
}

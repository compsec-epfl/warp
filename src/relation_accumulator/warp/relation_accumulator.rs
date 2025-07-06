use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::marker::PhantomData;
use spongefish::DuplexSpongeInterface;

use crate::{
    relation::{PreimageRelation, Relation},
    relation_accumulator::relation_accumulator::RelationAccumulator,
};

#[derive(Clone)]
pub struct PreimageRelationAccumulatorConfig<F, H>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
{
    codeword_len: usize,
    witness_len: usize,
    hash_parameters: H::Parameters,
    initialization_vector: [u8; 32],
}

pub struct PreimageRelationAccumulator<F, H, HG, R, S>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface,
{
    codeword_len: usize,
    witness_len: usize,
    circuit_description: Vec<u8>,
    max_num_constraints: usize,
    spongefish: S,
    _crhs_scheme: PhantomData<H>,
    _crhs_scheme_gadget: PhantomData<HG>,
    _relation: PhantomData<R>,
    _sponge: PhantomData<S>,
}

impl<F, H, HG, R, S> RelationAccumulator<F> for PreimageRelationAccumulator<F, H, HG, R, S>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
    S: DuplexSpongeInterface,
{
    type Config = PreimageRelationAccumulatorConfig<F, H>;
    type Relation = PreimageRelation<F, H, HG>;
    type Commitment = F;
    type Instance = F;
    type Witness = Vec<F>;
    type Proof = Vec<F>;

    fn commit(config: Self::Config, relations: &[Self::Relation]) -> Self {
        // num constraints may be different per assignment (TODO: check if this is true?)
        let mut max_num_constraints = 0_usize;
        for relation in relations {
            let num_constraints = relation.constraints();
            if num_constraints > max_num_constraints {
                max_num_constraints = num_constraints;
            }
        }

        // fs_state from i = (p, M, N, k) (TODO: hash parameters?)
        let circuit_description = Self::Relation::description(&config.hash_parameters);
        let mut spongefish = S::new(config.initialization_vector);
        spongefish.absorb_unchecked(&circuit_description);
        spongefish.absorb_unchecked(&max_num_constraints.to_le_bytes());
        spongefish.absorb_unchecked(&config.codeword_len.to_le_bytes());
        spongefish.absorb_unchecked(&config.witness_len.to_le_bytes());

        Self {
            codeword_len: config.codeword_len,
            witness_len: config.witness_len,
            circuit_description,
            max_num_constraints,
            spongefish,
            _crhs_scheme: PhantomData,
            _crhs_scheme_gadget: PhantomData,
            _relation: PhantomData,
            _sponge: PhantomData,
        }
    }

    fn commitment(&self) -> Self::Commitment {
        F::zero()
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
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::{Field, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::io::Cursor;
    use ark_std::test_rng;
    use spongefish::duplex_sponge::{DuplexSponge, Permutation};
    use spongefish::DuplexSpongeInterface;
    use spongefish_poseidon::PoseidonHash;
    use spongefish_poseidon::PoseidonPermutation;
    use zeroize::{DefaultIsZeroes, Zeroize, ZeroizeOnDrop};

    use super::{PreimageRelationAccumulator, PreimageRelationAccumulatorConfig};
    use crate::merkle::poseidon_test_params;
    use crate::relation::PreimageRelation;
    use crate::relation_accumulator::RelationAccumulator;

    type TestCRHScheme = CRH<BLS12_381>;
    type TestCRHSchemeGadget = CRHGadget<BLS12_381>;
    type TestRelation = PreimageRelation<BLS12_381, TestCRHScheme, TestCRHSchemeGadget>;
    // type TestSponge = DuplexSponge<PoseidonPermutation<255, BLS12_381, 2, 3>>;
    type TestSponge = PoseidonHash<255, BLS12_381, 2, 3>;
    type TestAccumulator = PreimageRelationAccumulator<
        BLS12_381,
        TestCRHScheme,
        TestCRHSchemeGadget,
        TestRelation,
        TestSponge,
    >;

    #[derive(Zeroize, ZeroizeOnDrop, Clone, Default)]
    pub struct FieldSpongeAdapter<S, F>
    where
        S: DuplexSpongeInterface<u8>,
        F: PrimeField + CanonicalSerialize + CanonicalDeserialize,
    {
        inner: S,
        _marker: std::marker::PhantomData<F>,
    }

    impl<S, F> FieldSpongeAdapter<S, F>
    where
        S: DuplexSpongeInterface<u8>,
        F: PrimeField + CanonicalSerialize + CanonicalDeserialize,
    {
        pub fn new(iv: [u8; 32]) -> Self {
            Self {
                inner: S::new(iv),
                _marker: Default::default(),
            }
        }
    }

    impl<S, F> DuplexSpongeInterface<F> for FieldSpongeAdapter<S, F>
    where
        S: DuplexSpongeInterface<u8>,
        F: PrimeField + CanonicalSerialize + CanonicalDeserialize + spongefish::Unit,
    {
        fn new(iv: [u8; 32]) -> Self {
            Self::new(iv)
        }

        fn absorb_unchecked(&mut self, elems: &[F]) -> &mut Self {
            let mut serialized_elems: Vec<u8> = vec![];
            for elem in elems {
                let mut buf = Vec::new();
                elem.serialize_uncompressed(&mut buf).unwrap();
                serialized_elems.append(&mut buf);
            }
            self.inner.absorb_unchecked(&serialized_elems);
            self
        }

        fn squeeze_unchecked(&mut self, out: &mut [F]) -> &mut Self {
            // squeeze bytes
            let mut squeezed = Vec::new();
            self.inner.squeeze_unchecked(&mut squeezed);

            // figure out how many bytes we fit in one field element
            let mut buf = Vec::new();
            F::zero().serialize_uncompressed(&mut buf).unwrap();
            let size = buf.len();
            // TODO(z-tech): would squeezed ever have length gt what fits into one field element?
            // Shouldn't this interface return F and not [F]?
            assert!(squeezed.len() <= size);

            // deserialize back into field elements
            let mut reader = Cursor::new(squeezed);
            assert!(out.len() > 0);
            out[0] = F::deserialize_uncompressed(&mut reader).unwrap();
            self
        }

        fn ratchet_unchecked(&mut self) -> &mut Self {
            self.inner.ratchet_unchecked();
            self
        }
    }

    #[test]
    fn test_commit_function() {
        let mut rng = test_rng();

        // Poseidon parameters for CRH
        let params: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let config = PreimageRelationAccumulatorConfig {
            codeword_len: 64,
            witness_len: 32,
            hash_parameters: params.clone(),
            initialization_vector: [0u8; 32],
        };

        // For now, create an empty list of relations (you can add real ones later)
        let relations: Vec<TestRelation> = vec![];

        let accumulator: TestAccumulator = RelationAccumulator::commit(config, &relations);

        assert_eq!(accumulator.codeword_len, 64);
        assert_eq!(accumulator.witness_len, 32);
        assert_eq!(accumulator.max_num_constraints, 0);
        assert!(!accumulator.circuit_description.is_empty());
    }
}

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;

use crate::{
    relation::{PreimageRelation, Relation},
    relation_accumulator::relation_accumulator::RelationAccumulator,
};

#[derive(Clone)]
pub struct PreimageRelationAccumulatorConfig<F, H, HG, R>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
{
    circuit_definition: Vec<u8>,
    hash_params: H::Parameters,
    _field: PhantomData<F>,
    _crhs_scheme_gadget: PhantomData<HG>,
    _relation: PhantomData<R>,
}

impl<F, H, HG, R> PreimageRelationAccumulatorConfig<F, H, HG, R>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    R: Relation<F>,
{
    pub fn new(hash_params: H::Parameters) -> Self {
        Self {
            circuit_definition: Vec::new(), //R::definition(),
            hash_params,
            _field: PhantomData,
            _crhs_scheme_gadget: PhantomData,
            _relation: PhantomData,
        }
    }
}

// pub struct PreimageRelationAccumulator<
// F, H, HG, R
// >
// where
//     F: Field + PrimeField,
//     H: CRHScheme<Input = [F], Output = F>,
//     HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
//     R: Relation<F>,
// {
//     merkle_tree: MerkleTree<M>,
//     _field: PhantomData<F>,
//     _merkle_config: PhantomData<M>,
//     _merkle_config_gadget: PhantomData<MG>,
//     _relation: PhantomData<R>,
// }

// impl<F, H, HG, R> RelationAccumulator<F> for PreimageRelationAccumulator<F, H, HG, R>
// where
//     F: Field + PrimeField,
//     H: CRHScheme<Input = [F], Output = F>,
//     HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
//     R: Relation<F>,
// {
//     type Config = PreimageRelationAccumulatorConfig<F, H, HG, R>;
//     type Relation = PreimageRelation<F, H, HG>;
//     type Commitment = M::InnerDigest;
//     type Instance = F;
//     type Witness = Vec<F>;
//     type Proof = Path<M>;

//     fn commit(config: Self::Config, relations: &[Self::Relation]) -> Self {
//         Self {
//             merkle_tree: MerkleTree::<M>::new(
//                 &config.leaf_hash_param,
//                 &config.one_two_hash_param,
//                 instances,
//             )
//             .unwrap(),
//             _field: PhantomData,
//             _merkle_config: PhantomData,
//             _merkle_config_gadget: PhantomData,
//             _relation: PhantomData,
//         }
//     }

//     fn commitment(&self) -> Self::Commitment {
//         self.merkle_tree.root()
//     }

//     fn open(&self, index: usize) -> Result<Self::Proof, Error> {
//         self.merkle_tree.generate_proof(index)
//     }

//     fn verify(
//         config: &Self::Config,
//         commitment: &Self::Commitment,
//         instance: &Self::Instance,
//         proof: &Self::Proof,
//     ) -> bool {
//         proof
//             .verify(
//                 &config.leaf_hash_param,
//                 &config.one_two_hash_param,
//                 commitment,
//                 instance.as_ref(),
//             )
//             .unwrap()
//     }
// }

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_std::marker::PhantomData;

    use crate::{
        merkle::poseidon::{
            poseidon_test_params, PoseidonMerkleConfig, PoseidonMerkleConfigGadget,
        },
        relation::MerkleInclusionRelation,
        relation_accumulator::RelationAccumulator,
    };

    // #[test]
    // fn generate_params() {
    //     let parameters: PoseidonMerkleConfig<BLS12_381> = poseidon_test_params();
    //     let gadget_parameters: PoseidonMerkleConfigGadget<BLS12_381> =
    //         PoseidonMerkleConfigGadget::new(&parameters);
    //     let relation_accumulator_config = PreimageRelationAccumulatorConfig::<
    //         BLS12_381,
    //         PoseidonMerkleConfig<BLS12_381>,
    //         PoseidonMerkleConfigGadget<BLS12_381>,
    //         MerkleInclusionRelation<
    //             BLS12_381,
    //             PoseidonMerkleConfig<BLS12_381>,
    //             PoseidonMerkleConfigGadget<BLS12_381>,
    //         >,
    //     >::new(parameters);
    //     assert!(relation_accumulator_config.circuit_definition.is_empty());
    // }
}

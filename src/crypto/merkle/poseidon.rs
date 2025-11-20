use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{
                CRHGadget as PoseidonCRHGadget, TwoToOneCRHGadget as PoseidonTwoToOneCRHGadget,
            },
            TwoToOneCRH as PoseidonTwoToOneCRH, CRH as PoseidonCRH,
        },
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{
        constraints::ConfigGadget as MerkleConfigGadget, Config as MerkleConfig,
        IdentityDigestConverter,
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::marker::PhantomData;

#[derive(Clone)]
pub struct PoseidonMerkleConfig<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField + Absorb> MerkleConfig for PoseidonMerkleConfig<F> {
    type Leaf = [F];
    type LeafDigest = <Self::LeafHash as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHScheme>::Output;
    type LeafHash = PoseidonCRH<F>;
    type TwoToOneHash = PoseidonTwoToOneCRH<F>;
}

#[derive(Clone)]
pub struct PoseidonMerkleConfigGadget<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField + Absorb> MerkleConfigGadget<PoseidonMerkleConfig<F>, F>
    for PoseidonMerkleConfigGadget<F>
{
    type Leaf = [FpVar<F>];
    type LeafDigest = <PoseidonCRHGadget<F> as CRHSchemeGadget<PoseidonCRH<F>, F>>::OutputVar;
    type LeafHash = PoseidonCRHGadget<F>;
    type LeafInnerConverter = IdentityDigestConverter<Self::LeafDigest>;
    type InnerDigest = <PoseidonTwoToOneCRHGadget<F> as TwoToOneCRHSchemeGadget<
        PoseidonTwoToOneCRH<F>,
        F,
    >>::OutputVar;
    type TwoToOneHash = PoseidonTwoToOneCRHGadget<F>;
}

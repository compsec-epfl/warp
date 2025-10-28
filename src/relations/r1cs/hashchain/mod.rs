mod config;
mod instance;
mod relation;
mod synthesizer;
mod witness;

use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
pub use config::HashChainConfig;
pub use instance::HashChainInstance;
pub use relation::compute_hash_chain;
pub use relation::HashChainRelation;
pub use synthesizer::HashChainSynthesizer;
pub use witness::HashChainWitness;

use crate::{relations::relation_trait::ToPolySystem, WARPError};

use super::R1CS;

impl<
        F: PrimeField + Absorb,
        H: CRHScheme<Input = [F], Output = F>,
        HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
    > ToPolySystem<F> for HashChainRelation<F, H, HG>
{
    fn into_r1cs(config: &Self::Config) -> Result<R1CS<F>, WARPError> {
        let (params, hash_chain_size) = config;
        let preimage = vec![F::ZERO];
        let digest = compute_hash_chain::<F, H>(params, &preimage, *hash_chain_size);
        let instance = HashChainInstance { digest };
        let witness = HashChainWitness {
            preimage,
            _crhs_scheme: PhantomData::<H>,
        };
        let constraint_synthesizer = HashChainSynthesizer {
            instance,
            witness,
            config: params.clone(),
            size: *hash_chain_size,
            _crhs_scheme_gadget: PhantomData::<HG>,
        };

        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();
        R1CS::try_from(constraint_system)
    }
}

use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

use crate::relations::r1cs::hashchain::{HashChainInstance, HashChainWitness};

#[derive(Clone)]
pub struct HashChainSynthesizer<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F]>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>]>,
{
    pub instance: HashChainInstance<F>,
    pub witness: HashChainWitness<F, H>,
    pub config: H::Parameters,
    pub size: usize, // size of hashchain
    pub _crhs_scheme_gadget: PhantomData<HG>,
}

impl<F, H, HG> ConstraintSynthesizer<F> for HashChainSynthesizer<F, H, HG>
where
    F: Field + PrimeField,
    H: CRHScheme<Input = [F], Output = F>,
    HG: CRHSchemeGadget<H, F, InputVar = [FpVar<F>], OutputVar = FpVar<F>>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let preimage_var: Vec<FpVar<F>> = self
            .witness
            .preimage
            .iter()
            .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
            .collect::<Result<_, _>>()?;
        let digest_var = FpVar::new_input(cs.clone(), || Ok(self.instance.digest))?;
        let params_var = HG::ParametersVar::new_constant(cs.clone(), &self.config)?;
        let mut computed_hash = HG::evaluate(&params_var, &preimage_var)?;
        for _ in 0..(self.size - 1) {
            computed_hash = HG::evaluate(&params_var, &[computed_hash])?;
        }
        computed_hash.enforce_equal(&digest_var)?;
        Ok(())
    }
}

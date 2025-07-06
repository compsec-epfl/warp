use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::relation::{IdentityInstance, IdentityWitness};

#[derive(Clone)]
pub struct IdentitySynthesizer<F: Field + PrimeField> {
    pub instance: IdentityInstance<F>,
    pub witness: IdentityWitness<F>,
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for IdentitySynthesizer<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_input(cs.clone(), || Ok(self.instance.x))?;
        let w_var = FpVar::new_witness(cs.clone(), || Ok(self.witness.w))?;

        x_var.enforce_equal(&w_var)?;
        cs.finalize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    use super::IdentitySynthesizer;
    use crate::relation::identity::{IdentityInstance, IdentityWitness};

    #[test]
    fn sanity() {
        let constraint_synthesizer = IdentitySynthesizer::<BLS12_381> {
            instance: IdentityInstance::<BLS12_381> {
                x: BLS12_381::from(1u64),
            },
            witness: IdentityWitness::<BLS12_381> {
                w: BLS12_381::from(1u64),
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_2() {
        let constraint_synthesizer = IdentitySynthesizer::<BLS12_381> {
            instance: IdentityInstance::<BLS12_381> {
                x: BLS12_381::from(1u64),
            },
            witness: IdentityWitness::<BLS12_381> {
                w: BLS12_381::from(0u64),
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
}

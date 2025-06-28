use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use crate::relation::Relation;

#[derive(Clone)]
pub struct IdentityInstance<F: Field + PrimeField> {
    pub x: F,
}

#[derive(Clone)]
pub struct IdentityWitness<F: Field + PrimeField> {
    pub w: F,
}

#[derive(Clone)]
pub struct IdentityConstraintSynthesizer<F: Field + PrimeField> {
    instance: IdentityInstance<F>,
    witness: IdentityWitness<F>,
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for IdentityConstraintSynthesizer<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_var = FpVar::new_input(cs.clone(), || Ok(self.instance.x))?;
        let w_var = FpVar::new_witness(cs.clone(), || Ok(self.witness.w))?;

        x_var.enforce_equal(&w_var)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct IdentityRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
}

impl<F: Field + PrimeField> Relation<F> for IdentityRelation<F> {
    type Instance = IdentityInstance<F>;
    type Witness = IdentityWitness<F>;
    fn new(instance: Self::Instance, witness: Self::Witness) -> Self {
        let constraint_synthesizer = IdentityConstraintSynthesizer::<F> { instance, witness };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self { constraint_system }
    }
    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::relation::identity::{
        IdentityConstraintSynthesizer, IdentityInstance, IdentityRelation, IdentityWitness,
    };

    use crate::relation::Relation;

    #[test]
    fn witness_sanity() {
        let constraint_synthesizer = IdentityConstraintSynthesizer::<BLS12_381> {
            instance: IdentityInstance::<BLS12_381> {
                x: BLS12_381::from(1u64),
            },
            witness: IdentityWitness::<BLS12_381> {
                w: BLS12_381::from(1u64),
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_2() {
        let constraint_synthesizer = IdentityConstraintSynthesizer::<BLS12_381> {
            instance: IdentityInstance::<BLS12_381> {
                x: BLS12_381::from(1u64),
            },
            witness: IdentityWitness::<BLS12_381> {
                w: BLS12_381::from(0u64),
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn relation_sanity() {
        let instance = IdentityInstance::<BLS12_381> {
            x: BLS12_381::from(293u64),
        };

        let witness = IdentityWitness::<BLS12_381> {
            w: BLS12_381::from(293u64),
        };

        // Create and verify the relation
        let relation = IdentityRelation::<BLS12_381>::new(instance, witness);
        assert!(relation.verify());
    }
}

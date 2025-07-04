use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};

use crate::relation::{
    constraint_matrices::SerializableConstraintMatrices,
    identity::synthesizer::IdentitySynthesizer, IdentityInstance, IdentityWitness, Relation,
};

#[derive(Clone)]
pub struct IdentityRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
}

impl<F: Field + PrimeField> Relation<F> for IdentityRelation<F> {
    type Instance = IdentityInstance<F>;
    type Witness = IdentityWitness<F>;
    type Config = ();

    fn description(_config: &Self::Config) -> Vec<u8> {
        let constraint_synthesizer = IdentitySynthesizer::<F> {
            instance: Self::Instance { x: F::zero() },
            witness: Self::Witness { w: F::zero() },
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }

    fn new(instance: Self::Instance, witness: Self::Witness, _config: Self::Config) -> Self {
        let constraint_synthesizer = IdentitySynthesizer::<F> { instance, witness };
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
    use crate::relation::{
        identity::{IdentityInstance, IdentityRelation, IdentityWitness},
        Relation,
    };
    use ark_bls12_381::Fr as BLS12_381;

    #[test]
    fn relation_sanity() {
        let instance = IdentityInstance::<BLS12_381> {
            x: BLS12_381::from(293u64),
        };

        let witness = IdentityWitness::<BLS12_381> {
            w: BLS12_381::from(293u64),
        };

        // Create and verify the relation
        let relation = IdentityRelation::<BLS12_381>::new(instance, witness, ());
        assert!(relation.verify());
    }
}

use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;

use crate::relations::{
    r1cs::{IdentityInstance, IdentitySynthesizer, IdentityWitness},
    Relation, SerializableConstraintMatrices,
};

#[derive(Clone)]
pub struct IdentityRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
    instance: IdentityInstance<F>,
    witness: IdentityWitness<F>,
}

impl<F: Field + PrimeField> Relation<F> for IdentityRelation<F> {
    type Instance = IdentityInstance<F>;
    type Witness = IdentityWitness<F>;
    type Config = ();

    fn constraints(&self) -> usize {
        self.constraint_system.num_constraints()
    }

    fn description(_config: &Self::Config) -> Vec<u8> {
        let constraint_synthesizer = IdentitySynthesizer::<F> {
            instance: Self::Instance { x: F::zero() },
            witness: Self::Witness { w: F::zero() },
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }

    fn instance(&self) -> Self::Instance {
        self.instance.clone()
    }

    fn new(instance: Self::Instance, witness: Self::Witness, _config: Self::Config) -> Self {
        let constraint_synthesizer = IdentitySynthesizer::<F> {
            instance: instance.clone(),
            witness: witness.clone(),
        };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
            instance,
            witness,
        }
    }

    fn public_config(&self) -> Vec<u8> {
        // there is no public config for this relation
        vec![]
    }

    fn public_inputs(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.instance.serialize_uncompressed(&mut inputs).unwrap();
        inputs
    }

    fn private_inputs(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.witness.serialize_uncompressed(&mut inputs).unwrap();
        inputs
    }

    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }

    fn witness(&self) -> Self::Witness {
        self.witness.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::relations::{
        r1cs::identity::{IdentityInstance, IdentityRelation, IdentityWitness},
        Relation,
    };
    use ark_bls12_381::Fr as BLS12_381;

    #[test]
    fn relation_sanity_1() {
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

    #[test]
    fn relation_sanity_2() {
        let instance = IdentityInstance::<BLS12_381> {
            x: BLS12_381::from(293u64),
        };

        let witness = IdentityWitness::<BLS12_381> {
            w: BLS12_381::from(292u64),
        };

        // Create and verify the relation
        let relation = IdentityRelation::<BLS12_381>::new(instance, witness, ());
        assert!(!relation.verify());
    }
}

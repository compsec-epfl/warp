use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};

use crate::relation::{
    description::SerializableConstraintMatrices,
    is_prime::{synthesizer::IsPrimeSynthesizer, PrattCertificate},
    IsPrimeInstance, IsPrimeWitness, Relation,
};

pub struct IsPrimeRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
    instance: IsPrimeInstance<F>,
}

impl<F: Field + PrimeField> Relation<F> for IsPrimeRelation<F> {
    type Instance = IsPrimeInstance<F>;
    type Witness = IsPrimeWitness<F>;
    type Config = ();

    fn constraints(&self) -> usize {
        self.constraint_system.num_constraints()
    }

    fn description(_config: &Self::Config) -> Vec<u8> {
        let constraint_synthesizer = IsPrimeSynthesizer::<F> {
            instance: Self::Instance { prime: F::zero() },
            witness: Self::Witness {
                pratt_certificates: vec![PrattCertificate {
                    prime: F::zero(),
                    generator: F::zero(),
                    prime_factors_p_minus_one: vec![],
                    prime_factors_p_minus_one_exponents: vec![],
                }],
            },
        };
        SerializableConstraintMatrices::generate_description(constraint_synthesizer)
    }
    fn new(instance: Self::Instance, witness: Self::Witness, _config: Self::Config) -> Self {
        let constraint_synthesizer = IsPrimeSynthesizer::<F> {
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
        }
    }
    fn public_inputs(&self) -> Vec<u8> {
        let mut inputs: Vec<u8> = Vec::new();
        self.instance
            .prime
            .serialize_uncompressed(&mut inputs)
            .unwrap();
        inputs
    }
    fn verify(&self) -> bool {
        self.constraint_system.is_satisfied().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;

    use crate::relation::is_prime::PrattCertificate;
    use crate::relation::is_prime::{IsPrimeInstance, IsPrimeRelation, IsPrimeWitness};
    use crate::relation::Relation;
    #[test]
    fn relation_sanity() {
        // p = 293, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}]
        let instance = IsPrimeInstance::<BLS12_381> {
            prime: BLS12_381::from(293u64),
        };

        let witness = IsPrimeWitness::<BLS12_381> {
            pratt_certificates: vec![
                PrattCertificate {
                    prime: BLS12_381::from(3u64),
                    generator: BLS12_381::from(2u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64)],
                    prime_factors_p_minus_one_exponents: vec![1],
                },
                PrattCertificate {
                    prime: BLS12_381::from(73u64),
                    generator: BLS12_381::from(5u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64), BLS12_381::from(3u64)],
                    prime_factors_p_minus_one_exponents: vec![3, 2],
                },
                PrattCertificate {
                    prime: BLS12_381::from(293u64),
                    generator: BLS12_381::from(2u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64), BLS12_381::from(73u64)],
                    prime_factors_p_minus_one_exponents: vec![2, 1],
                },
            ],
        };

        // Create and verify the relation
        let relation = IsPrimeRelation::<BLS12_381>::new(instance, witness, ());
        assert!(relation.verify());
    }
}

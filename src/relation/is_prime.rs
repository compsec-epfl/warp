use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use crate::relation::Relation;

#[derive(Clone)]
pub struct PrattCertificate<F: Field + PrimeField> {
    pub prime: F,
    pub generator: F,
    pub prime_factors_p_minus_one: Vec<F>,
    pub prime_factors_p_minus_one_exponents: Vec<usize>,
}

#[derive(Clone)]
pub struct IsPrimeInstance<F: Field + PrimeField> {
    prime: F,
}

#[derive(Clone)]
pub struct IsPrimeWitness<F: Field + PrimeField> {
    pratt_certificates: Vec<PrattCertificate<F>>,
}

#[derive(Clone)]
pub struct IsPrimeConstraintSynthesizer<F: Field + PrimeField> {
    instance: IsPrimeInstance<F>,
    witness: IsPrimeWitness<F>,
}

// NOTE: no hash, map, nor .contains() in r1cs so we have to search in vector like this
fn is_verified_prime<F: Field + PrimeField>(
    candidate: &FpVar<F>,
    verified_primes: &Vec<FpVar<F>>,
) -> Boolean<F> {
    let mut comparisons = Vec::with_capacity(verified_primes.len());
    for verified_prime in verified_primes {
        comparisons.push(verified_prime.is_eq(&candidate).unwrap());
    }
    Boolean::kary_or(&comparisons).unwrap()
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for IsPrimeConstraintSynthesizer<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // there should be more than zero certificates
        // certificates must be in increasing order
        // the last certificate should be for the instance
        let len_zero: Boolean<F> = Boolean::Constant(self.witness.pratt_certificates.len() < 1);
        len_zero.enforce_equal(&Boolean::FALSE).unwrap();

        let mut verified_primes: Vec<FpVar<F>> =
            vec![FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap()];

        // for all the certificates
        for certificate in self.witness.pratt_certificates.iter() {
            let prime_var = FpVar::<F>::new_witness(cs.clone(), || Ok(certificate.prime)).unwrap();
            let prime_minus_one_var =
                FpVar::<F>::new_witness(cs.clone(), || Ok(certificate.prime - F::one())).unwrap();
            let generator_var =
                FpVar::<F>::new_witness(cs.clone(), || Ok(certificate.generator)).unwrap();

            // for all the factors of p-1
            let mut product = FpVar::<F>::new_witness(cs.clone(), || Ok(F::one())).unwrap();
            for i in 0..certificate.prime_factors_p_minus_one.len() {
                let factor = certificate.prime_factors_p_minus_one[i];
                let exponent = certificate.prime_factors_p_minus_one_exponents[i];
                let exponent_var = UInt64::new_witness(cs.clone(), || Ok(exponent as u64)).unwrap();
                let factor_var = FpVar::<F>::new_witness(cs.clone(), || Ok(factor)).unwrap();
                let factor_inv_var = FpVar::<F>::new_witness(cs.clone(), || {
                    let inverse = factor
                        .inverse()
                        .ok_or(SynthesisError::AssignmentMissing)
                        .unwrap();
                    Ok(inverse)
                })
                .unwrap();

                let is_verified = is_verified_prime(&factor_var, &verified_primes);
                is_verified.enforce_equal(&Boolean::constant(true)).unwrap();

                // ensure g ^ ((p-1)/ qi) != 1 mod p for each factor qi of p-1
                // this proves that g is a primitive root, which can only occur if p is prime
                generator_var
                    .pow_le(
                        &(prime_minus_one_var.clone() * factor_inv_var)
                            .to_bits_le()
                            .unwrap(),
                    )
                    .unwrap()
                    .enforce_not_equal(&FpVar::<F>::Constant(F::one()))
                    .unwrap();

                // ensure product of all factors qi^ei = p-1
                product *= factor_var
                    .pow_le(&exponent_var.to_bits_le().unwrap())
                    .unwrap();
            }
            product.enforce_equal(&prime_minus_one_var).unwrap();

            verified_primes.push(prime_var.clone());
        }

        let instance_prime_var =
            FpVar::<F>::new_input(cs.clone(), || Ok(self.instance.prime)).unwrap();
        let last_cert_prime_var = verified_primes.last().unwrap();
        last_cert_prime_var
            .enforce_equal(&instance_prime_var)
            .unwrap();

        Ok(())
    }
}

pub struct IsPrimeRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
}

impl<F: Field + PrimeField> Relation<F> for IsPrimeRelation<F> {
    type Instance = IsPrimeInstance<F>;
    type Witness = IsPrimeWitness<F>;
    fn new(instance: Self::Instance, witness: Self::Witness) -> Self {
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<F> { instance, witness };
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

    use crate::relation::is_prime::PrattCertificate;
    use crate::relation::is_prime::{
        IsPrimeConstraintSynthesizer, IsPrimeInstance, IsPrimeRelation, IsPrimeWitness,
    };
    use crate::relation::Relation;

    // fn compute_generator<F: Field + PrimeField>(p: F, prime_factors: Vec<F>) -> Option<F> {
    //     // NOTE: this is incomplete sanity it doesn't check if the factors are prime
    //     let mut product = F::one();
    //     for factor in &prime_factors {
    //         product *= factor;
    //     }
    //     assert_eq!(p, product);

    //     // special case
    //     let two = F::from(2u64);
    //     if p == two {
    //         return Some(F::one());
    //     }

    //     // compute generator if exists
    //     let p_minus_1 = p - F::one();
    //     let mut candidate_g = two;
    //     while candidate_g <= p_minus_1 {
    //         let mut is_generator = true;
    //         for factor in &prime_factors {
    //             let exp = p_minus_1 / factor;
    //             let exp_big_int = exp.into_bigint();
    //             if candidate_g.pow(exp_big_int) == F::one() {
    //                 is_generator = false;
    //                 break;
    //             }
    //         }
    //         if is_generator {
    //             return Some(candidate_g);
    //         }
    //         candidate_g += F::one();
    //     }

    //     None
    // }
    // p = 13, then pc = [{13, 2, [2, 3], [2, 1]}]
    // p = 17, then pc = [{17, 3, [2], [4]}]
    #[test]
    fn witness_sanity_0() {
        // Example:
        // p = 0, then pc = [{0, 0, [], []}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(0u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
                pratt_certificates: vec![PrattCertificate {
                    prime: BLS12_381::from(0u64),
                    generator: BLS12_381::from(0u64),
                    prime_factors_p_minus_one: vec![],
                    prime_factors_p_minus_one_exponents: vec![],
                }],
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_1() {
        // Example:
        // p = 1, then pc = [{1, 1, [], []}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(1u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
                pratt_certificates: vec![PrattCertificate {
                    prime: BLS12_381::from(1u64),
                    generator: BLS12_381::from(1u64),
                    prime_factors_p_minus_one: vec![],
                    prime_factors_p_minus_one_exponents: vec![],
                }],
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_2() {
        // Example:
        // p = 1, then pc = [{2, 1, [], []}]
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(2u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
                pratt_certificates: vec![PrattCertificate {
                    prime: BLS12_381::from(2u64),
                    generator: BLS12_381::from(1u64),
                    prime_factors_p_minus_one: vec![],
                    prime_factors_p_minus_one_exponents: vec![],
                }],
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_3() {
        // Example:
        // p = 3, then pc = [{3, 2, [2], [1]}]
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(3u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
                pratt_certificates: vec![PrattCertificate {
                    prime: BLS12_381::from(3u64),
                    generator: BLS12_381::from(2u64),
                    prime_factors_p_minus_one: vec![BLS12_381::from(2u64)],
                    prime_factors_p_minus_one_exponents: vec![1],
                }],
            },
        };
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_293() {
        // Example:
        // p = 293, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}]
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(293u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
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
                        prime_factors_p_minus_one: vec![
                            BLS12_381::from(2u64),
                            BLS12_381::from(3u64),
                        ],
                        prime_factors_p_minus_one_exponents: vec![3, 2],
                    },
                    PrattCertificate {
                        prime: BLS12_381::from(293u64),
                        generator: BLS12_381::from(2u64),
                        prime_factors_p_minus_one: vec![
                            BLS12_381::from(2u64),
                            BLS12_381::from(73u64),
                        ],
                        prime_factors_p_minus_one_exponents: vec![2, 1],
                    },
                ],
            },
        };

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn witness_sanity_292() {
        // Example:
        // p = 292, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeConstraintSynthesizer::<BLS12_381> {
            instance: IsPrimeInstance::<BLS12_381> {
                prime: BLS12_381::from(292u64),
            },
            witness: IsPrimeWitness::<BLS12_381> {
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
                        prime_factors_p_minus_one: vec![
                            BLS12_381::from(2u64),
                            BLS12_381::from(3u64),
                        ],
                        prime_factors_p_minus_one_exponents: vec![3, 2],
                    },
                    PrattCertificate {
                        prime: BLS12_381::from(293u64),
                        generator: BLS12_381::from(2u64),
                        prime_factors_p_minus_one: vec![
                            BLS12_381::from(2u64),
                            BLS12_381::from(73u64),
                        ],
                        prime_factors_p_minus_one_exponents: vec![2, 1],
                    },
                ],
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
        // Example:
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
        let relation = IsPrimeRelation::<BLS12_381>::new(instance, witness);
        assert!(relation.verify());
    }
}

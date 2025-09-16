use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::{Boolean, ToBitsGadget},
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::relations::r1cs::is_prime::{instance::IsPrimeInstance, witness::IsPrimeWitness};

#[derive(Clone)]
pub struct IsPrimeSynthesizer<F: Field + PrimeField> {
    pub instance: IsPrimeInstance<F>,
    pub witness: IsPrimeWitness<F>,
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for IsPrimeSynthesizer<F> {
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

fn is_verified_prime<F: Field + PrimeField>(
    candidate: &FpVar<F>,
    verified_primes: &Vec<FpVar<F>>,
) -> Boolean<F> {
    let mut comparisons = Vec::with_capacity(verified_primes.len());
    // NOTE: this can be optimized --> we're just looking up if we processed this prime before
    for verified_prime in verified_primes {
        comparisons.push(verified_prime.is_eq(&candidate).unwrap());
    }
    Boolean::kary_or(&comparisons).unwrap()
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr as BLS12_381;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use ark_relations::r1cs::ConstraintSystem;

    use super::IsPrimeSynthesizer;
    use crate::relations::r1cs::is_prime::PrattCertificate;
    use crate::relations::r1cs::is_prime::{IsPrimeInstance, IsPrimeWitness};

    #[test]
    fn sanity_0() {
        // Example:
        // p = 0, then pc = [{0, 0, [], []}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_1() {
        // Example:
        // p = 1, then pc = [{1, 1, [], []}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_2() {
        // Example:
        // p = 1, then pc = [{2, 1, [], []}]
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_3() {
        // Example:
        // p = 3, then pc = [{3, 2, [2], [1]}]
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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
        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_293() {
        // Example:
        // p = 293, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}]
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }
    #[test]
    fn sanity_292() {
        // p = 292, then pc = [{3, 2, [2], [1]}, {73, 5, [2, 3], [3, 2]}, {293, 2, [2, 73], [2, 1]}] --> THIS SHOULD FAIL
        let constraint_synthesizer = IsPrimeSynthesizer::<BLS12_381> {
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

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref();
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap();
        assert!(!sanity_constraint_system.is_satisfied().unwrap());
    }
}

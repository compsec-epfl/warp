use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{convert::ToBitsGadget, fields::FieldVar,{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean}};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use crate::relation::Relation;

#[derive(Clone)]
pub struct IsPrimeInstance<F: Field + PrimeField> {
    prime: F,
}

#[derive(Clone)]
pub struct IsPrimeWitness<F: Field + PrimeField> {
    // btw this is a Pratt Certificate
    generator: F,
    q_factors: Vec<F>, // factors of p - 1
}

#[derive(Clone)]
pub struct IsPrimeConstraintSynthesizer<F: Field + PrimeField> {
    instance: IsPrimeInstance<F>,
    witness: IsPrimeWitness<F>,
}

impl<F: Field + PrimeField> ConstraintSynthesizer<F> for IsPrimeConstraintSynthesizer<F>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // public
        let prime_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.instance.prime))?;

        // private
        let generator_var = FpVar::<F>::new_witness(cs.clone(), || Ok(self.witness.generator))?;

        // === Compute (p - 1) ===
        let one = FpVar::<F>::Constant(F::one());
        let prime_minus_1 = &prime_var - &one;

        // === Check g^{p-1} ≡ 1 mod p ===
        let g_pow_pm1 = generator_var.pow_le(&prime_minus_1.to_bits_le().unwrap())?;
        g_pow_pm1.enforce_equal(&one)?; // constraint: g^{p-1} == 1

        // === For each q_i ∣ (p−1), check g^{(p−1)/q_i} ≠ 1 ===
        for q_opt in self.witness.q_factors.iter() {
            // Allocate q_i as witness
            let q_var = FpVar::<F>::new_witness(cs.clone(), || Ok(q_opt))?;

            // Compute (p−1)/q_i
            let divisor = q_var.inverse().unwrap_or(FpVar::<F>::Constant(F::zero()));
            // let divisor = FpVar::Constant(q_inv); // if q not invertible, constraint will fail

            let exp_var = &prime_minus_1 * divisor;

            // g^{(p−1)/q_i}
            let pow = generator_var.pow_le(&exp_var.to_bits_le().unwrap())?;

            // Enforce that g^{(p−1)/q_i} ≠ 1
            let is_eq = pow.is_eq(&one)?; // boolean
            is_eq.enforce_equal(&Boolean::FALSE)?; // constraint: g^{(p−1)/q_i} != 1
        }

        Ok(())
    }
}

pub struct IsPrimeRelation<F: Field + PrimeField> {
    constraint_system: ConstraintSystemRef<F>,
}

impl<F: Field + PrimeField> Relation<F> for IsPrimeRelation<F>
{
    type Instance = IsPrimeInstance<F>;
    type Witness = IsPrimeWitness<F>;
    fn new(instance: Self::Instance, witness: Self::Witness) -> Self {
        let constraint_synthesizer =
            IsPrimeConstraintSynthesizer::<F> { instance, witness };
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        Self {
            constraint_system,
        }
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
    use ark_std::marker::PhantomData;

    use crate::relation::is_prime::{IsPrimeConstraintSynthesizer, IsPrimeInstance, IsPrimeRelation, IsPrimeWitness};
    use crate::relation::Relation;

    #[test]
    fn witness_sanity() {
        // create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // commit to the tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // get root and proof
        let root = mt.root();
        let proof0 = mt.generate_proof(0).unwrap();

        //
        let constraint_synthesizer = MerkleInclusionConstraintSynthesizer::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            instance: MerkleInclusionInstance::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                leaf_hash_param,
                two_to_one_hash_param,
                root,
                leaf: leaf0,
                _config_gadget: PhantomData,
            },
            witness: MerkleInclusionWitness::<
                BLS12_381,
                PoseidonMerkleConfig<BLS12_381>,
                PoseidonMerkleConfigGadget<BLS12_381>,
            > {
                proof: proof0,
                _config_gadget: PhantomData,
            },
        };

        let sanity_constraint_system = ConstraintSystem::<BLS12_381>::new_ref(); // this is empty when instantiated
        constraint_synthesizer
            .generate_constraints(sanity_constraint_system.clone())
            .unwrap(); // now it has both constraints and witness
        assert!(sanity_constraint_system.is_satisfied().unwrap());
    }

    #[test]
    fn relation_sanity() {
        // Create some leaves
        let leaf0: Vec<BLS12_381> = vec![BLS12_381::from(1u64), BLS12_381::from(2u64)];
        let leaf1: Vec<BLS12_381> = vec![BLS12_381::from(3u64), BLS12_381::from(4u64)];
        let leaves: Vec<&[BLS12_381]> = vec![&leaf0, &leaf1];

        // Commit to the Merkle tree
        let leaf_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<BLS12_381> = poseidon_test_params();

        let mt = MerkleTree::<PoseidonMerkleConfig<BLS12_381>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            &leaves,
        )
        .unwrap();

        // Get root and proof
        let root = mt.root();
        let proof0 = mt.generate_proof(0).unwrap();

        // Construct the instance and witness
        let instance = MerkleInclusionInstance::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            leaf_hash_param,
            two_to_one_hash_param,
            root,
            leaf: leaf0,
            _config_gadget: PhantomData,
        };
        let witness = MerkleInclusionWitness::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        > {
            proof: proof0,
            _config_gadget: PhantomData,
        };

        // Create and verify the relation
        let relation = MerkleInclusionRelation::<
            BLS12_381,
            PoseidonMerkleConfig<BLS12_381>,
            PoseidonMerkleConfigGadget<BLS12_381>,
        >::new(instance, witness);

        assert!(relation.verify());
    }
}

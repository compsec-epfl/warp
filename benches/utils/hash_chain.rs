use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::{constraints::CRHGadget, CRH},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use rand::Rng;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Relation, ToPolySystem,
};

// utilities for the hashchain benchmark
pub fn get_hashchain_r1cs<F: PrimeField + Absorb>(
    poseidon_config: &PoseidonConfig<F>,
    hashchain_size: usize,
) -> R1CS<F> {
    HashChainRelation::<F, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hashchain_size,
    ))
    .unwrap()
}
pub fn get_hashchain_instance_witness_pairs<F: PrimeField + Absorb>(
    l: usize,
    poseidon_config: &PoseidonConfig<F>,
    hashchain_size: usize,
    mut rng: impl Rng,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    (0..l)
        .map(|_| {
            let preimage = vec![F::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<F, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hashchain_size,
                ),
            };
            let witness = HashChainWitness {
                preimage,
                _crhs_scheme: PhantomData::<CRH<F>>,
            };
            let relation = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hashchain_size),
            );
            (relation.x, relation.w)
        })
        .unzip()
}

use ark_bls12_381::Fr as BLS12_381;
use ark_crypto_primitives::crh::poseidon::constraints::CRHGadget;
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::marker::PhantomData;
use warp::accumulator::warp::{WARPConfig, WARP};
use warp::accumulator::AccumulationScheme;
use warp::domainsep::WARPDomainSeparator;
use warp::relations::r1cs::R1CS;
use whir::crypto::merkle_tree::blake3::Blake3MerkleTreeParams;

mod utils;
use spongefish::DomainSeparator;
use utils::poseidon;
use warp::linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig};
use warp::relations::r1cs::hashchain::{
    compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
};
use warp::relations::relation::{BundledPESAT, ToPolySystem};
use warp::relations::Relation;

pub fn bench_rs_warp(c: &mut Criterion) {
    let hash_chain_size = 160;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config.clone());

    let s = 8;
    let t = 7;
    for l in [32, 64, 128, 256, 512] {
        let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp = WARP::<
            BLS12_381,
            R1CS<BLS12_381>,
            _,
            Blake3MerkleTreeParams<BLS12_381>,
        >::new(
            warp_config.clone(), code.clone(), r1cs.clone(), (), ()
        );

        let instances_witnesses: (Vec<Vec<BLS12_381>>, Vec<Vec<BLS12_381>>) = (0..l)
            .map(|_| {
                let preimage = vec![BLS12_381::rand(&mut rng)];
                let instance = HashChainInstance {
                    digest: compute_hash_chain::<BLS12_381, CRH<_>>(
                        &poseidon_config,
                        &preimage,
                        hash_chain_size,
                    ),
                };
                let witness = HashChainWitness {
                    preimage,
                    _crhs_scheme: PhantomData::<CRH<BLS12_381>>,
                };
                let relation = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::new(
                    instance,
                    witness,
                    (poseidon_config.clone(), hash_chain_size),
                );
                (relation.x, relation.w)
            })
            .unzip();

        let mut group = c.benchmark_group("warp_rs_bls12_381_hash_chain");
        group.sample_size(10);

        group.bench_with_input(
            BenchmarkId::from_parameter(l),
            &instances_witnesses,
            |b, instance_witnesses| {
                b.iter_with_setup(
                    || {
                        let domainsep = DomainSeparator::new("bench::warp");
                        let domainsep =
                            WARPDomainSeparator::<
                                BLS12_381,
                                ReedSolomon<BLS12_381>,
                                Blake3MerkleTreeParams<BLS12_381>,
                            >::warp(domainsep, warp_config.clone());
                        let prover_state = domainsep.to_prover_state();
                        (prover_state, instance_witnesses.clone())
                    },
                    |(mut prover_state, x_w)| {
                        let ((acc_x, acc_w), pf) = hash_chain_warp
                            .prove(
                                (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                                &mut prover_state,
                                instances_witnesses.1.clone(),
                                instances_witnesses.0.clone(),
                                (vec![], vec![], vec![], (vec![], vec![]), vec![]),
                                (vec![], vec![], vec![]),
                            )
                            .unwrap();
                    },
                );
            },
        );
    }
}

criterion_group!(benches, bench_rs_warp);
criterion_main!(benches);

use std::sync::{Arc, Mutex};

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::reed_solomon::config::ReedSolomonConfig;
use ark_codes::reed_solomon::ReedSolomon;
use ark_codes::traits::LinearCode;
use ark_goldilocks::fields::fp::Fp as Field64;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::log2;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use utils::domainsep::init_domain_sep;
use utils::hash_chain::{get_hashchain_instance_witness_pairs, get_hashchain_r1cs};
use warp::config::WARPConfig;
use warp::crypto::merkle::blake3::Blake3MerkleTreeParams;
use warp::serialize::{AccInstanceSerializer, AccWitnessSerializer, ProofSerializer};
use warp::traits::AccumulationScheme;
use warp::WARP;

mod utils;
use utils::poseidon;
use warp::relations::BundledPESAT;

const HASHCHAIN_SIZE: usize = 600;

pub fn bench_rs_warp(c: &mut Criterion) {
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, HASHCHAIN_SIZE);

    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config.clone());
    let s = 8;
    let t = 7;

    for l in [32, 64, 128, 256, 512] {
        let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp = WARP::<_, _, _, Blake3MerkleTreeParams<_>>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            (),
            (),
        );

        let instances_witnesses =
            get_hashchain_instance_witness_pairs(l, &poseidon_config, HASHCHAIN_SIZE, &mut rng);

        let mut group = c.benchmark_group("warp_rs_bls12_381_hash_chain");
        group.sample_size(10);
        group.bench_with_input(
            BenchmarkId::from_parameter(l),
            &instances_witnesses,
            |b, instance_witnesses| {
                b.iter_with_setup(
                    || {
                        let domainsep = init_domain_sep::<
                            _,
                            ReedSolomon<_>,
                            Blake3MerkleTreeParams<BLS12_381>,
                            _,
                        >("warp::rs", warp_config.clone());
                        let prover_state = domainsep.to_prover_state();
                        (prover_state, instance_witnesses.clone())
                    },
                    |(mut prover_state, _x_w)| {
                        let _ = hash_chain_warp
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

pub fn bench_rs_warp_fields(c: &mut Criterion) {
    pub type F = Field64;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, HASHCHAIN_SIZE);

    let code_config = ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config.clone());
    let s = 2;
    let t = 130;

    for l in [32, 64, 128, 256, 512] {
        let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp = WARP::<_, _, _, Blake3MerkleTreeParams<_>>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            (),
            (),
        );

        let instances_witnesses =
            get_hashchain_instance_witness_pairs(l, &poseidon_config, HASHCHAIN_SIZE, &mut rng);

        let mut group = c.benchmark_group("warp_rs_f64_hash_chain");
        group.sample_size(10);
        group.bench_with_input(
            BenchmarkId::from_parameter(l),
            &instances_witnesses,
            |b, instance_witnesses| {
                b.iter_with_setup(
                    || {
                        let domainsep = init_domain_sep::<
                            _,
                            ReedSolomon<_>,
                            Blake3MerkleTreeParams<Field64>,
                            _,
                        >("warp::rs", warp_config.clone());
                        let prover_state = domainsep.to_prover_state();
                        (prover_state, instance_witnesses.clone())
                    },
                    |(mut prover_state, _x_w)| {
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

                        let acc_x_to_serde =
                            AccInstanceSerializer::<_, Blake3MerkleTreeParams<F>>::new(acc_x);
                        let acc_w_to_serde =
                            AccWitnessSerializer::<_, Blake3MerkleTreeParams<F>>::new(acc_w);
                        let proof_to_serde = ProofSerializer::new(pf);

                        println!("hash_chain_size: {}", HASHCHAIN_SIZE);
                        println!("queries: {}", s + t + 1);
                        println!("code_len: {}", code_config.code_length);
                        println!(
                            "acc_x size: {}",
                            acc_x_to_serde.serialized_size(Compress::Yes)
                        );
                        println!(
                            "acc_w size: {}",
                            acc_w_to_serde.serialized_size(Compress::Yes)
                        );
                        println!(
                            "proof size: {}",
                            proof_to_serde.serialized_size(Compress::Yes)
                        );
                        let narg_str = prover_state.narg_string();
                        println!("narg_str size: {}", narg_str.len());
                    },
                );
            },
        );
    }
}

pub fn bench_rs_warp_proof_sizes(c: &mut Criterion) {
    pub type F = Field64;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, HASHCHAIN_SIZE);

    let small_code = r1cs.k.next_power_of_two();
    let large_code = 2 * small_code;
    let small_confs = [
        (small_code, 2, 131),
        (small_code, 2, 148),
        (small_code, 2, 164),
        (small_code, 2, 211),
    ];
    let big_confs = [
        (large_code, 2, 48),
        (large_code, 2, 54),
        (large_code, 2, 61),
        (large_code, 2, 78),
    ];

    println!("HASHCHAIN_SIZE: {}", HASHCHAIN_SIZE);
    for conf in small_confs.into_iter().chain(big_confs) {
        let (code_size, s, t) = conf;

        let code_config = ReedSolomonConfig::<F>::default(r1cs.k, code_size);
        let code = ReedSolomon::new(code_config.clone());

        println!("====================================");
        println!("code_len: {}", code_config.code_length);
        println!("queries: {}", s + t);
        for l in [32, 64, 128, 256, 512] {
            let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());

            let hash_chain_warp = WARP::<_, _, _, Blake3MerkleTreeParams<_>>::new(
                warp_config.clone(),
                code.clone(),
                r1cs.clone(),
                (),
                (),
            );

            let instances_witnesses =
                get_hashchain_instance_witness_pairs(l, &poseidon_config, HASHCHAIN_SIZE, &mut rng);

            let domainsep = init_domain_sep::<_, ReedSolomon<_>, Blake3MerkleTreeParams<Field64>, _>(
                "warp::rs",
                warp_config.clone(),
            );
            let mut prover_state = domainsep.to_prover_state();
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

            let acc_x_to_serde = AccInstanceSerializer::<_, Blake3MerkleTreeParams<F>>::new(acc_x);
            let acc_w_to_serde = AccWitnessSerializer::<_, Blake3MerkleTreeParams<F>>::new(acc_w);
            let proof_to_serde = ProofSerializer::new(pf);

            println!("------------------------------------");
            println!("(x, w) size: {}", l);
            println!("k: {}", r1cs.k);

            println!("log l: {}", log2(l));
            println!("r1cs logM: {}", r1cs.log_m);
            println!(
                "acc_x size: {}",
                acc_x_to_serde.serialized_size(Compress::No)
            );
            println!(
                "acc_w size: {}",
                acc_w_to_serde.serialized_size(Compress::No)
            );
            println!(
                "proof size: {}",
                proof_to_serde.serialized_size(Compress::No)
            );
            let narg_str = prover_state.narg_string();
            println!("narg_str size: {}", narg_str.len());
            println!("------------------------------------")
        }
        println!("====================================");
    }
}

criterion_group!(benches, bench_rs_warp_proof_sizes);
criterion_main!(benches);

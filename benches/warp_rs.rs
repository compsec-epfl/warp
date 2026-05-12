use ark_codes::reed_solomon::config::ReedSolomonConfig;
use ark_codes::reed_solomon::ReedSolomon;
use ark_codes::traits::LinearCode;

use ark_mt::blake3::Blake3FieldHasher;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use utils::domainsep::init_prover_state;
use utils::hash_chain::{get_hashchain_instance_witness_pairs, get_hashchain_r1cs};
use warp::config::WARPConfig;
use warp::accumulation::AccumulationScheme;
use warp::warp::WARPProverKey;
use warp::WARP;

mod utils;
use utils::poseidon;
use warp::relations::BundledPESAT;
use warp::utils::fields::Goldilocks;

const HASHCHAIN_SIZE: usize = 800;

pub fn bench_rs_warp_fields(c: &mut Criterion) {
    pub type F = Goldilocks;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, HASHCHAIN_SIZE);

    let code_config = ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config.clone());
    let s = 2;
    let t = 125;

    for l in [32, 64, 128, 256, 512] {
        let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp = WARP::<_, _, _, Blake3FieldHasher<F>>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            Blake3FieldHasher::<F>::new(),
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
                        let prover_state = init_prover_state();
                        (prover_state, instance_witnesses.clone())
                    },
                    |(mut prover_state, _x_w)| {
                        let _ = hash_chain_warp
                            .prove(
                                WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
                                &mut prover_state,
                                instances_witnesses.1.clone(),
                                instances_witnesses.0.clone(),
                                warp::warp::AccumulatorInstance::empty(),
                                warp::warp::AccumulatorWitness::empty(),
                            )
                            .unwrap();
                    },
                );
            },
        );
    }
}

criterion_group!(benches, bench_rs_warp_fields);
criterion_main!(benches);

use ark_bls12_381::Fr as BLS12_381;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use utils::domainsep::init_domain_sep;
use utils::hash_chain::{get_hashchain_instance_witness_pairs, get_hashchain_r1cs};
use warp::accumulator::warp::config::WARPConfig;
use warp::accumulator::warp::WARP;
use warp::accumulator::AccumulationScheme;
use warp::merkle::blake3::Blake3MerkleTreeParams;

mod utils;
use utils::poseidon;
use warp::linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig};
use warp::relations::BundledPESAT;

const HASHCHAIN_SIZE: usize = 1600;

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

criterion_group!(benches, bench_rs_warp);
criterion_main!(benches);

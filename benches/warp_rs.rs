use ark_codes::reed_solomon::config::ReedSolomonConfig;
use ark_codes::reed_solomon::ReedSolomon;
use ark_codes::traits::LinearCode;

use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};
use ark_std::rand::thread_rng;
use ark_vc::mvc::MultiVectorCommitment;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use utils::domainsep::init_prover_state;
use utils::hash_chain::{get_hashchain_instance_witness_pairs, get_hashchain_r1cs};
use warp::config::WarpConfig;
use warp::{WarpAccumulationScheme, WarpProverKey};

mod utils;
use utils::poseidon;
use warp::utils::fields::Goldilocks;

const HASHCHAIN_SIZE: usize = 800;

pub fn bench_rs_warp_fields(c: &mut Criterion) {
    pub type F = Goldilocks;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, HASHCHAIN_SIZE);

    let code_config = ReedSolomonConfig::<F>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    );
    let code = ReedSolomon::new(code_config.clone());
    let s = 2;
    let t = 125;

    type V = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

    for l in [32, 64, 128, 256, 512] {
        let warp_config = WarpConfig::new(l, 0, s, t);

        let pp = <V as MultiVectorCommitment>::setup_multiple(0, code.code_len(), t, &mut rng)
            .expect("setup_multiple");
        let (ck, vk) = <V as MultiVectorCommitment>::trim_multiple(&pp, 0, code.code_len(), t)
            .expect("trim_multiple");
        let hash_chain_warp = WarpAccumulationScheme::<_, _, _, V>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            ck,
            vk,
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
                                WarpProverKey {
                                    index: r1cs.clone(),
                                    m_num_constraints: r1cs.m_num_constraints,
                                    n_num_variables: r1cs.n_num_variables,
                                    k_num_witness_vars: r1cs.k_num_witness_vars,
                                },
                                &mut prover_state,
                                instances_witnesses.1.clone(),
                                instances_witnesses.0.clone(),
                                warp::AccumulatorInstance::empty(),
                                warp::AccumulatorWitness::empty(),
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

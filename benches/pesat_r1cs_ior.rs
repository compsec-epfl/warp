use ark_bls12_381::Fr as BLS12_381;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

mod utils;
use utils::domain_sep::initialize_pesat_ior_domain_separator;
use utils::merkle::generate_merkle_instance_witness_pair;
use utils::{codes::TwinConstraintRS, merkle, poseidon};
use warp::iors::pesat::r1cs::twin_constraint::R1CSTwinConstraintIOR;
use warp::iors::{IORConfig, IOR};
use warp::linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig};
use warp::merkle::poseidon::PoseidonMerkleConfig;
use warp::relations::r1cs::MerkleInclusionRelation;
use warp::relations::relation::ToPolySystem;

pub fn bench_rs_pesat_r1cs_ior(c: &mut Criterion) {
    const TREE_HEIGHT: usize = 15;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let (mt_config, leaves, mt) =
        merkle::initialize_merkle_tree(TREE_HEIGHT, poseidon_config, &mut rng);
    let r1cs = MerkleInclusionRelation::into_r1cs(&mt_config).unwrap();
    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config);
    let log_m = r1cs.log_m;

    // initialize IOR
    let ior_config: IORConfig<BLS12_381, ReedSolomon<BLS12_381>, PoseidonMerkleConfig<BLS12_381>> =
        IORConfig::new(
            code,
            mt_config.leaf_hash_param.clone(),
            mt_config.two_to_one_hash_param.clone(),
        );

    for l in [2, 32, 64, 128, 256, 512] {
        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS<BLS12_381>, _>::new(
            r1cs.clone(),
            &ior_config,
            l,
        );

        let instances_witnesses: (Vec<Vec<BLS12_381>>, Vec<Vec<BLS12_381>>) = (0..l)
            .map(|index| {
                generate_merkle_instance_witness_pair(
                    &mt_config,
                    &mt,
                    index,
                    leaves.get(index).unwrap(),
                )
            })
            .unzip();

        let mut group = c.benchmark_group("pesat_ior_rs_r1cs_bls12_381");
        group.sample_size(10);

        group.bench_with_input(
            BenchmarkId::from_parameter(l),
            &instances_witnesses,
            |b, instance_witnesses| {
                b.iter_with_setup(
                    || {
                        let domain_separator = initialize_pesat_ior_domain_separator::<
                            BLS12_381,
                            poseidon::Permutation<BLS12_381>,
                        >(l, log_m);
                        let prover_state = domain_separator.to_prover_state();
                        (prover_state, instance_witnesses.clone())
                    },
                    |(mut prover_state, x_w)| {
                        r1cs_twinrs_ior
                            .prove(&mut prover_state, x_w.0, x_w.1)
                            .unwrap();
                    },
                );
            },
        );
    }

    // intialize prover state
}

criterion_group!(benches, bench_rs_pesat_r1cs_ior);
criterion_main!(benches);

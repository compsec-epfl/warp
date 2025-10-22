use ark_bls12_381::Fr as BLS12_381;
use ark_crypto_primitives::crh::poseidon::constraints::CRHGadget;
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_ff::UniformRand;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::marker::PhantomData;
use warp::domainsep::WARPDomainSeparator;
use whir::crypto::merkle_tree::blake3::Blake3MerkleTreeParams;

mod utils;
use spongefish::DomainSeparator;
use utils::{codes::TwinConstraintRS, poseidon};
use warp::iors::pesat::r1cs::twin_constraint::R1CSTwinConstraintIOR;
use warp::iors::pesat::TwinConstraintIORConfig;
use warp::iors::IOR;
use warp::linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig};
use warp::relations::r1cs::hashchain::{
    compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
};
use warp::relations::relation::ToPolySystem;
use warp::relations::Relation;

pub fn bench_rs_pesat_r1cs_ior_hashchain(c: &mut Criterion) {
    let hash_chain_size = 160;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let log_m = r1cs.log_m;
    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());

    let code = ReedSolomon::new(code_config.clone());

    // initialize IOR

    for l in [32, 64, 128, 256, 512] {
        let ior_config = TwinConstraintIORConfig::<_, _, Blake3MerkleTreeParams<BLS12_381>>::new(
            code.clone(),
            code_config.clone(),
            (),
            (),
            l,
            log_m,
        );

        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS<BLS12_381>, _>::new(
            r1cs.clone(),
            ior_config,
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

        let mut group = c.benchmark_group("pesat_ior_rs_r1cs_bls12_381_hash_chain");
        group.sample_size(10);

        group.bench_with_input(
            BenchmarkId::from_parameter(l),
            &instances_witnesses,
            |b, instance_witnesses| {
                b.iter_with_setup(
                    || {
                        let domainsep = DomainSeparator::new("bench::ior");
                        let domainsep = domainsep.pesat_ior(&r1cs_twinrs_ior.config);
                        let prover_state = domainsep.to_prover_state();
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
}

criterion_group!(benches, bench_rs_pesat_r1cs_ior_hashchain);
criterion_main!(benches);

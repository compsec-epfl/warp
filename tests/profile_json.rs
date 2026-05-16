//! End-to-end check that the profile JSON layer emits well-formed
//! `warp.profile.v1` records. Runs only under `--features profile`.

#![cfg(feature = "profile")]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_ff::UniformRand;
use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};
use ark_std::rand::thread_rng;
use ark_vc::{mvc::MultiVectorCommitment, vc::VectorCommitment};

use warp::config::WarpConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Arithmetize, Relation,
};
use warp::utils::poseidon;
use warp::{
    AccumulatorInstance, AccumulatorWitness, WarpAccumulationScheme, WarpProverKey,
};

type MerkleVc<F> = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn json_layer_emits_phase_records() {
    let sink = SharedBuf(Arc::new(Mutex::new(Vec::new())));
    let installed = warp::profile::init_json(sink.clone());
    assert!(installed);

    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code = ReedSolomon::new(ReedSolomonConfig::<BLS12_381>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    ));

    let (instances, witnesses): (Vec<_>, Vec<_>) = (0..l1)
        .map(|_| {
            let preimage = vec![BLS12_381::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<BLS12_381, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hash_chain_size,
                ),
            };
            let witness = HashChainWitness::<BLS12_381, CRH<BLS12_381>>::new(preimage);
            let relation = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    let warp_config = WarpConfig::new(l1, 0, s, t);
    let pp = <MerkleVc<BLS12_381> as MultiVectorCommitment>::setup_multiple(
        0,
        code.code_len(),
        t,
        &mut rng,
    )
    .expect("setup_multiple");
    let (ck, vk) = <MerkleVc<BLS12_381> as MultiVectorCommitment>::trim_multiple(
        &pp,
        0,
        code.code_len(),
        t,
    )
    .expect("trim_multiple");
    let warp = WarpAccumulationScheme::<BLS12_381, R1CS<BLS12_381>, _, MerkleVc<BLS12_381>>::new(
        warp_config,
        code,
        r1cs.clone(),
        ck,
        vk,
    );

    let domainsep = spongefish::domain_separator!("test::profile_json");
    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();

    warp.prove(
        WarpProverKey {
            index: r1cs.clone(),
            m_num_constraints: r1cs.m_num_constraints,
            n_num_variables: r1cs.n_num_variables,
            k_num_witness_vars: r1cs.k_num_witness_vars,
        },
        &mut prover_state,
        witnesses,
        instances,
        AccumulatorInstance::empty(),
        AccumulatorWitness::empty(),
    )
    .unwrap();

    let bytes = sink.0.lock().unwrap().clone();
    let text = String::from_utf8(bytes).expect("JSON output is UTF-8");
    assert!(!text.is_empty());

    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty());

    for (i, line) in lines.iter().enumerate() {
        assert!(line.contains(r#""schema":"warp.profile.v1""#), "line {i}: {line}");
        assert!(line.contains(r#""wall_ns""#), "line {i}: {line}");
        assert!(line.contains(r#""counters""#), "line {i}: {line}");
        assert!(line.contains(r#""dimensions""#), "line {i}: {line}");
    }

    for phase in ["warp.prove", "pesat", "twin_constraint", "ood", "batching", "proximity"] {
        let needle = format!(r#""phase":"{phase}""#);
        assert!(text.contains(&needle), "missing phase `{phase}`");
    }

    assert!(text.contains(r#""merkle_tree_builds":"#));
    assert!(text.contains(r#""encode_calls":"#));
}

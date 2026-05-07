//! End-to-end check that Plan O's JSON layer emits well-formed
//! `warp.profile.v1` records with phase names, dimensions, and non-zero
//! op counters.
//!
//! Runs only under `--features profile` (see the `cfg` below). Without
//! the feature there's no JSON layer to test.

#![cfg(feature = "profile")]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_mt::blake3::Blake3FieldHasher;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use std::marker::PhantomData;

use warp::config::WARPConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    BundledPESAT, Relation, ToPolySystem,
};
use warp::traits::AccumulationScheme;
use warp::types::{AccumulatorInstance, AccumulatorWitness, WARPProverKey};
use warp::utils::poseidon;
use warp::WARP;

/// `Arc<Mutex<Vec<u8>>>` wrapped so it implements `io::Write`.
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
    assert!(
        installed,
        "json subscriber install should succeed on first call"
    );

    // Minimum viable prove run — same shape as the top-level warp_test.
    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config.clone());

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

    let warp_config = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
    let hash_chain_warp = WARP::<BLS12_381, R1CS<BLS12_381>, _, Blake3FieldHasher<BLS12_381>>::new(
        warp_config,
        code,
        r1cs.clone(),
        Blake3FieldHasher::<BLS12_381>::new(),
    );

    let domainsep = spongefish::domain_separator!("test::profile_json");
    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();

    hash_chain_warp
        .prove(
            WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
            &mut prover_state,
            witnesses,
            instances,
            AccumulatorInstance::empty(),
            AccumulatorWitness::empty(),
        )
        .unwrap();

    // Inspect collected records.
    let bytes = sink.0.lock().unwrap().clone();
    let text = String::from_utf8(bytes).expect("JSON output is UTF-8");
    assert!(
        !text.is_empty(),
        "JSON sink should contain at least one record"
    );

    let lines: Vec<&str> = text.lines().collect();
    assert!(
        !lines.is_empty(),
        "expected newline-delimited JSON, got: {text:?}"
    );

    // Every line is a record carrying the schema tag.
    for (i, line) in lines.iter().enumerate() {
        assert!(
            line.contains(r#""schema":"warp.profile.v1""#),
            "line {i} missing schema: {line}"
        );
        assert!(
            line.contains(r#""wall_ns""#),
            "line {i} missing wall_ns: {line}"
        );
        assert!(
            line.contains(r#""counters""#),
            "line {i} missing counters: {line}"
        );
        assert!(
            line.contains(r#""dimensions""#),
            "line {i} missing dimensions: {line}"
        );
    }

    // Every top-level phase must appear at least once.
    for phase in [
        "warp.prove",
        "pesat",
        "twin_constraint",
        "ood",
        "batching",
        "proximity",
    ] {
        let needle = format!(r#""phase":"{phase}""#);
        assert!(
            text.contains(&needle),
            "expected a record for phase `{phase}`, got lines: {lines:#?}"
        );
    }

    // At least one record must have non-empty counters (pesat bumps several).
    assert!(
        text.contains(r#""merkle_tree_builds":"#),
        "expected merkle_tree_builds counter in output: {text}"
    );
    assert!(
        text.contains(r#""encode_calls":"#),
        "expected encode_calls counter in output: {text}"
    );
}

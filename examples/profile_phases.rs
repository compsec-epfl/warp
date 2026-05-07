//! Per-phase wall-time profile of a Goldilocks WARP prove run — used to
//! report the micro-profile table after the rewrite-v2 effsc integration.
//! See the original shape in the PR #22 body.
//!
//! Run:
//! ```text
//! cargo run --release --features profile --example profile_phases
//! ```
//!
//! The `profile` feature installs the JSON layer from `warp::profile::init_json`.
//! This binary captures the emitted records, aggregates wall_ns per phase
//! over a handful of prove invocations, and prints a markdown table that
//! mirrors the PR #22 breakdown (rs_encode, pesat_merkle_tree,
//! twin_constraint_sumcheck, etc.).
//!
//! Best run with `RAYON_NUM_THREADS` pinned and all other workloads off.

#[cfg(not(feature = "profile"))]
fn main() {
    eprintln!(
        "profile_phases: build with --features profile (and preferably --release).\n\
         example: cargo run --release --features profile --example profile_phases"
    );
}

#[cfg(feature = "profile")]
fn main() {
    inner::run();
}

#[cfg(feature = "profile")]
mod inner {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use ark_codes::reed_solomon::config::ReedSolomonConfig;
    use ark_codes::reed_solomon::ReedSolomon;
    use ark_codes::traits::LinearCode;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_crypto_primitives::merkle_tree::configs::Blake3MerkleConfig;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    use warp::config::WARPConfig;
    use warp::relations::{
        r1cs::{
            hashchain::{
                compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
            },
            R1CS,
        },
        BundledPESAT, Relation, ToPolySystem,
    };
    use warp::traits::AccumulationScheme;
    use warp::types::{AccumulatorInstance, AccumulatorWitness, WARPProverKey};
    use warp::utils::fields::Goldilocks;
    use warp::utils::poseidon;
    use warp::WARP;

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

    pub fn run() {
        let iters = std::env::var("WARP_PROFILE_ITERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5);
        let hash_chain_size = std::env::var("WARP_PROFILE_HCSIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(10);
        let warmup = 2usize;

        let sink = SharedBuf(Arc::new(Mutex::new(Vec::new())));
        let installed = warp::profile::init_json(sink.clone());
        assert!(installed, "failed to install JSON profile subscriber");

        let l1 = 4;
        let s = 8;
        let t = 7;
        let mut rng = thread_rng();
        let poseidon_config = poseidon::initialize_poseidon_config::<Goldilocks>();
        let r1cs = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::into_r1cs(&(
            poseidon_config.clone(),
            hash_chain_size,
        ))
        .unwrap();
        let code_config =
            ReedSolomonConfig::<Goldilocks>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config);
        let n = code.code_len();

        let (instances, witnesses): (Vec<_>, Vec<_>) = (0..l1)
            .map(|_| {
                let preimage = vec![Goldilocks::rand(&mut rng)];
                let instance = HashChainInstance {
                    digest: compute_hash_chain::<Goldilocks, CRH<_>>(
                        &poseidon_config,
                        &preimage,
                        hash_chain_size,
                    ),
                };
                let witness = HashChainWitness::<Goldilocks, CRH<Goldilocks>>::new(preimage);
                let relation = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::new(
                    instance,
                    witness,
                    (poseidon_config.clone(), hash_chain_size),
                );
                (relation.x, relation.w)
            })
            .unzip();

        let warp_config = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
        let prover = WARP::<Goldilocks, R1CS<Goldilocks>, _, Blake3MerkleConfig<Goldilocks>>::new(
            warp_config,
            code.clone(),
            r1cs.clone(),
            (),
            (),
        );

        println!(
            "=== warp profile (Goldilocks hashchain) — n={n}, l1={l1}, s={s}, t={t}, hashchain_size={hash_chain_size}, iters={iters} (+ {warmup} warmup)"
        );

        for i in 0..(warmup + iters) {
            let domainsep = spongefish::domain_separator!("profile_phases");
            let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
            if i == warmup {
                sink.0.lock().unwrap().clear();
            }
            prover
                .prove(
                    WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
                    &mut prover_state,
                    witnesses.clone(),
                    instances.clone(),
                    AccumulatorInstance::empty(),
                    AccumulatorWitness::empty(),
                )
                .unwrap();
        }

        let bytes = sink.0.lock().unwrap().clone();
        let text = String::from_utf8(bytes).expect("JSON output is UTF-8");

        let rows: &[(&str, &str)] = &[
            ("pesat.encode", "rs_encode (FFT)"),
            ("pesat.merkle_commit", "pesat_merkle_tree"),
            ("twin_constraint.sumcheck", "twin_constraint_sumcheck"),
            ("warp.commit_new_oracle", "merkle_commit"),
            ("batching.eq_evals", "eq_poly_evals + ood_evals_vec"),
            ("batching.sumcheck", "batching_sumcheck (inner product)"),
            ("warp.prove", "end-to-end prover"),
        ];

        let mut series: std::collections::BTreeMap<&str, Vec<u64>> =
            std::collections::BTreeMap::new();
        for line in text.lines() {
            for (phase, _) in rows.iter() {
                let needle = format!("\"phase\":\"{phase}\"");
                if line.contains(&needle) {
                    if let Some(w) = extract_u64(line, "\"wall_ns\":") {
                        series.entry(*phase).or_default().push(w);
                    }
                    break;
                }
            }
        }

        println!();
        println!("| Phase | n | mean (ms) | min (ms) | samples |");
        println!("|-------|---|-----------|----------|---------|");
        for (phase, label) in rows {
            let vs = series.remove(*phase).unwrap_or_default();
            if vs.is_empty() {
                println!("| {label} | {n} | n/a | n/a | 0 |");
                continue;
            }
            let sum_ns: u128 = vs.iter().map(|&v| v as u128).sum();
            let mean_ms = (sum_ns as f64 / vs.len() as f64) / 1e6;
            let min_ms = *vs.iter().min().unwrap() as f64 / 1e6;
            println!(
                "| {label} | {n} | {mean_ms:.3} | {min_ms:.3} | {} |",
                vs.len()
            );
        }
    }

    fn extract_u64(line: &str, key: &str) -> Option<u64> {
        let i = line.find(key)? + key.len();
        let rest = &line[i..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

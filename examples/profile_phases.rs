//! Per-phase wall-time profile of a Goldilocks WARP prove run. Drives the
//! `phase!` instrumentation inside `prove()` behind the `profile` feature.
//!
//! Run:
//! ```text
//! cargo run --release --features profile --example profile_phases
//! ```
//!
//! The prover is called `WARP_PROFILE_ITERS` times (+ a warmup), per-phase
//! durations are aggregated, and the output is a markdown table suitable for
//! pasting into a PR description. Match the phase set from the
//! `constrained_code_accumulate` rollup in the PR comment shape.

#[cfg(not(feature = "profile"))]
fn main() {
    eprintln!(
        "profile_phases: build with --features profile (and --release).\n\
         example: cargo run --release --features profile --example profile_phases"
    );
}

#[cfg(feature = "profile")]
fn main() {
    inner::run();
}

#[cfg(feature = "profile")]
mod inner {
    use std::collections::BTreeMap;
    use std::marker::PhantomData;
    use std::time::Duration;

    use ark_codes::reed_solomon::{config::ReedSolomonConfig, ReedSolomon};
    use ark_codes::traits::LinearCode;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;

    use warp::config::WARPConfig;
    use warp::crypto::merkle::blake3::Blake3MerkleTreeParams;
    use warp::relations::r1cs::hashchain::{
        compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
    };
    use warp::relations::r1cs::R1CS;
    use warp::relations::{BundledPESAT, Relation, ToPolySystem};
    use warp::traits::AccumulationScheme;
    use warp::utils::fields::Goldilocks;
    use warp::utils::poseidon;
    use warp::WARP;

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
                let witness = HashChainWitness {
                    preimage,
                    _crhs_scheme: PhantomData::<CRH<Goldilocks>>,
                };
                let relation = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::new(
                    instance,
                    witness,
                    (poseidon_config.clone(), hash_chain_size),
                );
                (relation.x, relation.w)
            })
            .unzip();

        let warp_config = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
        let prover =
            WARP::<Goldilocks, R1CS<Goldilocks>, _, Blake3MerkleTreeParams<Goldilocks>>::new(
                warp_config,
                code.clone(),
                r1cs.clone(),
                (),
                (),
            );

        println!(
            "=== warp profile (Goldilocks hashchain) — n={n}, l1={l1}, s={s}, t={t}, hashchain_size={hash_chain_size}, iters={iters} (+ {warmup} warmup)"
        );

        // Aggregated timings: phase name -> samples (one per iter), always
        // taken as the TOTAL duration for that phase in that iter.
        let mut series: BTreeMap<&'static str, Vec<Duration>> = BTreeMap::new();

        for i in 0..(warmup + iters) {
            let ds = spongefish::domain_separator!("profile_phases");
            let mut ps = ds.without_session().instance(&0u32).std_prover();

            warp::profile::reset();

            prover
                .prove(
                    (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                    &mut ps,
                    witnesses.clone(),
                    instances.clone(),
                    (vec![], vec![], vec![], (vec![], vec![]), vec![]),
                    (vec![], vec![], vec![]),
                )
                .unwrap();

            if i < warmup {
                continue;
            }

            // Collapse duplicate phase entries within this iter (e.g. if a
            // phase fires more than once we want the sum).
            let mut per_iter: BTreeMap<&'static str, Duration> = BTreeMap::new();
            for (name, dur) in warp::profile::drain() {
                *per_iter.entry(name).or_default() += dur;
            }
            for (name, dur) in per_iter {
                series.entry(name).or_default().push(dur);
            }
        }

        // Phases in PR-shape order + which rollups they belong to.
        let phases: &[(&str, &str)] = &[
            ("rs_encode", "rs_encode (FFT)"),
            ("pesat_merkle_tree", "pesat_merkle_tree"),
            ("twin_constraint_sumcheck", "**twin_constraint_sumcheck**"),
            ("eval_bundled_r1cs", "eval_bundled_r1cs"),
            ("merkle_commit", "merkle_commit"),
            (
                "eq_poly_evals_and_ood_evals_vec",
                "eq_poly_evals + ood_evals_vec",
            ),
            ("batching_sumcheck", "batching_sumcheck (inner product)"),
        ];
        let mean_ms = |samples: &[Duration]| -> Option<f64> {
            if samples.is_empty() {
                return None;
            }
            let sum_ns: u128 = samples.iter().map(|d| d.as_nanos()).sum();
            Some((sum_ns as f64 / samples.len() as f64) / 1e6)
        };

        println!();
        println!("| Phase | Mean (ms) |");
        println!("|-------|-----------|");
        for (key, label) in phases {
            let samples = series.get(*key).cloned().unwrap_or_default();
            match mean_ms(&samples) {
                Some(m) => println!("| {label} | {m:.2} |"),
                None => println!("| {label} | n/a |"),
            }
        }

        // Rollups: real wall-time around `pesat_reduce` and
        // `constrained_code_accumulate`, recorded as whole-block phases
        // inside `prove()`. `prove_total` is the full wall time.
        let cca = series
            .get("constrained_code_accumulate")
            .cloned()
            .unwrap_or_default();
        let total = series.get("prove_total").cloned().unwrap_or_default();

        println!();
        if let Some(m) = mean_ms(&cca) {
            println!("| **Total (constrained_code_accumulate)** | **{m:.2} ms** |");
        }
        if let Some(m) = mean_ms(&total) {
            println!("| **Total (incl. pesat_reduce)** | **{m:.2} ms** |");
        }
    }
}

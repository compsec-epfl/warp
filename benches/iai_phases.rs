//! iai-callgrind benchmarks measuring deterministic instruction counts
//! per prove call at fixed parameter points.
//!
//! Unlike [`benches/warp_rs.rs`] (criterion, wall time), these numbers
//! are reproducible across machines: callgrind counts executed
//! instructions, not time. A 1% change is real signal.
//!
//! Runs under valgrind. On macOS valgrind is not available natively —
//! use `make bench-ci-local` which invokes Docker (see benches/README.md).
//!
//! Installation:
//!   cargo install iai-callgrind-runner --version 0.14.0
//! then
//!   cargo bench --bench iai_phases
//!
//! **v1 scope**: one size (l1=4, hashchain=10). Setup (encoding,
//! poseidon config build, instance gen) is measured inside the bench
//! because plumbing the `setup = expr` attribute through
//! parameterised `#[bench::...]` cases didn't resolve cleanly on
//! iai-callgrind 0.14 — the macro failed to see the target function
//! from the bench-crate root. Revisit when adding more parameter
//! points; a working pattern is either the non-parameterised form
//! below, or `iai_callgrind::BinaryBenchmarkConfig`.

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_std::rand::thread_rng;

use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};
use warp::config::WARPConfig;
use warp::relations::BundledPESAT;
use warp::traits::AccumulationScheme as _;
use warp::types::{AccumulatorInstance, AccumulatorWitness};
use warp::WARP;

mod utils;
use utils::domainsep::init_prover_state;
use utils::hash_chain::{get_hashchain_instance_witness_pairs, get_hashchain_r1cs};
use utils::poseidon;

type F = BLS12_381;

/// Output of [`setup_prove`]: everything needed to call `warp.prove` once,
/// assembled in setup time (NOT counted in the measurement).
struct ProveInputs {
    warp: WARP<F, warp::relations::r1cs::R1CS<F>, ReedSolomon<F>>,
    pk: (warp::relations::r1cs::R1CS<F>, usize, usize, usize),
    prover_state: spongefish::ProverState,
    instances: Vec<Vec<F>>,
    witnesses: Vec<Vec<F>>,
}

fn setup_prove(l: usize, s: usize, t: usize, hashchain_size: usize) -> ProveInputs {
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = get_hashchain_r1cs(&poseidon_config, hashchain_size);

    let code_config = ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two());
    let code = ReedSolomon::new(code_config);

    let warp_config = WARPConfig::new(l, l, s, t, r1cs.config(), code.code_len());
    let warp = WARP::<F, _, _>::new(warp_config, code, r1cs.clone());

    let (instances, witnesses) =
        get_hashchain_instance_witness_pairs(l, &poseidon_config, hashchain_size, &mut rng);

    ProveInputs {
        warp,
        pk: (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
        prover_state: init_prover_state(),
        instances,
        witnesses,
    }
}

fn run_prove(mut inputs: ProveInputs) {
    black_box(
        inputs
            .warp
            .prove(
                inputs.pk,
                &mut inputs.prover_state,
                inputs.witnesses,
                inputs.instances,
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap(),
    );
}

// Smallest configuration — matches the unit-test shape (l1=4, hashchain=10).
#[library_benchmark]
fn bench_prove_small() {
    let inputs = setup_prove(4, 2, 7, 10);
    run_prove(black_box(inputs));
}

library_benchmark_group!(
    name = prove_benches;
    benchmarks = bench_prove_small
);

main!(library_benchmark_groups = prove_benches);

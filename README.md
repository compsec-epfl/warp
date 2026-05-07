🌀 WARP 🌀

Implementation repo for [WARP](https://eprint.iacr.org/2025/753) — an
accumulation scheme over R1CS with code-based commitments.

## Status

Research artifact. Reproduces the protocol from the paper. Not packaged
for crates.io (depends on git branches of `ark-vc`, `ark-codes`, and
`effsc`).

## Quick start

```rust
use warp::prelude::*;
use warp::utils::poseidon;
use warp::relations::{r1cs::{R1CS, hashchain::HashChainRelation}, BundledPESAT, ToPolySystem};
use ark_codes::{reed_solomon::{ReedSolomon, config::ReedSolomonConfig}, traits::LinearCode};
use ark_crypto_primitives::crh::poseidon::{CRH, constraints::CRHGadget};
use ark_mt::blake3::Blake3FieldHasher;
use ark_bls12_381::Fr as F;

// 1. Build the relation (here: a hash chain of length 10).
let poseidon = poseidon::initialize_poseidon_config::<F>();
let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::into_r1cs(&(poseidon, 10))?;

// 2. Pick a code and a hasher.
let code = ReedSolomon::new(ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two()));
let hasher = Blake3FieldHasher::<F>::new();

// 3. Configure WARP and instantiate.
//    `l1` = fresh-instance batch size, `l` = total accumulator capacity, `s`/`t` = OOD/shift queries.
let cfg = WARPConfig::new(/*l1*/ 4, /*l*/ 4, /*s*/ 8, /*t*/ 7, r1cs.config(), code.code_len());
let warp = WARP::new(cfg, code, r1cs.clone(), hasher);

// 4. Fold a stream of fresh (instance, witness) batches into the accumulator.
let mut acc_x = AccumulatorInstance::empty();
let mut acc_w = AccumulatorWitness::empty();
let pk = WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k };
for batch in batches {
    let mut prover_state = /* spongefish prover state */;
    let ((new_x, new_w), _proof) = warp.prove(
        pk.clone(), &mut prover_state, batch.witnesses, batch.instances,
        AccumulatorInstance::empty(), AccumulatorWitness::empty(),
    )?;
    acc_x = acc_x.extend(new_x);
    acc_w = acc_w.extend(new_w);
}

// 5. Final decide (the only non-succinct step — wrap in a SNARK if you need succinctness).
warp.decide(acc_w, acc_x)?;
```

The `examples/profile_phases.rs` runs the full pipeline and prints a
per-phase wall-time breakdown when built with `--features profile`.

## Layout

- `src/lib.rs` — `WARP::{prove, verify, decide}` orchestrator
- `src/protocol/phases/` — IOR phases (`pesat`, `twin_constraint`, `ood`, `batching`, `proximity`)
- `src/relations/` — `R1CS`, `BundledPESAT`, `HashChainRelation`
- `src/crypto/`, `src/utils/` — Merkle wrapper, field/poly helpers
- `src/profile/` — opt-in tracing layer (gated behind the `profile` feature)
- `tests/integration_warp.rs` — end-to-end on BLS12-381 and Goldilocks
- `tests/verifier_negative.rs` — single-tamper rejection tests

## Running tests / benches

```sh
cargo test --release
cargo bench
cargo run --release --features profile --example profile_phases
```

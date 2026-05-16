🌀 WARP 🌀

Implementation repo for [WARP](https://eprint.iacr.org/2025/753) — an
accumulation scheme with code-based commitments.

## Status

Ongoing research.

## Quick start

```rust
use warp::{
    AccumulatorInstance, AccumulatorWitness, WarpAccumulationScheme, WarpConfig,
    WarpProverKey,
};
use warp::relations::{Arithmetize, r1cs::{R1CS, hashchain::HashChainRelation}};
use warp::utils::poseidon;
use ark_codes::{reed_solomon::{ReedSolomon, config::ReedSolomonConfig}, traits::LinearCode};
use ark_crypto_primitives::crh::poseidon::{CRH, constraints::CRHGadget};
use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};
use ark_vc::{mvc::MultiVectorCommitment, vc::VectorCommitment};
use ark_bls12_381::Fr as F;
use ark_std::rand::thread_rng;

type Vc = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

// 1. Build the relation (e.g., a hash chain of length 10).
let poseidon = poseidon::initialize_poseidon_config::<F>();
let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::arithmetize(&(poseidon, 10))?;

// 2. Pick a code.
let code = ReedSolomon::new(ReedSolomonConfig::<F>::default(
    r1cs.k_num_witness_vars,
    r1cs.k_num_witness_vars.next_power_of_two(),
));

// 3. Provision the VC committer/verifier keys.
let mut rng = thread_rng();
let t = 7;
let pp = <Vc as MultiVectorCommitment>::setup_multiple(0, code.code_len(), t, &mut rng)?;
let (ck, vk) = <Vc as MultiVectorCommitment>::trim_multiple(&pp, 0, code.code_len(), t)?;

// 4. Configure WARP and instantiate.
//    (l1, l2, s, t): fresh-batch size, acc capacity, OOD samples, shift queries.
let cfg = WarpConfig::new(/*l1*/ 4, /*l2*/ 4, /*s*/ 8, /*t*/ 7);
let warp = WarpAccumulationScheme::<F, R1CS<F>, _, Vc>::new(cfg, code, r1cs.clone(), ck, vk);

// 5. Fold a stream of (instance, witness) batches into the accumulator.
let pk = WarpProverKey {
    index: r1cs.clone(),
    m_num_constraints: r1cs.m_num_constraints,
    n_num_variables: r1cs.n_num_variables,
    k_num_witness_vars: r1cs.k_num_witness_vars,
};
let mut acc_x = AccumulatorInstance::empty();
let mut acc_w = AccumulatorWitness::empty();
for batch in batches {
    let mut prover_state = /* spongefish prover state */;
    let ((new_x, new_w), _proof) = warp.prove(
        pk.clone(), &mut prover_state, batch.witnesses, batch.instances,
        AccumulatorInstance::empty(), AccumulatorWitness::empty(),
    )?;
    acc_x = acc_x.extend(new_x);
    acc_w = acc_w.extend(new_w);
}

// 6. Final decide (the only non-succinct step — wrap in a SNARK for succinctness).
warp.decide(&acc_x, &acc_w)?;
```

## Picking `(s, t)` for a target security level

The `warp-params` binary picks and validates soundness parameters per
`docs/paper-mods/mod4_parameter_selection.tex`:

```sh
# Pick (s, t) for λ bits of security at a given code rate and field size.
cargo run --release --bin warp-params -- select \
    --lambda 128 --rate 1/2 --field-bits 64 --regime conjectured

# Check that a specific (s, t) actually hits λ bits.
cargo run --release --bin warp-params -- validate \
    --s 8 --t 128 --lambda 128 --rate 1/2 --field-bits 64 --regime conjectured

# Dump the attested presets as TSV.
cargo run --release --bin warp-params -- table
```

`--regime` picks between `provable` and `conjectured` proximity bounds.
Exit codes: 0 ok, 1 derivation failed / target not met, 2 bad args.

## Layout

- `src/accumulation_scheme/` — `WarpAccumulationScheme::{prove, verify, decide}`, `AccumulationScheme` trait, accumulator types
- `src/iop/iors/` — concrete IORs (`pesat`, `twin_constraint`, `bridge`, `ood`, `sample_queries`, `batching`, `proximity`)
- `src/iop/oracles/` — oracle vocabulary used by IORs
- `src/iop/schema.rs` — `ProtocolSchema` (structural snapshot of the IOR sequence + tags)
- `src/relations/` — `R1CS`, `HashChainRelation`, predicate traits
- `src/params/` — soundness-driven `(s, t)` selection backing `warp-params`
- `src/bin/warp-params.rs` — CLI front-end for `src/params/`
- `src/crypto/`, `src/utils/` — VC helper, field / poly utilities
- `src/profile/` — opt-in tracing layer (gated behind the `profile` feature)
- `tests/integration_warp.rs` — end-to-end on BLS12-381 and Goldilocks
- `tests/verifier_negative.rs` — single-tamper rejection tests
- `tests/snapshot_fs.rs` — Fiat-Shamir transcript snapshot (catches FS drift)
- `tests/snapshot_schema.rs` — `ProtocolSchema` snapshot (catches IOR shape drift)

The `IOR` and `IOP` traits live in the external [`ark_iop`](https://github.com/arkworks-rs/ark-vc/tree/z-tech/ark-iop) crate.

## Running tests / benches

```sh
cargo test --release
cargo bench
```

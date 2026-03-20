# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **Migrated to new spongefish API.** Replaced old `add_scalars`, `add_digest`, `fill_challenge_scalars` calls with `prover_message`/`verifier_message`. Updated tests and benchmarks to use `domain_separator!` macro instead of `DomainSeparator::new()` + `WARPDomainSeparator::warp()`.
- **Bump arkworks algebra to upstream.** Switched `ark-ff`, `ark-poly`, and `ark-serialize` patches from [benbencik/algebra](https://github.com/benbencik/algebra) fork to upstream [arkworks-rs/algebra](https://github.com/arkworks-rs/algebra), following the merge of [PR #1044](https://github.com/arkworks-rs/algebra/pull/1044) (Small Field Support).
- **Switched `efficient-sumcheck` to `main` branch.**
- **Renamed `SmallGoldilocks` to `Goldilocks`** in `utils/fields.rs`.
- **Consolidated error types.** Reduced from 6 error enums to 4. Folded `WARPSumcheckProverError` into `ProverError`, inlined `WARPSumcheckVerifierError` into `VerifierError`, dropped `WARP` prefix. Moved errors from `utils/errs.rs` to `error.rs`.
- **Made `chunk_size` compile-time.** Replaced runtime serialization with a `const fn` computed from `PrimeField::MODULUS_BIT_SIZE`.

### Fixed

- **BLS test desync.** Fixed `WARPConfig` in the BLS test from `l=4` to `l=8`, matching `l2=4` accumulated instances. The prover absorbed all accumulators unconditionally while the verifier only read `l2` of them, causing a sponge state mismatch.
- **Coefficient padding.** `DensePolynomial::from_coefficients_vec` strips trailing zeros, causing the prover to write fewer coefficients than the verifier expects. Added padding in `twin_constraint_round_poly` to a fixed degree.

### Removed

- **Unused dependencies:** `zeroize`, `ark-poly-commit`, `rayon`.
- **`ark-goldilocks` dependency.** The Goldilocks field is now defined via `SmallFp` directly.
- **Dead code:** `HintSerialize`/`HintDeserialize` traits (unused), `WARPDomainSeparator` trait, commented-out code, unused imports.

## [0.0.1] — 2025-05-01 → 2026-03-15

Initial development of the WARP accumulation scheme.

### Added

#### Core protocol (May–October 2025)
- Relation trait with separated instance/witness types.
- R1CS constraint system with bundled PESAT evaluation.
- Merkle tree-based commitment scheme using `ark-crypto-primitives` (blake3 backend).
- Prover, verifier, and decider for the WARP accumulation scheme.
- IOR (Interactive Oracle Reduction) implementations for codeword batching and constraint checking.
- Twin constraint pseudo-batching sumcheck.
- Multilinear extension evaluation and eq-polynomial utilities.
- Hashchain relation (Poseidon-based) for benchmarking and testing.
- Domain separator construction (`WARPDomainSeparator`) for Fiat–Shamir via spongefish.
- Error handling with structured prover/verifier/decider error types.
- `MultiConstraintsChecker` trait for all linear codes.
- Proof serialization module.
- End-to-end test (`warp_test`) over BLS12-381.

#### Dependency integration (November 2025)
- Integrated [`efficient-sumcheck`](https://github.com/compsec-epfl/efficient-sumcheck) library, replacing internal sumcheck implementations.
- Adopted [`ark-codes`](https://github.com/dmpierre/ark-codes) for Reed–Solomon and linear code abstractions.
- Switched to [`ark-goldilocks`](https://github.com/dmpierre/ark-goldilocks) for Goldilocks field, removing local field definitions.

#### Small field support (December 2025)
- Added `SmallFp`-based field definitions: `SmallF16` (modulus 65521), `SmallM31` (Mersenne-31), `SmallGoldilocks` (Goldilocks prime).
- Extension field configurations: `Fp2SmallM31` and `Fp4SmallM31`.
- End-to-end test (`warp_test_small_field`) over `SmallGoldilocks`.
- Spongefish integration with SmallFp `Unit` trait (via [benbencik/spongefish](https://github.com/benbencik/spongefish) fork).
- Crypto-primitives `Absorb` trait for SmallFp (via [benbencik/crypto-primitives](https://github.com/benbencik/crypto-primitives) fork).

#### Sumcheck refactoring (March 2026)
- Refactored twin constraint sumcheck to use `coefficient_sumcheck` from `efficient-sumcheck`.
- Extracted helper functions and abstractions for batched constraint polynomial construction.

### Removed
- Internal IOR module (replaced by protocol-level abstractions).
- Local linear code trait (replaced by `ark-codes`).
- Local field definitions (replaced by `ark-goldilocks`).
- Direct WHIR dependency (functionality re-implemented internally).
- Unused BN254 config, traits, and field definitions.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **Bump arkworks algebra to upstream.** Switched `ark-ff`, `ark-poly`, and `ark-serialize` patches from [benbencik/algebra](https://github.com/benbencik/algebra) fork to upstream [arkworks-rs/algebra](https://github.com/arkworks-rs/algebra), following the merge of [PR #1044](https://github.com/arkworks-rs/algebra/pull/1044) (Small Field Support).
- **Consolidated field definitions to SmallFp only.** Removed unused BigInt-based field types (`F19`, `M31`, `F64`, `F128` using `Fp64`/`Fp128`/`MontBackend`) from `utils/fields.rs`.

### Removed

- **`ark-goldilocks` dependency.** The Goldilocks field is now defined via `SmallFp` directly (`SmallGoldilocks`).

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

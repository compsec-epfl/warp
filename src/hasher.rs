//! Hasher bound warp expects callers to satisfy.
//!
//! Warp's `WARP<F, P, C, H>` generic takes any [`ark_vc::MerkleHasher`]
//! whose leaf shape matches our codeword layout (a `Vec<F>` per leaf
//! position) and whose digest is transcript-serialisable under
//! spongefish. Blake3 over field-element leaves is the default (Blake3
//! digest = `[u8; 32]`, directly absorbable); Poseidon2 over field-
//! element leaves is the recursion-friendly alternative (Poseidon
//! digest = `F`, absorbed as a field element).
//!
//! The [`WarpHasher`] trait below is a marker: it bundles the trait
//! bounds into one name so every generic signature in the crate can
//! write `H: WarpHasher<F>` instead of repeating the full bound list.
//! Bounds on the associated `Digest` type are expressed via the
//! `MerkleHasher<..., Digest: ...>` associated-type-bounds syntax so
//! they propagate through generic use sites without callers having to
//! re-state them.
//!
//! There's a blanket impl for anything that satisfies the component
//! bounds, so callers don't need to implement it explicitly — they
//! just need to pass a hasher that meets the component traits (which
//! `Blake3FieldHasher<F>` and `Poseidon2Hasher<F>` from ark-vc both
//! do).

use ark_ff::PrimeField;
use ark_vc::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

/// Hasher bound used throughout warp's generic API.
pub trait WarpHasher<F: PrimeField>:
    MerkleHasher<
        Symbol = Vec<F>,
        Digest: Clone + Eq + Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize,
    > + Clone
{
}

impl<F, H> WarpHasher<F> for H
where
    F: PrimeField,
    H: MerkleHasher<Symbol = Vec<F>> + Clone,
    H::Digest: Clone + Eq + Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize,
{
}

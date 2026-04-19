//! Vector-commitment aliases for warp.
//!
//! Warp pins its Merkle scheme to Blake3-over-field-elements with a
//! perfect-binary tree shape — the canonical FRI/STARK layout. As of
//! ark-vc 2571ef6 that combination ships upstream as the
//! [`ark_vc::blake3::binary`] preset, so this module is a thin
//! re-export: it keeps the import path `crate::crypto::vc::*` stable
//! for warp's internals while sourcing the types from upstream.
//!
//! Swapping the hasher family (e.g. to Poseidon2) would still route
//! through this module — add new `pub use` lines here rather than
//! changing every import site.

pub use ark_vc::blake3::binary::{
    hasher, scheme, Committed, Hasher, Proof, Scheme, Shape, DIGEST_BYTES,
};

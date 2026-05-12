//! Oracle access via handle traits.
//!
//! IOR verifiers code against [`IndexedOracle`] rather than against a
//! concrete BCS-shaped tuple of `(root, opening proof, precomputed answer
//! table)`. The handle internally validates the commitment-scheme opening
//! and exposes a partial-function view of the committed oracle:
//!
//! ```text
//!   query(i) -> Some(value)  iff  index in range AND opening passes
//!   query(i) -> None         otherwise
//! ```
//!
//! Matches the IOP/BCS formalism where oracles are partial functions;
//! the BCS instantiation (Merkle root + path-pruned multi-opening proof +
//! authenticated values) lives behind the trait, not in IOR verifier code.
//!
//! Currently used by [`super::proximity`] on the verifier side. Other
//! IORs continue to use concrete oracle types for now; migration of
//! OOD / Batching prover-side `Oracle<F>` access to a sibling
//! `EvalOracle<F>` trait is tracked as a follow-up.

use std::cell::OnceCell;

use ark_ff::Field;
use ark_mt::{multi_vector::MultiVectorOpening, MerkleHasher};

use crate::crypto::merkle::{WarpProof, WarpScheme};

/// Partial-function view of an indexed oracle.
///
/// Implementations are responsible for any validation needed before
/// returning a value. `query(i) -> None` covers both "index out of
/// range" and "opening failed validation."
pub trait IndexedOracle<A> {
    fn query(&self, i: usize) -> Option<A>;
    /// Optional eager validation hook. Callers that want a single
    /// up-front check (rather than lazy per-query) call `validate()`
    /// once. The default impl performs a no-op `query(0)` to drive
    /// whatever lazy validation the impl uses.
    fn validate(&self) -> bool {
        self.query(0).is_some()
    }
}

/// BCS-checked Merkle handle for a multi-vector commitment.
///
/// Holds the scheme, root, opening proof, and the (sorted, unique)
/// indices + per-index values that get authenticated against the root.
/// Validation runs lazily on the first call to [`query`] /
/// [`validate`] and is memoized so repeated calls are free.
pub struct MerkleIndexedOracle<'a, F, H>
where
    F: Field + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub scheme: WarpScheme<H, F>,
    pub root: &'a H::Digest,
    pub proof: &'a WarpProof<H>,
    /// Sorted, unique leaf positions that appear in `values_by_index`.
    pub sorted_indices: Vec<usize>,
    /// `values_by_index[k]` is the leaf-tuple at `sorted_indices[k]`.
    /// Inner length = number of codewords interleaved under this root.
    pub values_by_index: Vec<Vec<F>>,
    /// Memoized opening-validation result.
    validated: OnceCell<bool>,
}

impl<'a, F, H> MerkleIndexedOracle<'a, F, H>
where
    F: Field + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn new(
        scheme: WarpScheme<H, F>,
        root: &'a H::Digest,
        proof: &'a WarpProof<H>,
        sorted_indices: Vec<usize>,
        values_by_index: Vec<Vec<F>>,
    ) -> Self {
        Self {
            scheme,
            root,
            proof,
            sorted_indices,
            values_by_index,
            validated: OnceCell::new(),
        }
    }

    fn run_validation(&self) -> bool {
        let opening = match MultiVectorOpening::new(
            self.sorted_indices.clone(),
            self.values_by_index.clone(),
        ) {
            Ok(o) => o,
            Err(_) => return false,
        };
        self.scheme.check(self.root, &opening, self.proof)
    }
}

impl<'a, F, H> IndexedOracle<Vec<F>> for MerkleIndexedOracle<'a, F, H>
where
    F: Field + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    fn query(&self, i: usize) -> Option<Vec<F>> {
        let valid = *self.validated.get_or_init(|| self.run_validation());
        if !valid {
            return None;
        }
        let pos = self.sorted_indices.binary_search(&i).ok()?;
        Some(self.values_by_index[pos].clone())
    }

    fn validate(&self) -> bool {
        *self.validated.get_or_init(|| self.run_validation())
    }
}

//! Partial-function view of a Merkle-committed indexed oracle:
//! `query(i)` returns `Some(value)` iff the opening at `i` validates.

use std::cell::OnceCell;

use ark_ff::Field;
use ark_mt::{multi_vector::MultiVectorOpening, MerkleHasher};

use crate::crypto::merkle::{WarpProof, WarpScheme};

pub trait IndexedOracle<A> {
    fn query(&self, i: usize) -> Option<A>;
    fn validate(&self) -> bool {
        self.query(0).is_some()
    }
}

pub struct MerkleIndexedOracle<'a, F, H>
where
    F: Field + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub scheme: WarpScheme<H, F>,
    pub root: &'a H::Digest,
    pub proof: &'a WarpProof<H>,
    pub sorted_indices: Vec<usize>,
    pub values_by_index: Vec<Vec<F>>,
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

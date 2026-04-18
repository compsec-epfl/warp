//! Oracle abstraction for Warp's IOR phases.
//!
//! Paired spec: `docs/paper-mods/mod1_oracle.tex`.
//!
//! An [`Oracle`] is a single object that carries both views Warp's phases
//! need of a committed codeword: the raw evaluation table `f: [n] → F`
//! (BCS-native, index-queryable) and the implied multilinear extension
//! `\hat f: F^{log n} → F` (point-queryable). The multilinear extension is
//! materialised lazily on first point query and cached.
//!
//! The Merkle commitment of the codeword is **not** held here. In PESAT a
//! single Merkle tree covers many interleaved codewords
//! (`src/crypto/merkle/mod.rs::build_codeword_leaves`), so the tree is
//! tracked by the enclosing data structure (`PesatOutput`,
//! `AccumulatorWitness`) rather than 1:1 with the oracle. See the
//! Implementation note in `mod1_oracle.tex` §2.

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::log2;
use std::cell::OnceCell;

use crate::count_ops;

/// A Warp oracle: a committed codeword together with its lazily-materialised
/// multilinear extension.
pub struct Oracle<F: Field> {
    evals: Vec<F>,
    mle: OnceCell<DenseMultilinearExtension<F>>,
}

impl<F: Field> Oracle<F> {
    /// Wrap an existing evaluation table.
    pub fn from_evals(evals: Vec<F>) -> Self {
        Self {
            evals,
            mle: OnceCell::new(),
        }
    }

    /// Borrow the evaluation table `f`.
    pub fn evals(&self) -> &[F] {
        &self.evals
    }

    /// Consume the oracle and return the underlying evaluation table.
    pub fn into_evals(self) -> Vec<F> {
        self.evals
    }

    /// Length `n` of the evaluation table.
    pub fn len(&self) -> usize {
        self.evals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evals.is_empty()
    }

    /// Index query: `f[i]`.
    pub fn query_at_leaf(&self, idx: usize) -> F {
        count_ops!(OracleLeafQueries);
        self.evals[idx]
    }

    /// Point query on the multilinear extension: `\hat f(ζ)` for
    /// `ζ ∈ F^{log n}`. Materialises the MLE on first call and caches it.
    pub fn query_at_point(&self, point: &[F]) -> F {
        count_ops!(OraclePointQueries);
        let mle = self.mle.get_or_init(|| {
            count_ops!(MleMaterializations);
            let log_n = log2(self.evals.len()) as usize;
            DenseMultilinearExtension::from_evaluations_slice(log_n, &self.evals)
        });
        mle.fix_variables(point)[0]
    }
}

impl<F: Field> From<Vec<F>> for Oracle<F> {
    fn from(evals: Vec<F>) -> Self {
        Self::from_evals(evals)
    }
}

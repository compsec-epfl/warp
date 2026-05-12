//! Codeword oracle: index-queryable evaluation table plus its
//! lazily-materialised multilinear extension.

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
    pub fn from_evals(evals: Vec<F>) -> Self {
        Self {
            evals,
            mle: OnceCell::new(),
        }
    }

    pub fn evals(&self) -> &[F] {
        &self.evals
    }

    pub fn into_evals(self) -> Vec<F> {
        self.evals
    }

    pub fn len(&self) -> usize {
        self.evals.len()
    }

    pub fn is_empty(&self) -> bool {
        self.evals.is_empty()
    }

    pub fn query_at_leaf(&self, idx: usize) -> F {
        count_ops!(OracleLeafQueries);
        self.evals[idx]
    }

    /// `\hat f(ζ)`. Materialises the MLE on first call, caches afterward.
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

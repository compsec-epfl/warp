//! Pre-validated lookup view of an opened indexed oracle.
//!
//! With the trait migration, opening proofs live in the spongefish
//! transcript and `V::check_multiple` consumes them at a specific
//! point in the transcript. The orchestrator validates upstream and
//! hands IORs a `ValidatedOracle` — a sorted (index, value) table the
//! IOR queries without re-running the BCS check.

use ark_ff::Field;

pub trait IndexedOracle<A> {
    fn query(&self, i: usize) -> Option<A>;
    fn validate(&self) -> bool {
        self.query(0).is_some()
    }
}

pub struct ValidatedOracle<F: Field> {
    pub sorted_indices: Vec<usize>,
    pub values_by_index: Vec<Vec<F>>,
}

impl<F: Field> ValidatedOracle<F> {
    pub fn new(sorted_indices: Vec<usize>, values_by_index: Vec<Vec<F>>) -> Self {
        Self {
            sorted_indices,
            values_by_index,
        }
    }
}

impl<F: Field> IndexedOracle<Vec<F>> for ValidatedOracle<F> {
    fn query(&self, i: usize) -> Option<Vec<F>> {
        let pos = self.sorted_indices.binary_search(&i).ok()?;
        Some(self.values_by_index[pos].clone())
    }

    fn validate(&self) -> bool {
        true
    }
}

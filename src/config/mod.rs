use ark_ff::Field;

use crate::relations::PolyPredicate;

#[derive(Clone)]
pub struct WARPConfig<F: Field, P: PolyPredicate<F>> {
    pub l1_first_fold_factor: usize,
    pub l2_second_fold_factor: usize,
    pub s_num_ood_samples: usize,
    pub t_num_queries: usize,
    pub predicate_config: P::Config,
    pub n_code_len: usize,
}

impl<F: Field, P: PolyPredicate<F>> WARPConfig<F, P> {
    pub fn new(
        l1_first_fold_factor: usize,
        l2_second_fold_factor: usize,
        s_num_ood_samples: usize,
        t_num_queries: usize,
        predicate_config: P::Config,
        n_code_len: usize,
    ) -> Self {
        Self {
            l1_first_fold_factor,
            l2_second_fold_factor,
            s_num_ood_samples,
            t_num_queries,
            predicate_config,
            n_code_len,
        }
    }

    /// Total fold factor `l = l1 + l2`.
    pub fn l_total_fold_factor(&self) -> usize {
        self.l1_first_fold_factor + self.l2_second_fold_factor
    }
}

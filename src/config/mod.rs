use ark_ff::Field;

use crate::params::{validate, ParamError, Params, Regime, SecurityLevel, SoundnessBound};
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

    /// Fail-closed soundness check on `(s, t)`. Returns `Ok(bound)` only when
    /// every admissibility flag passes and proximity soundness meets the
    /// target. `WARPConfig::new` itself does not call this (it cannot, the
    /// security target / field-size / rate / regime live outside the config);
    /// callers building a config for production use **must** call this before
    /// invoking the prover. See `docs/paper-mods/mod4_parameter_selection.tex`.
    pub fn validate_security(
        &self,
        field_bits: u32,
        code_rate: f64,
        regime: Regime,
        target: SecurityLevel,
    ) -> Result<SoundnessBound, ParamError> {
        let params = Params {
            s: self.s_num_ood_samples,
            t: self.t_num_queries,
        };
        validate(&params, field_bits, code_rate, regime, target)
    }
}

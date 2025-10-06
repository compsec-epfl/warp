use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
};
use ark_ff::Field;
use spongefish::Unit;

use crate::linear_code::LinearCode;

pub mod r1cs;

#[derive(Clone)]
pub struct TwinConstraintIORConfig<F: Field + Unit, C: LinearCode<F>, MT: Config> {
    code: C,
    pub l: usize,
    pub log_m: usize,
    _f: PhantomData<F>,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<F: Field + Unit, C: LinearCode<F>, MT: Config> TwinConstraintIORConfig<F, C, MT> {
    pub fn new(
        code: C,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        l: usize,
        log_m: usize,
    ) -> Self {
        Self {
            code,
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
            l,
            log_m,
            _f: PhantomData,
        }
    }
}

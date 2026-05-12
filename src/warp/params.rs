use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_mt::MerkleHasher;
use std::marker::PhantomData;

use crate::config::WARPConfig;
use crate::relations::PolyPredicate;

/// Shared configuration used by all IORs.
pub struct WARPParams<F: Field, P: PolyPredicate<F>, C: LinearCode<F> + Clone, H: MerkleHasher> {
    pub(crate) _phantom_f: PhantomData<F>,
    pub config: WARPConfig<F, P>,
    pub code: C,
    pub predicate: P,
    pub hasher: H,
}

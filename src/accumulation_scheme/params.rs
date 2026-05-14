use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;
use std::marker::PhantomData;

use crate::config::WarpConfig;
use crate::relations::PolyPredicate;

/// Shared configuration used by all IORs.
pub struct WarpParams<F, P, C, V>
where
    F: Field,
    P: PolyPredicate<F>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub(crate) _phantom_f: PhantomData<F>,
    pub config: WarpConfig<F, P>,
    pub code: C,
    pub predicate: P,
    pub ck: V::CommitterKey,
    pub vk: V::VerifierKey,
}

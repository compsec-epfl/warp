use ark_codes::traits::LinearCode;
use ark_ff::Field;
use ark_vc::mvc::MultiVectorCommitment;

use crate::accumulation_scheme::params::WarpParams;
use crate::config::WarpConfig;
use crate::relations::PolyPredicate;

pub struct WarpAccumulationScheme<F, P, C, V>
where
    F: Field,
    P: PolyPredicate<F>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub params: WarpParams<F, P, C, V>,
}

impl<F, P, C, V> WarpAccumulationScheme<F, P, C, V>
where
    F: Field,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub fn new(
        config: WarpConfig<F, P>,
        code: C,
        predicate: P,
        ck: V::CommitterKey,
        vk: V::VerifierKey,
    ) -> WarpAccumulationScheme<F, P, C, V> {
        Self {
            params: WarpParams { config, code, predicate, ck, vk },
        }
    }
}


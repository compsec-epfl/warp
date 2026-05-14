use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerificationResult,
};
use std::marker::PhantomData;

use crate::accumulation_scheme::keys::{WarpProverKey, WarpVerifierKey};
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
            params: WarpParams {
                _phantom_f: PhantomData,
                config,
                code,
                predicate,
                ck,
                vk,
            },
        }
    }
}

impl<F, P, C, V> WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F>,
{
    pub fn index(
        prover_state: &mut ProverState,
        index: P,
    ) -> VerificationResult<(WarpProverKey<P>, WarpVerifierKey)> {
        let (m, n, k) = index.config();
        prover_state.public_message(&index.description());
        prover_state.prover_message(&F::from(m as u32));
        prover_state.prover_message(&F::from(n as u32));
        prover_state.prover_message(&F::from(k as u32));
        Ok((
            WarpProverKey {
                index,
                m_num_constraints: m,
                n_num_variables: n,
                k_num_witness_vars: k,
            },
            WarpVerifierKey {
                m_num_constraints: m,
                n_num_variables: n,
                k_num_witness_vars: k,
            },
        ))
    }
}

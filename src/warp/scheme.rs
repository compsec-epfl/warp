use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerificationResult,
};
use std::marker::PhantomData;

use crate::config::WARPConfig;
use crate::relations::PolyPredicate;
use crate::warp::keys::{WARPProverKey, WARPVerifierKey};
use crate::warp::params::WARPParams;

pub struct WARP<F: Field, P: PolyPredicate<F>, C: LinearCode<F> + Clone, H: MerkleHasher> {
    pub params: WARPParams<F, P, C, H>,
}

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn new(config: WARPConfig<F, P>, code: C, predicate: P, hasher: H) -> WARP<F, P, C, H> {
        Self {
            params: WARPParams {
                _phantom_f: PhantomData,
                config,
                code,
                predicate,
                hasher,
            },
        }
    }
}

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn index(
        prover_state: &mut ProverState,
        index: P,
    ) -> VerificationResult<(WARPProverKey<P>, WARPVerifierKey)> {
        let (m, n, k) = index.config();
        prover_state.public_message(&index.description());
        prover_state.prover_message(&F::from(m as u32));
        prover_state.prover_message(&F::from(n as u32));
        prover_state.prover_message(&F::from(k as u32));
        Ok((
            WARPProverKey {
                index,
                m_num_constraints: m,
                n_num_variables: n,
                k_num_witness_vars: k,
            },
            WARPVerifierKey {
                m_num_constraints: m,
                n_num_variables: n,
                k_num_witness_vars: k,
            },
        ))
    }
}

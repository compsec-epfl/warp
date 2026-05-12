use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{
    Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerificationResult,
    VerifierState,
};
use std::marker::PhantomData;

use crate::accumulation::AccumulationScheme;
use crate::config::WARPConfig;
use crate::error::{VerifierError, WARPError};
use crate::relations::{r1cs::R1CSConstraints, BundledPESAT};
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};
use crate::warp::keys::{WARPProverKey, WARPVerifierKey};
use crate::warp::params::WARPParams;
use crate::warp::proof::{ProveResult, WARPProof};

pub struct WARP<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, H: MerkleHasher> {
    pub params: WARPParams<F, P, C, H>,
}

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field,
    P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn new(config: WARPConfig<F, P>, code: C, p: P, hasher: H) -> WARP<F, P, C, H> {
        Self {
            params: WARPParams {
                _f: PhantomData,
                config,
                code,
                p,
                hasher,
            },
        }
    }
}

impl<F, P, C, H> AccumulationScheme<F, H> for WARP<F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    type Index = P;
    type ProverKey = WARPProverKey<P>;
    type VerifierKey = WARPVerifierKey;
    type Instances = Vec<Vec<F>>;
    type Witnesses = Vec<Vec<F>>;

    fn index(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> VerificationResult<(Self::ProverKey, Self::VerifierKey)> {
        let (m, n, k) = index.config();
        prover_state.public_message(&index.description());
        prover_state.prover_message(&F::from(m as u32));
        prover_state.prover_message(&F::from(n as u32));
        prover_state.prover_message(&F::from(k as u32));
        Ok((
            WARPProverKey { index, m, n, k },
            WARPVerifierKey { m, n, k },
        ))
    }

    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instance: AccumulatorInstance<F, H>,
        acc_witness: AccumulatorWitness<F, H>,
    ) -> ProveResult<F, H> {
        self.prove_impl(pk, prover_state, witnesses, instances, acc_instance, acc_witness)
    }

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F, H>,
        proof: WARPProof<F, H>,
    ) -> Result<(), VerifierError> {
        self.verify_impl(vk, verifier_state, acc_instance, proof)
    }

    fn decide(
        &self,
        acc_witness: AccumulatorWitness<F, H>,
        acc_instance: AccumulatorInstance<F, H>,
    ) -> Result<(), WARPError> {
        self.decide_impl(acc_witness, acc_instance)
    }
}

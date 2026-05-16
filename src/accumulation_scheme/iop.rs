//! `IOP` + `AccumulationScheme` trait impls on `WarpAccumulationScheme`,
//! plus the `schema()` constructor and the decider.

use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_iop::{IOP, IOR};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;
use ark_vc::mvc::MultiVectorCommitment;
use ark_vc::vc::VectorCommitment;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use crate::accumulation_scheme::AccumulationScheme;
use crate::accumulation_scheme::{
    accumulator::{AccumulatorInstance, AccumulatorWitness},
    proof::WarpProof,
    scheme::WarpAccumulationScheme,
};
use crate::error::DeciderError;
use crate::iop::iors::{
    batching::Batching, bridge::Bridge, ood::Ood, pesat::Pesat, sample_queries::SampleQueries,
    twin_constraint::TwinConstraint,
};
use crate::relations::PolyPredicate;

impl<F, P, C, V> IOP for WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone,
{
    const NAME: &'static str = "WARP";

    // Names absorbed in the AccumulationScheme prologue (the top-level
    // domain separator). Excludes Proximity: its `compose_*` still
    // absorbs its name+tags mid-stream when invoked, but the prologue
    // here only lists the IOP-level IORs whose order defines the
    // FS protocol map up-front. For the *complete* protocol shape
    // (including Proximity), see `schema()`.
    fn ior_names() -> Vec<&'static str> {
        vec![
            <Pesat<'_, F, C, V> as IOR>::NAME,
            <TwinConstraint<'_, F, V> as IOR>::NAME,
            <Bridge<F, P, V> as IOR>::NAME,
            <Ood<F> as IOR>::NAME,
            <SampleQueries<F> as IOR>::NAME,
            <Batching<F> as IOR>::NAME,
        ]
    }

    type Statement = Vec<Vec<F>>;
    type Witness = Vec<Vec<F>>;
    type Proof = WarpProof<F, V>;
}

impl<F, P, C, V> WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone,
{
    /// Complete protocol shape (includes Proximity, which `ior_names()` omits).
    pub fn schema() -> crate::iop::schema::ProtocolSchema {
        use crate::iop::iors::proximity::Proximity;
        use crate::iop::schema::{IorSchema, ProtocolSchema};
        ProtocolSchema {
            iop_name: <Self as IOP>::NAME,
            iors: vec![
                IorSchema {
                    name: <Pesat<'_, F, C, V> as IOR>::NAME,
                    message_tags: <Pesat<'_, F, C, V> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <TwinConstraint<'_, F, V> as IOR>::NAME,
                    message_tags: <TwinConstraint<'_, F, V> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <Bridge<F, P, V> as IOR>::NAME,
                    message_tags: <Bridge<F, P, V> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <Ood<F> as IOR>::NAME,
                    message_tags: <Ood<F> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <SampleQueries<F> as IOR>::NAME,
                    message_tags: <SampleQueries<F> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <Batching<F> as IOR>::NAME,
                    message_tags: <Batching<F> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[],
                },
                IorSchema {
                    name: <Proximity<F> as IOR>::NAME,
                    message_tags: <Proximity<F> as IOR>::MESSAGE_TAGS,
                    delegated_events: &[
                        "vc.open_multiple:fresh",
                        "vc.open_multiple:acc[*]",
                    ],
                },
            ],
        }
    }
}

impl<F, P, C, V> AccumulationScheme for WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    const NAME: &'static str = "WARP-AccScheme";
    type Iop = Self;
    type FreshInstance = Vec<Vec<F>>;
    type FreshWitness = Vec<Vec<F>>;
    type AccumulatorInstance = AccumulatorInstance<F, V>;
    type AccumulatorWitness = AccumulatorWitness<F, V>;
    type AccumulationProof = WarpProof<F, V>;

    fn decide(
        &self,
        acc_instance: &Self::AccumulatorInstance,
        acc_witness: &Self::AccumulatorWitness,
    ) -> Result<(), DeciderError> {
        let acc_codeword = &acc_witness.td_committed_codewords[0].codewords[0];

        let computed_f = self.params.code.encode(&acc_witness.w_witnesses[0]);
        (acc_codeword == &computed_f)
            .then_some(())
            .ok_or(DeciderError::EncodedWitness)?;

        let (recomputed_commitment, _state) =
            <V as VectorCommitment>::commit(&self.params.ck, computed_f.iter())
                .map_err(|_| DeciderError::MerkleRoot)?;
        (acc_instance.rt_commitments[0] == recomputed_commitment)
            .then_some(())
            .ok_or(DeciderError::MerkleRoot)?;
        (acc_witness.td_committed_codewords[0].commitment == recomputed_commitment)
            .then_some(())
            .ok_or(DeciderError::MerkleTrapDoor)?;

        let f_hat = DenseMultilinearExtension::from_evaluations_slice(
            log2(self.params.code.code_len()) as usize,
            acc_codeword,
        );
        (f_hat.evaluate(&acc_instance.alpha_fold_vectors[0]) == acc_instance.mu_claimed_evals[0])
            .then_some(())
            .ok_or(DeciderError::MLExtensionEvaluation)?;

        let tau = &acc_instance.beta_twin_pairs[0].tau;
        let tau_zero_evader = compute_hypercube_eq_evals(tau.len(), tau);
        let mut z = acc_instance.beta_twin_pairs[0].x.clone();
        z.extend(acc_witness.w_witnesses[0].clone());
        let computed_eta = self
            .params
            .predicate
            .evaluate_bundled(&tau_zero_evader, &z)
            .map_err(|_| DeciderError::BundledEvaluation)?;
        (computed_eta == acc_instance.eta_predicate_evals[0])
            .then_some(())
            .ok_or(DeciderError::BundledEvaluation)?;

        Ok(())
    }
}

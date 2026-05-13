use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;
use ark_vc::mvc::MultiVectorCommitment;
use ark_vc::vc::VectorCommitment;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use crate::error::{DeciderError, WARPError};
use crate::relations::PolyPredicate;
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};
use crate::warp::scheme::WARP;

impl<F, P, C, V> WARP<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Clone + Eq,
{
    pub fn decide(
        &self,
        acc_witness: AccumulatorWitness<F, V>,
        acc_instance: AccumulatorInstance<F, V>,
    ) -> Result<(), WARPError> {
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

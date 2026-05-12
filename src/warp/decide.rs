use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_std::log2;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};

use crate::crypto::merkle::warp_scheme;
use crate::error::{DeciderError, WARPError};
use crate::relations::{r1cs::R1CSConstraints, BundledPESAT};
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};
use crate::warp::scheme::WARP;

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    pub fn decide(
        &self,
        acc_witness: AccumulatorWitness<F, H>,
        acc_instance: AccumulatorInstance<F, H>,
    ) -> Result<(), WARPError> {
        let acc_codeword = &acc_witness.td[0].codewords()[0];

        let computed_f = self.params.code.encode(&acc_witness.w[0]);
        (acc_codeword == &computed_f)
            .then_some(())
            .ok_or(DeciderError::EncodedWitness)?;

        let scheme = warp_scheme::<H, F>(self.params.hasher.clone(), self.params.code.code_len());
        let recomputed = scheme.commit(std::slice::from_ref(&computed_f));
        (acc_instance.rt[0] == *recomputed.root())
            .then_some(())
            .ok_or(DeciderError::MerkleRoot)?;
        (acc_witness.td[0].root() == recomputed.root())
            .then_some(())
            .ok_or(DeciderError::MerkleTrapDoor)?;

        let f_hat = DenseMultilinearExtension::from_evaluations_slice(
            log2(self.params.code.code_len()) as usize,
            acc_codeword,
        );
        (f_hat.evaluate(&acc_instance.alpha[0]) == acc_instance.mu[0])
            .then_some(())
            .ok_or(DeciderError::MLExtensionEvaluation)?;

        let tau = &acc_instance.beta.0[0];
        let tau_zero_evader = compute_hypercube_eq_evals(tau.len(), tau);
        let mut z = acc_instance.beta.1[0].clone();
        z.extend(acc_witness.w[0].clone());
        let computed_eta = self
            .params
            .p
            .evaluate_bundled(&tau_zero_evader, &z)
            .unwrap();
        (computed_eta == acc_instance.eta[0])
            .then_some(())
            .ok_or(DeciderError::BundledEvaluation)?;

        Ok(())
    }
}

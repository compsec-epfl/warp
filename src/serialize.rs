use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_vc::OpeningProof;

use crate::hasher::WarpHasher;
use crate::types::{AccumulatorInstance, AccumulatorWitness, WARPProof};

/// Wire-size view of an `AccumulatorWitness<F, H>` holding exactly one
/// accumulated oracle. Takes `&acc_witness` — cheap, no clone of the
/// ark-vc `Committed` (which isn't `Clone`).
#[derive(CanonicalSerialize)]
pub struct AccWitnessSerializer<F: PrimeField> {
    pub f: Vec<F>,
    pub w: Vec<F>,
}

impl<F: PrimeField> AccWitnessSerializer<F> {
    pub fn new<H: WarpHasher<F>>(acc_witness: &AccumulatorWitness<F, H>) -> Self {
        assert_eq!(acc_witness.td.len(), 1);
        assert_eq!(acc_witness.f.len(), 1);
        assert_eq!(acc_witness.w.len(), 1);
        Self {
            f: acc_witness.f[0].clone(),
            w: acc_witness.w[0].clone(),
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct AccInstanceSerializer<F: PrimeField, H: WarpHasher<F>> {
    pub rt: H::Digest,
    pub alpha: Vec<F>,
    pub mu: F,
    pub beta: (Vec<F>, Vec<F>),
    pub eta: F,
}

impl<F: PrimeField, H: WarpHasher<F>> AccInstanceSerializer<F, H> {
    pub fn new(acc_instance: &AccumulatorInstance<F, H>) -> Self {
        assert_eq!(acc_instance.rt.len(), 1);
        assert_eq!(acc_instance.alpha.len(), 1);
        assert_eq!(acc_instance.mu.len(), 1);
        assert_eq!(acc_instance.beta.0.len(), 1);
        assert_eq!(acc_instance.beta.1.len(), 1);
        assert_eq!(acc_instance.eta.len(), 1);
        Self {
            rt: acc_instance.rt[0].clone(),
            alpha: acc_instance.alpha[0].clone(),
            mu: acc_instance.mu[0],
            beta: (
                acc_instance.beta.0[0].clone(),
                acc_instance.beta.1[0].clone(),
            ),
            eta: acc_instance.eta[0],
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct ProofSerializer<F: PrimeField, H: WarpHasher<F>> {
    pub rt_0: H::Digest,
    pub mu_i: Vec<F>,
    pub nu_0: F,
    pub nu_i: Vec<F>,
    pub auth_0: OpeningProof<H>,
    pub auth_j: Vec<OpeningProof<H>>,
    pub f_i_x_j: Vec<Vec<F>>,
}

impl<F: PrimeField, H: WarpHasher<F>> ProofSerializer<F, H> {
    pub fn new(proof: &WARPProof<F, H>) -> Self {
        Self {
            rt_0: proof.rt_0.clone(),
            mu_i: proof.mu_i.clone(),
            nu_0: proof.nu_0,
            nu_i: proof.nu_i.clone(),
            auth_0: proof.auth_0.clone(),
            auth_j: proof.auth_j.clone(),
            f_i_x_j: proof.shift_query_answers.clone(),
        }
    }
}

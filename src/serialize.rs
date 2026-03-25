use ark_crypto_primitives::merkle_tree::{Config, Path};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;

use crate::types::{AccumulatorInstance, AccumulatorWitness, WARPProof};

#[derive(CanonicalSerialize)]
pub struct AccWitnessSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    pub f: Vec<F>,
    pub w: Vec<F>,
    _mt: std::marker::PhantomData<MT>,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    AccWitnessSerializer<F, MT>
{
    pub fn new(acc_witness: AccumulatorWitness<F, MT>) -> Self {
        assert_eq!(acc_witness.td.len(), 1);
        assert_eq!(acc_witness.f.len(), 1);
        assert_eq!(acc_witness.w.len(), 1);
        Self {
            f: acc_witness.f.into_iter().next().unwrap(),
            w: acc_witness.w.into_iter().next().unwrap(),
            _mt: std::marker::PhantomData,
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct AccInstanceSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    pub rt: MT::InnerDigest,
    pub alpha: Vec<F>,
    pub mu: F,
    pub beta: (Vec<F>, Vec<F>),
    pub eta: F,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    AccInstanceSerializer<F, MT>
{
    pub fn new(acc_instance: AccumulatorInstance<F, MT>) -> Self {
        assert_eq!(acc_instance.rt.len(), 1);
        assert_eq!(acc_instance.alpha.len(), 1);
        assert_eq!(acc_instance.mu.len(), 1);
        assert_eq!(acc_instance.beta.0.len(), 1);
        assert_eq!(acc_instance.beta.1.len(), 1);
        assert_eq!(acc_instance.eta.len(), 1);
        let beta = (
            acc_instance.beta.0.into_iter().next().unwrap(),
            acc_instance.beta.1.into_iter().next().unwrap(),
        );
        Self {
            rt: acc_instance.rt.into_iter().next().unwrap(),
            alpha: acc_instance.alpha.into_iter().next().unwrap(),
            mu: acc_instance.mu[0],
            beta,
            eta: acc_instance.eta[0],
        }
    }
}

#[derive(CanonicalSerialize)]
pub struct ProofSerializer<
    F: Field + PrimeField,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
> {
    pub rt_0: MT::InnerDigest,
    pub mu_i: Vec<F>,
    pub nu_0: F,
    pub nu_i: Vec<F>,
    pub auth_0: Vec<Path<MT>>,
    pub auth_j: Vec<Vec<Path<MT>>>,
    pub f_i_x_j: Vec<Vec<F>>,
}

impl<F: Field + PrimeField, MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>>
    ProofSerializer<F, MT>
{
    pub fn new(proof: WARPProof<F, MT>) -> Self {
        Self {
            rt_0: proof.rt_0,
            mu_i: proof.mu_i,
            nu_0: proof.nu_0,
            nu_i: proof.nu_i,
            auth_0: proof.auth_0,
            auth_j: proof.auth_j,
            f_i_x_j: proof.shift_query_answers,
        }
    }
}

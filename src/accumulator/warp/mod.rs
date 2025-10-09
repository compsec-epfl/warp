use crate::utils::{poly::eq_poly, DigestToUnitSerialize};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::Field;
use ark_std::log2;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    BytesToUnitSerialize, ProofResult, ProverState, UnitToBytes,
};
use std::marker::PhantomData;
use whir::poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint};

use crate::{linear_code::LinearCode, relations::relation::BundledPESAT};

use super::AccumulationScheme;

mod accumulator;

pub struct WARPConfig {
    l: usize,
}

pub struct WARP<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    _f: PhantomData<F>,
    l: usize,
    p: P,
    code: C,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<
        F: Field,
        P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>, // m, n, k
        C: LinearCode<F> + Clone,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > AccumulationScheme<F, MT> for WARP<F, P, C, MT>
{
    type Index = P;
    type ProverKey = (P, usize, usize, usize);
    type VerifierKey = (usize, usize, usize);
    type Instance = Vec<F>;
    type Witness = Vec<F>;
    type AccumulatorInstance = (MT::InnerDigest, Vec<F>, F, Vec<F>, F); // (rt, \alpha, \mu, \beta, \eta)
    type AccumulatorWitness = (MT, Vec<F>, Vec<F>); // (td, f, w)
    type Proof = F;

    fn index(
        prover_state: &mut ProverState,
        index: Self::Index,
    ) -> ProofResult<(Self::ProverKey, Self::VerifierKey)> {
        let (m, n, k) = index.config();
        // initialize prover state for fs
        prover_state.add_bytes(&index.description())?;
        prover_state.add_scalars(&[F::from(m as u32), F::from(n as u32), F::from(k as u32)])?;
        Ok(((index.clone(), m, n, k), (m, n, k)))
    }

    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Vec<Self::Witness>,
        instances: Vec<Self::Instance>,
        acc_instances: Vec<Self::AccumulatorInstance>,
        acc_witnesses: Vec<Self::AccumulatorWitness>,
    ) -> ProofResult<Self::Proof>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        debug_assert_eq!(witnesses.len(), instances.len());
        debug_assert_eq!(acc_witnesses.len(), acc_instances.len());

        let (l1, l2) = (witnesses.len(), acc_instances.len());
        let l = l1 + l2;

        debug_assert!(l.is_power_of_two());

        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        let (m, n, k) = (pk.1, pk.2, pk.3);
        let (log_m, log_n, log_l) = (log2(m) as usize, log2(n), log2(l) as usize);

        // NOTE: todo()!

        ////////////////////////
        // 2. PESAT Reduction
        ////////////////////////
        let code_length = self.code.code_len();
        let alpha = 0;

        let mut codewords = vec![vec![F::default(); code_length]; self.l];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        let mut codewords_as_leaves = vec![F::default(); self.l * code_length];
        let mut mu = vec![F::default(); self.l];

        // a. encode witnesses and b. evaluation claims
        for i in 0..self.l {
            let f_i = self.code.encode(&witnesses[i]);
            // stacking codewords in flat array, which we chunk below
            // [w_0[0], .., w_{N-1}[0], .., w_0[N-1], .., w_{N-1}[N-1]] // L * N elements
            for (j, value) in f_i.iter().enumerate() {
                codewords_as_leaves[(j * self.l) + i] = *value;
            }
            // evaluate the dense mle for the codeword \hat{f}(alpha) == f[alpha]
            mu[i] = f_i[alpha];
            codewords[i] = f_i;
        }

        let codewords_as_leaves: Vec<&[F]> =
            codewords_as_leaves.chunks_exact(code_length).collect();

        // c. commit to witnesses
        let mt = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            codewords_as_leaves,
        )
        .unwrap();

        // d. absorb commitment and code evaluations
        prover_state.add_digest(mt.root())?;
        prover_state.add_scalars(&mu)?;

        // e. zero check randomness and f. bundled evaluations
        let mut betas = vec![(vec![F::default(); log_m], vec![F::default(); n]); l1];
        let etas = vec![F::zero(); instances.len()];

        for i in 0..l1 {
            let mut tau_i = vec![F::default(); log_m];
            prover_state.fill_challenge_scalars(&mut tau_i)?;
            betas[i] = (tau_i, instances[i].clone()); // bundled evaluations
        }

        ////////////////////////
        // 3. Constrained Code Accumulation
        ////////////////////////
        // a. zero check randomness
        let omega = prover_state.challenge_scalars::<1>()?[0];
        let mut tau = vec![F::default(); log_l];
        prover_state.fill_challenge_scalars(&mut tau)?;

        // b. define [...]

        // c. sumcheck protocol
        let tau_eq_evals = BinaryHypercube::new(log_l)
            .map(|p| eq_poly(&tau, p))
            .collect::<Vec<F>>();

        todo!()
    }

    fn verify() {
        todo!()
    }

    fn decide() {
        todo!()
    }
}

use crate::utils::{poly::eq_poly, DigestToUnitSerialize};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::log2;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    BytesToUnitSerialize, ProofError, ProofResult, ProverState, UnitToBytes, VerifierState,
};
use std::marker::PhantomData;
use whir::poly_utils::hypercube::BinaryHypercube;

use crate::{linear_code::LinearCode, relations::relation::BundledPESAT};

use super::AccumulationScheme;

mod accumulator;

pub struct WARPConfig {
    l: usize,
}

pub struct WARP<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    _f: PhantomData<F>,
    l: usize,
    s: usize,
    t: usize,
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
    type AccumulatorWitness = (MerkleTree<MT>, Vec<F>, Vec<F>); // (td, f, w)
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
        // a. index
        let (m, n, k) = (pk.1, pk.2, pk.3);
        let (log_m, log_n, log_l) = (log2(m) as usize, log2(n) as usize, log2(l) as usize);

        // b. and c. statements and accumulators
        // d. absorb parameters
        instances
            .iter()
            .try_for_each(|x| prover_state.add_scalars(x))?;

        acc_instances
            .iter()
            .try_for_each::<_, Result<(), ProofError>>(|x| {
                prover_state.add_digest(x.0.clone())?; // mt root
                prover_state.add_scalars(&x.1)?; // \alpha
                prover_state.add_scalars(&x.3)?; // \beta
                prover_state.add_scalars(&[x.2, x.4])?; // [\mu, \eta]
                Ok(())
            })?;

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
        let td_0 = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            codewords_as_leaves,
        )
        .unwrap();

        // d. absorb commitment and code evaluations
        prover_state.add_digest(td_0.root())?;
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
        let [omega] = prover_state.challenge_scalars::<1>()?;
        let mut tau = vec![F::default(); log_l];
        prover_state.fill_challenge_scalars(&mut tau)?;

        // b. define [...]

        // c. sumcheck protocol
        let tau_eq_evals = BinaryHypercube::new(log_l)
            .map(|p| eq_poly(&tau, p))
            .collect::<Vec<F>>();

        let fn_f_i = ();

        // e. new oracle and target
        let f = vec![F::zero(); n]; // TODO placeholder
        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);

        // f. new commitment
        let mt_linear_comb = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            &f.chunks(1).collect::<Vec<_>>(),
        )
        .unwrap();

        let eta = F::zero();
        let nu_0 = F::zero();

        // g. absorb new commitment and target
        prover_state.add_digest(mt_linear_comb.root())?;
        prover_state.add_scalars(&[eta, nu_0])?;

        // h. ood samples
        let n_ood_samples = self.s * log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];
        prover_state.fill_challenge_scalars(&mut ood_samples)?;
        let ood_samples = ood_samples.chunks(log_n).collect::<Vec<_>>();

        // i. ood answers
        let ood_answers = ood_samples
            .iter()
            .map(|ood_p| f_hat.fix_variables(ood_p)[0])
            .collect::<Vec<F>>();

        // j. absorb ood answers
        prover_state.add_scalars(&ood_answers)?;

        // k. shift queries and zerocheck randomness
        let (r, log_r) = (1 + self.s + self.t, log2(1 + self.s + self.t) as usize);
        let n_shift_queries = (self.t * log_n).div_ceil(8);
        let mut bytes_shift_queries = vec![0u8; n_shift_queries];
        let mut xi = vec![F::default(); log_r];

        prover_state.fill_challenge_bytes(&mut bytes_shift_queries)?;
        prover_state.fill_challenge_scalars(&mut xi)?;

        // build a vector of tuples where first element is a
        // field element (1 or 0) and the second element equals the first, but as bool.
        let alpha_binary_shift_indexes = bytes_shift_queries
            .iter()
            .flat_map(|x| {
                (0..8)
                    .map(|i| {
                        let val = (x >> i) & 1 == 1;
                        // return in field element and in binary
                        (F::from(val), val)
                    })
                    .collect::<Vec<_>>()
            })
            .take(self.t * log_n)
            .collect::<Vec<(F, bool)>>();

        // l. sumcheck polynomials

        // m. new target
        let alpha = vec![F::default(); log_n];
        let mu = F::default();

        // n. compute authentication paths

        // chunk into log_n arrays whose elements are tuples (F, bool) --
        // F is either 1 or 0 and equals the bool
        // build an index out of it
        let query_index: Vec<usize> = alpha_binary_shift_indexes
            .chunks(log_n)
            .map(|vals| {
                vals.iter()
                    .rev()
                    .fold(0, |acc, &b| (acc << 1) | b.1 as usize)
            })
            .collect();

        let auth_0: Vec<Path<MT>> = query_index
            .iter()
            .map(|x_t| {
                td_0.generate_proof(*x_t)
                    .map_err(|_| ProofError::InvalidProof)
            })
            .collect::<Result<Vec<Path<MT>>, ProofError>>()?;

        let auth: Vec<Vec<Path<MT>>> = acc_witnesses // for each accumulated witness and for each
            // query index, get corresponding auth path
            .iter()
            .map(|(td, _, _)| {
                query_index
                    .iter()
                    .map(|x_t| {
                        td.generate_proof(*x_t)
                            .map_err(|_| ProofError::InvalidProof)
                    })
                    .collect::<Result<Vec<Path<MT>>, ProofError>>()
            })
            .collect::<Result<Vec<Vec<Path<MT>>>, ProofError>>()?;

        todo!()
    }

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        instances: Vec<Self::Instance>,
        acc_instances: Vec<Self::AccumulatorInstance>,
        acc_instance: Self::AccumulatorInstance,
        proof: Self::Proof,
    ) -> ProofResult<()>
    where
        VerifierState<'a>: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. verification key
        let (m, n, k) = (vk.0, vk.1, vk.2);
        // b. and c. instances and accumulators parsing
        // d. final accumulator
        let (rt, alpha, mu, beta, eta) = acc_instance;

        // d. absorb parameters
        instances
            .iter()
            .try_for_each(|x| verifier_state.next_scalars(x))?;

        acc_instances
            .iter()
            .try_for_each::<_, Result<(), ProofError>>(|x| {
                verifier_state.add_digest(x.0.clone())?; // mt root
                verifier_state.add_scalars(&x.1)?; // \alpha
                verifier_state.add_scalars(&x.3)?; // \beta
                verifier_state.add_scalars(&[x.2, x.4])?; // [\mu, \eta]
                Ok(())
            })?;

        ////////////////////////
        // 2. Derive randomness
        ////////////////////////

        todo!()
    }

    fn decide() {
        todo!()
    }
}

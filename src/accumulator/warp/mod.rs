use crate::{
    iors::multilinear_constraint_batching::{MultilinearConstraintBatchingSumcheck, UsizeMap},
    sumcheck::Sumcheck,
    utils::{poly::eq_poly, DigestToUnitDeserialize, DigestToUnitSerialize},
};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::log2;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
    BytesToUnitDeserialize, BytesToUnitSerialize, ProofError, ProofResult, ProverState,
    UnitToBytes, VerifierState,
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
    l1: usize,
    l2: usize,
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

    // (rt_0, \mu_i, \nu_0, \nu_i, auth_0, auth_j, ((f_i(x_j))))
    type Proof = (
        MT::InnerDigest,
        Vec<F>,
        F,
        Vec<F>,
        Vec<Path<MT>>,
        Vec<Vec<Path<MT>>>,
        Vec<Vec<F>>,
    );

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
        assert!(instances.len() > 1);
        debug_assert_eq!(witnesses.len(), instances.len());
        debug_assert_eq!(acc_witnesses.len(), acc_instances.len());

        let (l1, l2, l) = (self.l1, self.l2, self.l);
        debug_assert_eq!(l1 + l2, l);

        debug_assert!(l.is_power_of_two());

        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. index
        let (m, n, k) = (pk.1, pk.2, pk.3);
        let (log_m, log_n, log_l) = (log2(m) as usize, log2(n) as usize, log2(l) as usize);
        debug_assert_eq!(instances[0].len(), n - k);

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

        let mut codewords = vec![vec![F::default(); code_length]; l1];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        let mut codewords_as_leaves = vec![F::default(); l1 * code_length];
        let mut mus = vec![F::default(); l1];

        // a. encode witnesses and b. evaluation claims
        for i in 0..self.l1 {
            let f_i = self.code.encode(&witnesses[i]);
            // stacking codewords in flat array, which we chunk below
            // [w_0[0], .., w_{N-1}[0], .., w_0[N-1], .., w_{N-1}[N-1]] // L * N elements
            for (j, value) in f_i.iter().enumerate() {
                codewords_as_leaves[(j * l1) + i] = *value;
            }
            // evaluate the dense mle for the codeword \hat{f}(alpha) == f[alpha]
            mus[i] = f_i[alpha];
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
        prover_state.add_scalars(&mus)?;

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
        let zeta_0 = vec![F::default(); log_n];
        let nu_0 = f_hat.fix_variables(&zeta_0)[0];

        let mut zetas = vec![zeta_0.as_slice()];
        let mut nus = vec![nu_0];

        // f. new commitment
        let mt_linear_comb = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            &f.chunks(1).collect::<Vec<_>>(),
        )
        .unwrap();

        let eta = F::zero();

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

        zetas.extend(ood_samples);
        nus.extend(ood_answers);

        // k. shift queries and zerocheck randomness
        let (r, log_r) = (1 + self.s + self.t, log2(1 + self.s + self.t) as usize);
        let n_shift_queries = (self.t * log_n).div_ceil(8);
        let mut bytes_shift_queries = vec![0u8; n_shift_queries];
        let mut xi = vec![F::default(); log_r];

        prover_state.fill_challenge_bytes(&mut bytes_shift_queries)?;
        prover_state.fill_challenge_scalars(&mut xi)?;

        // get shift queries as binary field elements
        let binary_shift_queries = bytes_shift_queries
            .iter()
            .flat_map(|x| {
                // TODO factor out
                (0..8)
                    .map(|i| {
                        let val = (x >> i) & 1 == 1;
                        // return in field element and in binary
                        F::from(val)
                    })
                    .collect::<Vec<_>>()
            })
            .take(self.t * log_n)
            .collect::<Vec<F>>();

        let binary_shift_queries = binary_shift_queries.chunks(log_n).collect::<Vec<&[F]>>();

        // build indexes out of the shift queries stored
        let shift_queries_indexes: Vec<usize> = binary_shift_queries
            .iter()
            .map(|vals| {
                vals.iter()
                    .rev()
                    .fold(0, |acc, &b| (acc << 1) | b.is_one() as usize)
            })
            .collect();
        let binary_shift_queries_answers = binary_shift_queries
            .iter()
            .map(|zeta_i| f_hat.fix_variables(zeta_i)[0])
            .collect::<Vec<F>>();

        zetas.extend(binary_shift_queries);
        nus.extend(binary_shift_queries_answers);

        // l. sumcheck polynomials
        // compute evaluations for xi
        let xi_eq_evals = (0..r)
            .map(|i| eq_poly(&xi, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        let ood_evals_vec = (0..1 + self.s)
            .map(|i| {
                (0..r)
                    .map(|a| eq_poly(&zetas[i], BinaryHypercubePoint(a)) * xi_eq_evals[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // [CBBZ23] optimization from hyperplonk
        let mut id_non_0_eval_sums = UsizeMap::default();
        for i in (1 + self.s)..r {
            let a = zetas[i]
                .iter()
                .enumerate()
                .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
                .sum::<usize>();
            *id_non_0_eval_sums.entry(a).or_insert(F::zero()) += &xi_eq_evals[i];
        }

        let alpha = MultilinearConstraintBatchingSumcheck::prove(
            prover_state,
            &mut (f, ood_evals_vec, id_non_0_eval_sums),
            &(),
            log_n,
        )
        .unwrap();

        // m. new target
        let mu = f_hat.fix_variables(&alpha)[0];

        // n. compute authentication paths
        let auth_0: Vec<Path<MT>> = shift_queries_indexes
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
                shift_queries_indexes
                    .iter()
                    .map(|x_t| {
                        td.generate_proof(*x_t)
                            .map_err(|_| ProofError::InvalidProof)
                    })
                    .collect::<Result<Vec<Path<MT>>, ProofError>>()
            })
            .collect::<Result<Vec<Vec<Path<MT>>>, ProofError>>()?;

        let shift_queries_answers = witnesses
            .iter()
            .chain(acc_witnesses.iter().map(|(_, f, _)| f))
            .map(|f| {
                shift_queries_indexes
                    .iter()
                    .map(|x_i| f[*x_i])
                    .collect::<Vec<F>>()
            })
            .collect::<Vec<Vec<F>>>();

        Ok((
            td_0.root(),
            mus,
            nu_0,
            nus,
            auth_0,
            auth,
            shift_queries_answers,
        ))
    }

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: Self::AccumulatorInstance,
        proof: Self::Proof,
    ) -> ProofResult<()>
    where
        VerifierState<'a>: UnitToBytes
            + FieldToUnitDeserialize<F>
            + UnitToField<F>
            + DigestToUnitDeserialize<MT>
            + BytesToUnitDeserialize,
    {
        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. verification key
        let (m, n, k) = (vk.0, vk.1, vk.2);
        let (l1, l2, l) = (self.l1, self.l2, self.l);
        let (log_m, log_n, log_l) = (log2(m) as usize, log2(n) as usize, log2(l) as usize);

        // b. instances parsing
        let instances: Vec<Vec<F>> = (0..l1)
            .map(|_| {
                let mut instance = vec![F::default(); n - k];
                verifier_state.fill_next_scalars(&mut instance);
                instance
            })
            .collect();

        // c. accumulators parsing
        let acc_instances = (0..l2)
            .map(|_| {
                let mut alpha = vec![F::default(); log_n];
                let mut beta = vec![F::default(); log_m + n];
                let mut mu_eta = vec![F::default(); 2];
                let rt = verifier_state.read_digest()?;
                verifier_state.fill_next_scalars(&mut alpha)?;
                verifier_state.fill_next_scalars(&mut beta)?;
                verifier_state.fill_next_scalars(&mut mu_eta)?;
                Ok((rt, alpha, mu_eta[0], beta, mu_eta[1]))
            })
            .collect::<Result<Vec<Self::AccumulatorInstance>, ProofError>>();

        // d. final accumulator
        let (rt, alpha, mu, beta, eta) = acc_instance;

        // d. absorb parameters
        //instances
        //    .iter()
        //    .try_for_each(|x| verifier_state.fill_next_scalars(output)?;

        //acc_instances
        //    .iter()
        //    .try_for_each::<_, Result<(), ProofError>>(|x| {
        //        verifier_state.add_digest(x.0.clone())?; // mt root
        //        verifier_state.add_scalars(&x.1)?; // \alpha
        //        verifier_state.add_scalars(&x.3)?; // \beta
        //        verifier_state.add_scalars(&[x.2, x.4])?; // [\mu, \eta]
        //        Ok(())
        //    })?;

        ////////////////////////
        // 2. Derive randomness
        ////////////////////////

        todo!()
    }

    fn decide() {
        todo!()
    }
}

use crate::{
    concat_slices,
    iors::{
        multilinear_constraint_batching::{MultilinearConstraintBatchingSumcheck, UsizeMap},
        twin_constraint_pseudo_batching::{Evals, TwinConstraintPseudoBatchingSumcheck},
    },
    relations::r1cs::R1CSConstraints,
    sumcheck::Sumcheck,
    utils::{
        poly::{eq_poly, eq_poly_non_binary},
        DigestToUnitDeserialize, DigestToUnitSerialize,
    },
    WARPError,
};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree, Path},
    Error,
};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, DenseMultilinearExtension, DenseUVPolynomial,
    MultilinearExtension, Polynomial,
};
use ark_std::log2;
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitDeserialize, FieldToUnitSerialize, UnitToField},
    BytesToUnitDeserialize, BytesToUnitSerialize, ProofError, ProofResult, ProverState,
    UnitToBytes, VerifierState,
};
use std::marker::PhantomData;
use whir::poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint};

use crate::{linear_code::LinearCode, relations::BundledPESAT};

use super::AccumulationScheme;

#[derive(Clone)]
pub struct WARPConfig<F: Field, P: BundledPESAT<F>> {
    pub l: usize,
    pub l1: usize,
    pub s: usize,
    pub t: usize,
    pub p_conf: P::Config,
    pub n: usize,
}

impl<F: Field, P: BundledPESAT<F>> WARPConfig<F, P> {
    pub fn new(l: usize, l1: usize, s: usize, t: usize, p_conf: P::Config, n: usize) -> Self {
        Self {
            l,
            l1,
            s,
            t,
            p_conf,
            n,
        }
    }
}

pub struct WARP<F: Field, P: BundledPESAT<F>, C: LinearCode<F> + Clone, MT: Config> {
    _f: PhantomData<F>,
    config: WARPConfig<F, P>,
    code: C,
    p: P,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<
        F: Field,
        P: Clone + BundledPESAT<F, Config = (usize, usize, usize)>, // m, n, k
        C: LinearCode<F> + Clone,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > WARP<F, P, C, MT>
{
    pub fn new(
        config: WARPConfig<F, P>,
        code: C,
        p: P,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> WARP<F, P, C, MT> {
        Self {
            _f: PhantomData,
            config,
            code,
            p,
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
        }
    }
}

impl<
        F: Field + PrimeField,
        P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>, // m, n, k
        C: LinearCode<F> + Clone,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > AccumulationScheme<F, MT> for WARP<F, P, C, MT>
{
    type Index = P;
    type ProverKey = (P, usize, usize, usize);
    type VerifierKey = (usize, usize, usize);
    type Instances = Vec<Vec<F>>;
    type Witnesses = Vec<Vec<F>>;
    type AccumulatorInstances = (
        Vec<MT::InnerDigest>,
        Vec<Vec<F>>,
        Vec<F>,
        (Vec<Vec<F>>, Vec<Vec<F>>),
        Vec<F>,
    ); // (rt, \alpha, \mu, \beta (\tau, x), \eta)
    type AccumulatorWitnesses = (Vec<MerkleTree<MT>>, Vec<Vec<F>>, Vec<Vec<F>>); // (td, f, w)

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
        // TODO for R1CS
        prover_state.add_bytes(&index.description())?;
        prover_state.add_scalars(&[F::from(m as u32), F::from(n as u32), F::from(k as u32)])?;
        Ok(((index.clone(), m, n, k), (m, n, k)))
    }

    fn prove(
        &self,
        pk: Self::ProverKey,
        prover_state: &mut ProverState,
        witnesses: Self::Witnesses,
        instances: Self::Instances,
        acc_instances: Self::AccumulatorInstances,
        acc_witnesses: Self::AccumulatorWitnesses,
    ) -> Result<
        (
            (Self::AccumulatorInstances, Self::AccumulatorWitnesses),
            Self::Proof,
        ),
        WARPError,
    >
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        debug_assert!(instances.len() > 1);
        debug_assert_eq!(witnesses.len(), instances.len());
        debug_assert_eq!(acc_witnesses.0.len(), acc_instances.0.len());

        let (l1, l) = (self.config.l1, self.config.l);
        let l2 = l - l1;
        debug_assert_eq!(l1 + l2, l);

        debug_assert!(l.is_power_of_two());

        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. index
        #[allow(non_snake_case)]
        let (M, N, k) = (pk.1, pk.2, pk.3);
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);

        debug_assert_eq!(instances[0].len(), N - k);

        // b. and c. statements and accumulators
        // d. absorb parameters
        instances
            .iter()
            .try_for_each(|x| prover_state.add_scalars(x))?;

        // roots
        acc_instances
            .0
            .clone()
            .into_iter()
            .try_for_each(|digest| prover_state.add_digest(digest))?;

        // alpha
        acc_instances
            .1
            .iter()
            .try_for_each(|alpha| prover_state.add_scalars(alpha))?;

        // mu
        prover_state.add_scalars(&acc_instances.2)?;

        //// taus
        acc_instances
            .3
             .0
            .iter()
            .try_for_each(|tau| prover_state.add_scalars(tau))?;

        //// xs
        acc_instances
            .3
             .1
            .iter()
            .try_for_each(|x| prover_state.add_scalars(x))?;

        //// etas
        prover_state.add_scalars(&acc_instances.4)?;

        ////////////////////////
        // 2. PESAT Reduction
        ////////////////////////
        let n = self.code.code_len();
        let log_n = log2(n) as usize;

        let alpha = 0;

        let mut codewords = vec![vec![F::default(); n]; l1];

        // we "stack" codewords to make a single merkle commitment over alphabet \mathbb{F}^{L}
        let mut codewords_as_leaves = vec![F::default(); l1 * n];
        let mut mus = vec![F::default(); l1];

        // a. encode witnesses and b. evaluation claims
        for i in 0..l1 {
            let f_i = self.code.encode(&witnesses[i]);
            // stacking codewords in flat array, which we chunk below
            // [[w_0[0], .., w_{N-1}[0]], .., [w_0[N-1], .., w_{N-1}[N-1]]] // L * N elements
            for (j, value) in f_i.iter().enumerate() {
                codewords_as_leaves[(j * l1) + i] = *value;
            }
            // evaluate the dense mle for the codeword \hat{f}(alpha) == f[alpha]
            mus[i] = f_i[alpha];
            codewords[i] = f_i;
        }

        let codewords_as_leaves: Vec<&[F]> = codewords_as_leaves.chunks_exact(l1).collect();

        // c. commit to witnesses
        let td_0 = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            codewords_as_leaves,
        )?;

        // d. absorb commitment and code evaluations
        prover_state.add_digest(td_0.root())?;
        prover_state.add_scalars(&mus)?;

        // e. zero check randomness and f. bundled evaluations
        let mut taus = vec![vec![F::default(); log_M]; l1];

        for tau in taus.iter_mut().take(l1) {
            let mut tau_i = vec![F::default(); log_M];
            prover_state.fill_challenge_scalars(&mut tau_i)?;
            *tau = tau_i; // bundled evaluations
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

        let alpha_vecs = concat_slices(&acc_instances.1, &vec![vec![F::zero(); log_n]; l1]);

        let z_vecs: Vec<Vec<F>> = acc_instances
            .3
             .1
            .iter()
            .zip(&acc_witnesses.2)
            .chain(instances.iter().zip(&witnesses))
            .map(|(x, w)| concat_slices(x, w))
            .collect();

        let beta_vecs: Vec<Vec<F>> = acc_instances.3 .0.into_iter().chain(taus).collect();

        // TODO: remove this clone()
        let all_codewords: Vec<Vec<F>> = acc_witnesses
            .1
            .clone()
            .into_iter()
            .chain(codewords.clone())
            .collect();

        let mut evals = Evals::new(
            all_codewords.clone(),
            z_vecs,
            alpha_vecs,
            beta_vecs,
            tau_eq_evals,
        );

        let gamma = TwinConstraintPseudoBatchingSumcheck::prove(
            prover_state,
            &mut evals,
            &(self.p.constraints(), omega),
            log_l,
        )?;

        debug_assert_eq!(gamma.len(), log_l);

        // e. new oracle and target
        let (f, z, zeta_0, beta_tau) = evals.get_last_evals()?;

        // eval the bundled r1cs
        let beta_eq_evals = (0..M)
            .map(|i| eq_poly(&beta_tau, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        let eta = self
            .p
            .evaluate_bundled(&beta_eq_evals, &z)
            .map_err(|_| ProofError::InvalidProof)?;

        let (x, w) = z.split_at(N - k);
        let beta = (vec![beta_tau], vec![x.to_vec()]);
        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);
        let nu_0 = f_hat.fix_variables(&zeta_0)[0];

        // f. new commitment
        let td = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            f.chunks(1).collect::<Vec<_>>(),
        )?;

        // g. absorb new commitment and target
        prover_state.add_digest(td.root())?;
        prover_state.add_scalars(&[eta, nu_0])?;

        // h. ood samples
        let n_ood_samples = self.config.s * log_n;
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

        let mut zetas = vec![zeta_0.as_slice()];
        let mut nus = vec![nu_0];
        zetas.extend(ood_samples);
        nus.extend(ood_answers);

        // k. shift queries and zerocheck randomness
        let r = 1 + self.config.s + self.config.t;
        let log_r = log2(r) as usize;
        let n_shift_queries = (self.config.t * log_n).div_ceil(8);
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
            .take(self.config.t * log_n)
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

        let ood_evals_vec = (0..1 + self.config.s)
            .map(|i| {
                (0..n)
                    .map(|a| eq_poly(zetas[i], BinaryHypercubePoint(a)) * xi_eq_evals[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // [CBBZ23] optimization from hyperplonk
        let mut id_non_0_eval_sums = UsizeMap::default();
        for i in 1 + self.config.s..r {
            let a = zetas[i]
                .iter()
                .enumerate()
                .filter_map(|(j, bit)| bit.is_one().then_some(1 << j))
                .sum::<usize>();
            *id_non_0_eval_sums.entry(a).or_insert(F::zero()) += &xi_eq_evals[i];
        }

        let alpha = MultilinearConstraintBatchingSumcheck::prove(
            prover_state,
            &mut (f.clone(), ood_evals_vec, id_non_0_eval_sums),
            &(),
            log_n,
        )?;

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

        let auth: Vec<Vec<Path<MT>>> = acc_witnesses
            .0 // for each accumulated witness and for each
            // query index, get corresponding auth path
            .iter()
            .map(|td| {
                shift_queries_indexes
                    .iter()
                    .map(|x_t| td.generate_proof(*x_t))
                    .collect::<Result<Vec<Path<MT>>, Error>>()
            })
            .collect::<Result<Vec<Vec<Path<MT>>>, Error>>()?;

        let shift_queries_answers = shift_queries_indexes
            .iter()
            .map(|idx| all_codewords.iter().map(|f| f[*idx]).collect::<Vec<F>>())
            .collect::<Vec<Vec<F>>>();

        let acc_instance = (vec![td.root()], vec![alpha], vec![mu], beta, vec![eta]);
        let acc_witness = (vec![td], vec![f], vec![w.to_vec()]);

        // 4. return
        Ok((
            (acc_instance, acc_witness),
            (
                td_0.root(),
                mus,
                nu_0,
                nus,
                auth_0,
                auth,
                shift_queries_answers,
            ),
        ))
    }

    fn verify<'a>(
        &self,
        vk: Self::VerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: Self::AccumulatorInstances,
        proof: Self::Proof,
    ) -> Result<(), WARPError>
    where
        VerifierState<'a>: UnitToBytes
            + FieldToUnitDeserialize<F>
            + UnitToField<F>
            + DigestToUnitDeserialize<MT>
            + BytesToUnitDeserialize,
    {
        let (l1, l) = (self.config.l1, self.config.l);
        let l2 = l - l1;

        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. verification key
        #[allow(non_snake_case)]
        let (M, N, k) = (vk.0, vk.1, vk.2);
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);

        let n = self.code.code_len();
        let log_n = log2(n) as usize;

        // f. absorb parameters
        let mut l1_xs = vec![vec![F::default(); N - k]; l1];
        l1_xs
            .iter_mut()
            .try_for_each(|inst| verifier_state.fill_next_scalars(inst))?;

        // l2 instances
        let l2_roots = (0..l2)
            .map(|_| verifier_state.read_digest())
            .collect::<Result<Vec<MT::InnerDigest>, ProofError>>()?;

        let mut l2_alphas = vec![vec![F::default(); log_n]; l2];
        l2_alphas
            .iter_mut()
            .try_for_each(|alpha| verifier_state.fill_next_scalars(alpha))?;

        let mut l2_mus = vec![F::default(); l2];
        verifier_state.fill_next_scalars(&mut l2_mus)?;

        let mut l2_taus = vec![vec![F::default(); log_M]; l2];
        l2_taus
            .iter_mut()
            .try_for_each(|tau| verifier_state.fill_next_scalars(tau))?;

        let mut l2_xs = vec![vec![F::default(); N - k]; l2];
        l2_xs
            .iter_mut()
            .try_for_each(|x| verifier_state.fill_next_scalars(x))?;

        let mut l2_etas = vec![F::default(); l2];
        verifier_state.fill_next_scalars(&mut l2_etas)?;

        ////////////////////////
        // 2. Derive randomness
        ////////////////////////
        let rt_0 = verifier_state.read_digest()?;
        let mut l1_mus = vec![F::default(); l1];
        verifier_state.fill_next_scalars(&mut l1_mus)?;

        let mut l1_taus = vec![vec![F::default(); log_M]; l1];

        for l1_tau in l1_taus.iter_mut().take(l1) {
            let mut tau_i = vec![F::default(); log_M];
            verifier_state.fill_challenge_scalars(&mut tau_i)?;
            *l1_tau = tau_i; // bundled evaluations
        }

        let [omega] = verifier_state.challenge_scalars::<1>()?;
        let mut tau = vec![F::default(); log_l];
        verifier_state.fill_challenge_scalars(&mut tau)?;

        // e. twin constraints sumcheck
        let mut gamma_sumcheck = Vec::new();
        let mut coeffs_twinc_sumcheck = Vec::new();
        for _ in 0..log_l {
            let mut h_coeffs = vec![F::zero(); 2 + (log_n + 1).max(log_M + 2) as usize];
            verifier_state.fill_next_scalars(&mut h_coeffs)?;
            let [c] = verifier_state.challenge_scalars::<1>()?;
            gamma_sumcheck.push(c);
            coeffs_twinc_sumcheck.push(h_coeffs);
        }

        let _td = verifier_state.read_digest();
        let [eta, nu_0] = verifier_state.next_scalars::<2>()?;
        let mut nus = vec![nu_0];

        // g. ood samples
        let n_ood_samples = self.config.s * log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];
        verifier_state.fill_challenge_scalars(&mut ood_samples)?;
        let ood_samples = ood_samples.chunks(log_n).collect::<Vec<_>>();

        // h. ood answers
        let mut ood_answers = vec![F::default(); self.config.s];
        verifier_state.fill_next_scalars(&mut ood_answers)?;
        nus.extend(ood_answers);

        // i. shift queries and zero check
        let r = 1 + self.config.s + self.config.t;
        let log_r = log2(r) as usize;
        let n_shift_queries = (self.config.t * log_n).div_ceil(8);
        let mut bytes_shift_queries = vec![0u8; n_shift_queries];
        let mut xi = vec![F::default(); log_r];
        verifier_state.fill_challenge_bytes(&mut bytes_shift_queries)?;
        verifier_state.fill_challenge_scalars(&mut xi)?;

        // j. batching sumcheck
        let mut alpha_sumcheck = Vec::new();
        let mut sums_batching_sumcheck = Vec::new();
        for _ in 0..log_n {
            let [sum_00, sum_11, sum_0110]: [F; 3] = verifier_state.next_scalars()?;
            let [c] = verifier_state.challenge_scalars::<1>()?;
            alpha_sumcheck.push(c);
            sums_batching_sumcheck.push([sum_00, sum_11, sum_0110]);
        }

        ////////////////////////
        // 3. Derive values
        ////////////////////////
        // b.
        let alpha_vecs = concat_slices(&l2_alphas, &vec![vec![F::zero(); log_n]; l1]);
        let gamma_eq_evals = BinaryHypercube::new(log_l)
            .map(|p| eq_poly(&gamma_sumcheck, p))
            .collect::<Vec<F>>();
        let zeta_0 = scale_and_sum(&alpha_vecs, &gamma_eq_evals);

        // compute \eta_{s + k}
        let mut nu_s_t = vec![F::default(); self.config.t];
        for (i, v_jk) in proof.6.iter().enumerate() {
            let res = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(F::zero(), |acc, (v, eq)| acc + *eq * *v);
            nu_s_t[i] = res;
        }

        nus.extend(nu_s_t);

        // d. set \sigma^{(1)} and \sigma^{(2)}
        // compute eq(\tau, i) and eq(\xi, i)
        let tau_eq_evals = BinaryHypercube::new(log_l)
            .map(|p| eq_poly(&tau, p))
            .collect::<Vec<F>>();
        let etas = concat_slices(&l2_etas, &vec![F::zero(); l1]);

        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(l2_mus.into_iter().chain(l1_mus.to_vec()).zip(etas))
            .fold(F::zero(), |acc, (eq_tau, (mu, eta))| {
                acc + eq_tau * (mu + omega * eta)
            });

        let xi_eq_evals = BinaryHypercube::new(log_r)
            .map(|p| eq_poly(&xi, p))
            .collect::<Vec<F>>();

        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&nus)
            .fold(F::zero(), |acc, (xi_eq, nu)| acc + *xi_eq * nu);

        ////////////////////////
        // 4. Decision phase
        ////////////////////////
        // a. new code evaluation point
        assert!(acc_instance.1[0]
            .iter()
            .zip(alpha_sumcheck.clone())
            .fold(true, |acc, (a_x, a_i)| acc & (*a_x == a_i)));

        // b. new circuit evaluation point
        let betas = l2_taus
            .into_iter()
            .chain(l1_taus)
            .zip(l2_xs.clone().into_iter().chain(l1_xs))
            .map(|(tau, x)| concat_slices(&tau, &x))
            .collect::<Vec<Vec<F>>>();
        let _beta = scale_and_sum(&betas, &gamma_eq_evals);

        // c. check auth paths
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
            .take(self.config.t * log_n)
            .collect::<Vec<F>>();

        let binary_shift_queries = binary_shift_queries.chunks(log_n).collect::<Vec<&[F]>>();

        let shift_queries_indexes: Vec<usize> = binary_shift_queries
            .iter()
            .map(|vals| {
                vals.iter()
                    .rev()
                    .fold(0, |acc, &b| (acc << 1) | b.is_one() as usize)
            })
            .collect();

        // check:
        // that the leaf index corresponds to the shift query
        // that the path is correct
        assert_eq!(proof.6.len(), self.config.t);
        // proof.4 is auth_0
        for (i, path) in proof.4.iter().enumerate() {
            assert_eq!(path.leaf_index, shift_queries_indexes[i]);
            let is_valid = path.verify(
                &self.mt_leaf_hash_params,
                &self.mt_two_to_one_hash_params,
                &rt_0,
                &proof.6[i][l2..], // leaves are evaluations of the l1 codewords
            )?;
            assert!(is_valid);
        }

        // proof.5 holds merkle proofs for l2 accumulated instances
        assert_eq!(proof.5.len(), l2);
        for (i, paths) in proof.5.iter().enumerate() {
            assert_eq!(paths.len(), self.config.t);
            let root = &l2_roots[i];
            for (j, path) in paths.iter().enumerate() {
                assert_eq!(path.leaf_index, shift_queries_indexes[j]);
                let is_valid = path.verify(
                    &self.mt_leaf_hash_params,
                    &self.mt_two_to_one_hash_params,
                    root,
                    [proof.6[j][i]], // proof.6[j][i] holds f_i(x_j)
                )?;
                assert!(is_valid);
            }
        }

        // d. sumcheck decisions
        // twin constraints sumcheck
        assert_eq!(coeffs_twinc_sumcheck.len(), log_l);
        let mut target_1 = sigma_1;
        for (coeffs, gamma) in coeffs_twinc_sumcheck.into_iter().zip(&gamma_sumcheck) {
            let h = DensePolynomial::from_coefficients_vec(coeffs);
            assert_eq!(h.evaluate(&F::one()) + h.evaluate(&F::zero()), target_1);
            target_1 = h.evaluate(gamma);
        }

        // multilinear batching sumcheck
        assert_eq!(sums_batching_sumcheck.len(), log_n);
        let mut target_2 = sigma_2;
        for ([sum_00, sum_11, sum_0110], alpha) in
            sums_batching_sumcheck.into_iter().zip(&alpha_sumcheck)
        {
            assert_eq!(sum_00 + sum_11, target_2);
            target_2 = (target_2 - sum_0110) * alpha.square()
                + sum_00 * (F::one() - alpha.double())
                + sum_0110 * alpha;
        }

        // e. new target decision
        // build eq^{\star}(\alpha)
        assert_eq!(
            eq_poly_non_binary(&tau, &gamma_sumcheck) * (nus[0] + omega * eta),
            target_1
        );

        let mut zeta_eqs = vec![eq_poly_non_binary(&zeta_0, &alpha_sumcheck)];

        zeta_eqs.extend(
            ood_samples
                .into_iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck))
                .collect::<Vec<F>>(),
        );
        zeta_eqs.extend(
            binary_shift_queries
                .iter()
                .map(|zeta| eq_poly_non_binary(zeta, &alpha_sumcheck))
                .collect::<Vec<F>>(),
        );
        assert_eq!(zeta_eqs.len(), r);

        // mul by \mu and compare to target_2
        assert_eq!(
            acc_instance.2[0]
                * zeta_eqs
                    .into_iter()
                    .zip(xi_eq_evals)
                    .fold(F::zero(), |acc, (a, b)| acc + a * b),
            target_2
        );

        Ok(())
    }

    fn decide(
        &self,
        acc_witness: Self::AccumulatorWitnesses,
        acc_instance: Self::AccumulatorInstances,
    ) -> Result<(), WARPError> {
        let (_td, f, w) = acc_witness;
        let (rt, alpha, mu, beta, eta) = acc_instance;

        let computed_td = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            f[0].chunks(1).collect::<Vec<_>>(),
        )?;
        assert_eq!(rt[0], computed_td.root());
        // TODO? assert_eq!(td[0], computed_td);

        let f_hat = DenseMultilinearExtension::from_evaluations_slice(
            log2(self.code.code_len()) as usize,
            &f[0],
        );
        assert_eq!(f_hat.evaluate(&alpha[0]), mu[0]);

        let tau = &beta.0[0];

        let tau_zero_evader = BinaryHypercube::new(tau.len())
            .map(|p| eq_poly(tau, p))
            .collect::<Vec<F>>();

        let mut z = beta.1[0].clone();
        z.extend(w[0].clone());
        let computed_eta = self.p.evaluate_bundled(&tau_zero_evader, &z).unwrap();
        assert_eq!(computed_eta, eta[0]);

        let computed_f = self.code.encode(&w[0]);
        assert_eq!(f[0], computed_f);

        Ok(())
    }
}

fn scale_and_sum<F: Field>(vectors: &[Vec<F>], scalars: &[F]) -> Vec<F> {
    let n = vectors[0].len();
    let mut result = vec![F::default(); n];

    vectors.iter().zip(scalars).for_each(|(v, &a)| {
        result.iter_mut().zip(v).for_each(|(r, &x)| *r += a * x);
    });

    result
}

#[cfg(test)]
pub mod tests {
    use std::marker::PhantomData;

    use crate::{
        accumulator::AccumulationScheme,
        domainsep::WARPDomainSeparator,
        linear_code::{LinearCode, ReedSolomon, ReedSolomonConfig},
        relations::{
            r1cs::{
                hashchain::{
                    compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness,
                },
                R1CS,
            },
            BundledPESAT, Relation, ToPolySystem,
        },
        utils::poseidon,
    };
    use ark_bls12_381::Fr as BLS12_381;
    use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
    use ark_ff::UniformRand;
    use rand::thread_rng;
    use spongefish::DomainSeparator;
    use whir::crypto::merkle_tree::blake3::Blake3MerkleTreeParams;

    use super::{WARPConfig, WARP};

    #[test]
    pub fn warp_test() {
        let l1 = 4;
        let s = 8;
        let t = 7;
        let hash_chain_size = 10;
        let mut rng = thread_rng();
        let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
        let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::into_r1cs(&(
            poseidon_config.clone(),
            hash_chain_size,
        ))
        .unwrap();
        let code_config =
            ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config);

        let instances_witnesses: (Vec<Vec<BLS12_381>>, Vec<Vec<BLS12_381>>) = (0..l1)
            .map(|_| {
                let preimage = vec![BLS12_381::rand(&mut rng)];
                let instance = HashChainInstance {
                    digest: compute_hash_chain::<BLS12_381, CRH<_>>(
                        &poseidon_config,
                        &preimage,
                        hash_chain_size,
                    ),
                };
                let witness = HashChainWitness {
                    preimage,
                    _crhs_scheme: PhantomData::<CRH<BLS12_381>>,
                };
                let relation = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::new(
                    instance,
                    witness,
                    (poseidon_config.clone(), hash_chain_size),
                );
                (relation.x, relation.w)
            })
            .unzip();

        let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::into_r1cs(&(
            poseidon_config.clone(),
            hash_chain_size,
        ))
        .unwrap();

        let warp_config = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
        let hash_chain_warp = WARP::<
            BLS12_381,
            R1CS<BLS12_381>,
            _,
            Blake3MerkleTreeParams<BLS12_381>,
        >::new(
            warp_config.clone(), code.clone(), r1cs.clone(), (), ()
        );

        let (mut acc_roots, mut acc_alphas, mut acc_mus, mut acc_taus, mut acc_xs, mut acc_eta) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        let (mut acc_tds, mut acc_f, mut acc_ws) = (vec![], vec![], vec![]);

        for _ in 0..l1 {
            let domainsep = DomainSeparator::new("test::warp");

            let domainsep = WARPDomainSeparator::<
                BLS12_381,
                ReedSolomon<BLS12_381>,
                Blake3MerkleTreeParams<BLS12_381>,
            >::warp(domainsep, warp_config.clone());
            let mut prover_state = domainsep.to_prover_state();
            let ((acc_x, acc_w), pf) = hash_chain_warp
                .prove(
                    (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                    &mut prover_state,
                    instances_witnesses.1.clone(),
                    instances_witnesses.0.clone(),
                    (vec![], vec![], vec![], (vec![], vec![]), vec![]),
                    (vec![], vec![], vec![]),
                )
                .unwrap();
            acc_roots.push(acc_x.0[0].clone());
            acc_alphas.push(acc_x.1[0].clone());
            acc_mus.push(acc_x.2[0]);
            acc_taus.push(acc_x.3 .0[0].clone());
            acc_xs.push(acc_x.3 .1[0].clone());
            acc_eta.push(acc_x.4[0]);

            acc_tds.push(acc_w.0[0].clone());
            acc_f.push(acc_w.1[0].clone());
            acc_ws.push(acc_w.2[0].clone());
        }

        let domainsep = DomainSeparator::new("test::warp");
        let warp_config =
            WARPConfig::<_, R1CS<BLS12_381>>::new(8, l1, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp = WARP::<
            BLS12_381,
            R1CS<BLS12_381>,
            _,
            Blake3MerkleTreeParams<BLS12_381>,
        >::new(
            warp_config.clone(), code.clone(), r1cs.clone(), (), ()
        );
        let domainsep = WARPDomainSeparator::<
            BLS12_381,
            ReedSolomon<BLS12_381>,
            Blake3MerkleTreeParams<BLS12_381>,
        >::warp(domainsep, warp_config);

        let mut prover_state = domainsep.to_prover_state();
        let ((acc_x, acc_w), pf) = hash_chain_warp
            .prove(
                (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                &mut prover_state,
                instances_witnesses.1,
                instances_witnesses.0,
                (acc_roots, acc_alphas, acc_mus, (acc_taus, acc_xs), acc_eta),
                (acc_tds, acc_f, acc_ws),
            )
            .unwrap();

        let narg_str = prover_state.narg_string();
        let mut verifier_state = domainsep.to_verifier_state(narg_str);
        hash_chain_warp
            .verify(
                (r1cs.m, r1cs.n, r1cs.k),
                &mut verifier_state,
                acc_x.clone(),
                pf,
            )
            .unwrap();
        hash_chain_warp.decide(acc_w, acc_x).unwrap();
    }
}

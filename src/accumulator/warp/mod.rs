use crate::{
    iors::{
        multilinear_constraint_batching::{MultilinearConstraintBatchingSumcheck, UsizeMap},
        twin_constraint_pseudo_batching::{Evals, TwinConstraintPseudoBatchingSumcheck},
    },
    relations::r1cs::{R1CSConstraints, R1CS},
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
        F: Field,
        P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>, // m, n, k
        C: LinearCode<F> + Clone,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > AccumulationScheme<F, MT> for WARP<F, P, C, MT>
{
    type Index = P;
    type ProverKey = (P, usize, usize, usize);
    type VerifierKey = (usize, usize, usize);
    type Instance = Vec<F>;
    type Witness = Vec<F>;
    type AccumulatorInstance = (MT::InnerDigest, Vec<F>, F, (Vec<F>, Vec<F>), F); // (rt, \alpha, \mu, \beta (\tau, x), \eta)
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
        // TODO for R1CS
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
    ) -> ProofResult<(
        (Self::AccumulatorInstance, Self::AccumulatorWitness),
        Self::Proof,
    )>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        debug_assert!(instances.len() > 1);
        debug_assert_eq!(witnesses.len(), instances.len());
        debug_assert_eq!(acc_witnesses.len(), acc_instances.len());

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

        acc_instances
            .iter()
            .try_for_each::<_, Result<(), ProofError>>(|x| {
                prover_state.add_digest(x.0.clone())?; // mt root
                prover_state.add_scalars(&x.1)?; // \alpha
                prover_state.add_scalars(&(x.3).0)?; // \beta.tau
                prover_state.add_scalars(&(x.3).1)?; // \beta.x
                prover_state.add_scalars(&[x.2, x.4])?; // [\mu, \eta]
                Ok(())
            })?;

        #[cfg(test)]
        println!("1. Parsing done");

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
        )
        .unwrap();

        #[cfg(test)]
        println!("2.c committing to witness done");

        // d. absorb commitment and code evaluations
        prover_state.add_digest(td_0.root())?;
        prover_state.add_scalars(&mus)?;

        // e. zero check randomness and f. bundled evaluations
        let mut betas = vec![(vec![F::default(); log_M], vec![F::default(); N]); l1];
        let etas = vec![F::zero(); instances.len()];

        for i in 0..l1 {
            let mut tau_i = vec![F::default(); log_M];
            prover_state.fill_challenge_scalars(&mut tau_i)?;
            betas[i] = (tau_i, instances[i].clone()); // bundled evaluations
        }

        #[cfg(test)]
        println!("2. PESAT reduction done");

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

        // TODO: add l2 instances
        // TODO: remove all `clone()` calls
        let z_vecs = instances
            .iter()
            .zip(witnesses)
            .map(|(x, w)| [&x[..], &w].concat())
            .collect();
        let beta_vecs = betas.into_iter().map(|(beta, _)| beta.clone()).collect();
        let alpha_vecs = vec![vec![F::zero(); log_n]; l1];
        let mut evals = Evals::new(
            codewords.clone(),
            z_vecs,
            alpha_vecs,
            beta_vecs,
            tau_eq_evals,
        );

        #[cfg(test)]
        println!("starting pseudo batching sumcheck");
        let gamma = TwinConstraintPseudoBatchingSumcheck::prove(
            prover_state,
            &mut evals,
            &(self.p.constraints(), omega),
            log_l,
        )
        .unwrap();

        debug_assert_eq!(gamma.len(), log_l);

        let fn_f_i = ();

        // e. new oracle and target
        let f = vec![F::one(); n]; // TODO placeholder
        let w = vec![F::zero(); k];
        let beta = (vec![F::zero(); log_M], vec![F::zero(); N]);
        let f_hat = DenseMultilinearExtension::from_evaluations_slice(log_n, &f);
        let zeta_0 = vec![F::default(); log_n];
        let nu_0 = f_hat.fix_variables(&zeta_0)[0];
        let eta = F::zero();

        #[cfg(test)]
        println!("3.e done");

        // f. new commitment
        let td = MerkleTree::<MT>::new(
            &self.mt_leaf_hash_params,
            &self.mt_two_to_one_hash_params,
            &f.chunks(1).collect::<Vec<_>>(),
        )
        .unwrap();

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

        #[cfg(test)]
        println!("3.i done");

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
                    .map(|a| eq_poly(&zetas[i], BinaryHypercubePoint(a)) * xi_eq_evals[i])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        #[cfg(test)]
        println!("3.l done");

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

        #[cfg(test)]
        println!("3. starting sumcheck");

        let alpha = MultilinearConstraintBatchingSumcheck::prove(
            prover_state,
            &mut (f.clone(), ood_evals_vec, id_non_0_eval_sums),
            &(),
            log_n,
        )
        .unwrap();

        #[cfg(test)]
        println!("3.l sumcheck done");

        // m. new target
        let mu = f_hat.fix_variables(&alpha)[0];

        #[cfg(test)]
        println!("3.m new target done");

        // n. compute authentication paths
        let auth_0: Vec<Path<MT>> = shift_queries_indexes
            .iter()
            .map(|x_t| {
                td_0.generate_proof(*x_t)
                    .map_err(|_| ProofError::InvalidProof)
            })
            .collect::<Result<Vec<Path<MT>>, ProofError>>()?;

        #[cfg(test)]
        println!("3.n auth0 done");

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

        #[cfg(test)]
        println!("3.n auth done");
        let shift_queries_answers = codewords
            .iter()
            .chain(acc_witnesses.iter().map(|(_, f, _)| f))
            .map(|f| {
                shift_queries_indexes
                    .iter()
                    .map(|x_i| f[*x_i])
                    .collect::<Vec<F>>()
            })
            .collect::<Vec<Vec<F>>>();

        #[cfg(test)]
        println!("3. computed evaluations for f");

        let acc_instance = (td.root(), alpha, mu, beta, eta);
        let acc_witness = (td, f, w);

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
        let (l1, l) = (self.config.l1, self.config.l);
        let l2 = l - l1;
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
        //let acc_instances = (0..l2)
        //    .map(|_| {
        //        let mut alpha = vec![F::default(); log_n];
        //        let mut beta = vec![F::default(); log_m + n];
        //        let mut mu_eta = vec![F::default(); 2];
        //        let rt = verifier_state.read_digest()?;
        //        verifier_state.fill_next_scalars(&mut alpha)?;
        //        verifier_state.fill_next_scalars(&mut beta)?;
        //        verifier_state.fill_next_scalars(&mut mu_eta)?;
        //        Ok((rt, alpha, mu_eta[0], beta, mu_eta[1]))
        //    })
        //    .collect::<Result<Vec<Self::AccumulatorInstance>, ProofError>>();

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
            relation::{BundledPESAT, ToPolySystem},
            Relation,
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

        let domainsep = DomainSeparator::new("test::warp");

        let domainsep = WARPDomainSeparator::<
            BLS12_381,
            ReedSolomon<BLS12_381>,
            Blake3MerkleTreeParams<BLS12_381>,
        >::warp(domainsep, warp_config);
        let mut prover_state = domainsep.to_prover_state();

        let pf = hash_chain_warp
            .prove(
                (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                &mut prover_state,
                instances_witnesses.1,
                instances_witnesses.0,
                vec![],
                vec![],
            )
            .unwrap();
    }
}

use crate::utils::DigestToUnitSerialize;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    ProofResult, ProverState, Unit as SpongefishUnit,
};
use std::marker::PhantomData;

use crate::{
    iors::IOR,
    linear_code::{LinearCode, MultiConstrainedLinearCode},
    relations::relation::BundledPESAT,
};

use spongefish::UnitToBytes;

pub struct PseudoBatchingIORConfig<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> {
    code_config: C::Config,
    pub log_n: usize,
    pub l: usize,
    pub t: usize,
    pub s: usize,
    mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
    mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    _f: PhantomData<F>,
}

impl<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> PseudoBatchingIORConfig<F, C, MT> {
    pub fn new(
        code_config: C::Config,
        log_n: usize,
        l: usize,
        t: usize,
        s: usize,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            code_config,
            log_n,
            l,
            t,
            s,
            mt_leaf_hash_params,
            mt_two_to_one_hash_params,
            _f: PhantomData,
        }
    }
}

pub struct PseudoBatchingIOR<
    F: Field + SpongefishUnit,
    C: LinearCode<F> + Clone,
    P: BundledPESAT<F>,
    MC: MultiConstrainedLinearCode<F, C, P>,
    MT: Config,
> {
    // note that R is one by def and is provided as a constant
    config: PseudoBatchingIORConfig<F, C, MT>,
    _mc: PhantomData<MC>,
    _p: PhantomData<P>,
}

impl<
        F: Field + SpongefishUnit,
        C: LinearCode<F> + Clone,
        P: BundledPESAT<F>,
        MC: MultiConstrainedLinearCode<F, C, P>,
        MT: Config,
    > PseudoBatchingIOR<F, C, P, MC, MT>
{
    pub fn new(config: PseudoBatchingIORConfig<F, C, MT>) -> Self {
        Self {
            config,
            _mc: PhantomData,
            _p: PhantomData,
        }
    }
}

impl<
        F: Field + SpongefishUnit,
        C: LinearCode<F> + Clone,
        P: BundledPESAT<F>,
        MC: MultiConstrainedLinearCode<F, C, P>,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > IOR<F, C, MT> for PseudoBatchingIOR<F, C, P, MC, MT>
{
    // instance is a vector \gamma, an twin constraint and corresponding codewords
    // (\gamma, (\alpha, \mu), \beta, \eta, (u_1, \dots, u_l))
    type Instance = (Vec<F>, MC, Vec<Vec<F>>);

    // witness is the RLC of the above codewords
    // \Sigma_{i \in l}( \gamma_i \cdot u_{i})
    type Witness = Vec<F>;

    // output instance is multi constraint codeword with 1 + s + t multilinear evaluation claims
    type OutputInstance = MC;

    // output witness is a codeword, which is an RLC of the above codeword
    type OutputWitness = Vec<F>;

    fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        instance: Self::Instance,
        witness: Self::Witness,
    ) -> ProofResult<(Self::OutputInstance, Self::OutputWitness)>
    where
        ProverState: UnitToField<F> + UnitToBytes + DigestToUnitSerialize<MT>,
    {
        // (\gamma, (\alpha, \mu), \beta, \eta, (u_1, \dots, u_l))
        let (gamma, multi_constraints, codewords) = instance;

        debug_assert!(gamma.len() == codewords.len());

        let constraints = multi_constraints.get_constraints();
        let (mut multilinear_evals, beta, eta) =
            (constraints.0.to_vec(), constraints.1, constraints.2);
        let mu = multilinear_evals[0].1;

        let u_mle = DenseMultilinearExtension::from_evaluations_slice(self.config.log_n, &witness);

        // commit to the rlc of the codeword
        // TODO: figure out how to handle unwrap below
        let mt = MerkleTree::<MT>::new(
            &self.config.mt_leaf_hash_params,
            &self.config.mt_two_to_one_hash_params,
            witness.chunks(1).collect::<Vec<_>>(),
        )
        .unwrap();

        // absorb commitment to the rlc of the codewords
        prover_state.add_digest(mt.root())?;
        prover_state.add_scalars(&[mu])?;
        prover_state.add_scalars(&[eta])?;

        // 7.1 step 2, get OOD challenges `alpha_i` for i in [S]
        let n_ood_samples = self.config.s * self.config.log_n;
        let mut ood_samples = vec![F::default(); n_ood_samples];

        prover_state.fill_challenge_scalars(&mut ood_samples)?;

        let ood_samples = ood_samples.chunks(self.config.log_n).collect::<Vec<_>>();

        // 7.1 step 3, compute OOD answers
        // we return (\alpha, \hat{f}(\alpha), \hat{f}(\alpha)) for convenience, as we will below
        // extend the initial vector of multilinear evaluations and absorb the new claimed evaluations
        let (alpha_mu_ood_answers, mu): (Vec<(Vec<F>, F)>, Vec<F>) = ood_samples
            .iter()
            .map(|alpha| {
                let mu = u_mle.fix_variables(alpha)[0];
                ((alpha.to_vec(), mu), mu)
            })
            .unzip();

        // extend the multilinear evaluations with the new claimed ones
        multilinear_evals.extend(alpha_mu_ood_answers);

        // absorb ood answers
        prover_state.add_scalars(&mu)?;

        // 7.1 step 4, get shift query points `x_i` for i in [T]
        // Note that `x_i` should be in range 0..N, not in Fr
        let n_shift_queries = (self.config.t * self.config.log_n).div_ceil(8);
        let mut bytes_shift_queries = vec![0u8; n_shift_queries];

        prover_state.fill_challenge_bytes(&mut bytes_shift_queries)?;

        // build a vector of tuples where both are either 1 or 0, but where the first element is a
        // field element and the second element is a bool. we use it below to then store those new
        // evaluation claims
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
            .take(self.config.t * self.config.log_n)
            .collect::<Vec<(F, bool)>>();

        // we want to get (\alpha_k, \Sigma{\gamma_i \cdot f_i(x_k)})
        let alpha_mu_shift_queries: Vec<(Vec<F>, F)> = alpha_binary_shift_indexes
            .chunks(self.config.log_n)
            .map(|array_tuples| {
                let (alpha_as_field_elements, alpha_as_bool): (Vec<F>, Vec<bool>) =
                    array_tuples.to_vec().into_iter().unzip();

                // compute x_k as usize from binary representation
                // we need to rev for the mle evaluation routine of arkworks
                let x_k = alpha_as_bool
                    .iter()
                    .rev()
                    .fold(0, |acc, &b| (acc << 1) | b as usize);
                let mu = (0..self.config.l)
                    .map(|i| {
                        let gamma_i = gamma[i];
                        let f_i = &codewords[i];
                        gamma_i * f_i[x_k]
                    })
                    .sum::<F>();
                (alpha_as_field_elements, mu)
            })
            .collect();

        multilinear_evals.extend(alpha_mu_shift_queries);

        debug_assert!(multilinear_evals.len() == 1 + self.config.s + self.config.t);

        Ok((
            // NOTE: this is recomputing the eq_evaluation table
            MC::new_with_constraint(
                self.config.code_config.clone(),
                multilinear_evals,
                beta.clone(),
                eta,
            ),
            witness,
        ))
    }

    fn verify() {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::{
        domainsep::WARPDomainSeparator,
        iors::{
            pesat::{
                r1cs::twin_constraint::{tests::TwinConstraintRS, R1CSTwinConstraintIOR},
                TwinConstraintIORConfig,
            },
            IOR,
        },
        linear_code::MultiConstrainedLinearCode,
        merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget},
        relations::{
            r1cs::{
                merkle_inclusion::{tests::get_test_merkle_tree, MerkleInclusionInstance},
                MerkleInclusionRelation, MerkleInclusionWitness,
            },
            relation::{BundledPESAT, ToPolySystem},
            Relation,
        },
        utils::poly::eq_poly,
    };
    use ark_bls12_381::Fr;
    use ark_ff::{UniformRand, Zero};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
    use ark_std::{log2, test_rng};
    use spongefish::DomainSeparator;
    use whir::{
        crypto::merkle_tree::blake3::Blake3MerkleTreeParams, poly_utils::hypercube::BinaryHypercube,
    };

    use crate::{
        iors::codeword_batching::PseudoBatchingIOR,
        linear_code::{LinearCode, MultiConstrainedReedSolomon, ReedSolomon, ReedSolomonConfig},
        relations::r1cs::R1CS,
    };

    use super::PseudoBatchingIORConfig;

    #[test]
    pub fn test_ior_codeword_batching() {
        let mut rng = test_rng();

        // prepare r1cs, code and example tree
        let height = 3;
        let (mt_config, leaves, mt) = get_test_merkle_tree(height);
        let r1cs = MerkleInclusionRelation::into_r1cs(&mt_config).unwrap();
        let code_config = ReedSolomonConfig::<Fr>::default(r1cs.k, r1cs.k.next_power_of_two());
        let code = ReedSolomon::new(code_config.clone());

        let (l, s, t) = (4, 5, 5);
        let log_l = log2(l) as usize;

        // initialize pesat ior config
        let pesat_ior_config = TwinConstraintIORConfig::<_, _, Blake3MerkleTreeParams<Fr>>::new(
            code.clone(),
            code_config.clone(),
            (),
            (),
            l,
            r1cs.log_m,
        );

        let r1cs_twinrs_ior = R1CSTwinConstraintIOR::<_, _, TwinConstraintRS, _>::new(
            r1cs.clone(),
            pesat_ior_config.clone(),
        );

        let mut witnesses = vec![];
        let mut instances = vec![];

        // intialize some instances and witnesses
        for i in 0..l {
            let proof = mt.generate_proof(i).unwrap();
            let instance = MerkleInclusionInstance::<
                Fr,
                PoseidonMerkleConfig<Fr>,
                PoseidonMerkleConfigGadget<Fr>,
            > {
                root: mt.root(),
                leaf: (*leaves[i]).to_vec(),
                _merkle_config_gadget: PhantomData,
            };
            let witness = MerkleInclusionWitness::<
                Fr,
                PoseidonMerkleConfig<Fr>,
                PoseidonMerkleConfigGadget<Fr>,
            > {
                proof,
                _merkle_config_gadget: PhantomData,
            };

            let relation = MerkleInclusionRelation::new(instance, witness, mt_config.clone());

            witnesses.push(relation.w);
            instances.push(relation.x);
        }

        let domainsep = DomainSeparator::new("test::ior").pesat_ior(&pesat_ior_config);
        let mut prover_state = domainsep.to_prover_state();

        let (constraints, codewords) = r1cs_twinrs_ior
            .prove(&mut prover_state, instances, witnesses.clone())
            .unwrap();

        let gamma = vec![Fr::rand(&mut rng); log_l];
        let gamma_eq_evals = BinaryHypercube::new(log_l)
            .map(|p| eq_poly(&gamma, p))
            .collect::<Vec<Fr>>();

        // compute the rlc
        let mut rlc_w = vec![Fr::zero(); r1cs.k];
        let mut rlc_f = vec![Fr::zero(); code.code_len()];
        let mut rlc_alpha = vec![Fr::zero(); log2(code.code_len()) as usize];
        let mut rlc_beta = (
            vec![Fr::zero(); constraints[0].beta.0.len()],
            vec![Fr::zero(); r1cs.n - r1cs.k],
        );

        for p in BinaryHypercube::new(log_l) {
            let constraint_i = constraints[p.0].clone();

            let alpha_i = &constraint_i.evaluations[0].0;
            let beta = &constraint_i.beta;

            let f_i = &codewords[p.0];
            let w_i = &witnesses[p.0];
            let eq_eval_i = &gamma_eq_evals[p.0];

            for (i, element) in f_i.iter().enumerate() {
                rlc_f[i] += eq_eval_i * element;
            }

            for (i, element) in w_i.iter().enumerate() {
                rlc_w[i] += eq_eval_i * element;
            }

            for (i, element) in beta.0.iter().enumerate() {
                rlc_beta.0[i] += eq_eval_i * element;
            }

            for (i, element) in beta.1.iter().enumerate() {
                rlc_beta.1[i] += eq_eval_i * element;
            }

            for (i, element) in alpha_i.iter().enumerate() {
                rlc_alpha[i] += eq_eval_i * element;
            }
        }

        let rlc_f_mle = DenseMultilinearExtension::from_evaluations_slice(
            log2(code.code_len()) as usize,
            &rlc_f,
        );
        let upsilon = rlc_f_mle.evaluate(&rlc_alpha);

        // compute zero evader evals before evaluating on pesat
        let zero_evader = BinaryHypercube::new(r1cs.log_m)
            .map(|p| eq_poly(&rlc_beta.0, p))
            .collect::<Vec<Fr>>();

        let mut z = rlc_beta.1.clone();
        z.extend(rlc_w.clone());

        let eta = r1cs.evaluate_bundled(&zero_evader, &z).unwrap();

        let mc_instance =
            MultiConstrainedReedSolomon::<_, ReedSolomon<Fr>, R1CS<Fr>>::new_with_constraint(
                code_config.clone(),
                vec![(rlc_alpha, upsilon)],
                rlc_beta,
                eta,
            );

        // check that the built multi constrained codeword instance is correct
        mc_instance
            .check_constraints(&rlc_w, &rlc_f, &r1cs)
            .unwrap();

        let config = PseudoBatchingIORConfig::<_, _, Blake3MerkleTreeParams<Fr>>::new(
            code_config,
            log2(code.code_len()).try_into().unwrap(),
            l,
            t,
            s,
            (),
            (),
        );

        let domainsep =
            DomainSeparator::new("test::ior::codeword_batching").pseudo_batching_ior(&config);

        let mut prover_state = domainsep.to_prover_state();

        let k = r1cs.k; // message length for RS
        let mut rlc_w = vec![Fr::zero(); k];

        for (i, w_i) in witnesses.iter().enumerate() {
            let w = gamma_eq_evals[i];
            for (j, &wj) in w_i.iter().enumerate() {
                rlc_w[j] += w * wj;
            }
        }

        let pseudo_batching_ior = PseudoBatchingIOR::<
            Fr,
            ReedSolomon<Fr>,
            R1CS<Fr>,
            MultiConstrainedReedSolomon<Fr, ReedSolomon<Fr>, R1CS<Fr>>,
            Blake3MerkleTreeParams<Fr>,
        >::new(config);

        let (new_mc, wtns) = pseudo_batching_ior
            .prove(
                &mut prover_state,
                (gamma_eq_evals, mc_instance, codewords),
                rlc_f.clone(),
            )
            .unwrap();

        new_mc.check_constraints(&rlc_w, &wtns, &r1cs).unwrap();
    }
}

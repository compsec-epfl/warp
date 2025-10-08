use crate::utils::DigestToUnitSerialize;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, MerkleTree},
};
use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use spongefish::{
    codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
    BytesToUnitSerialize, DomainSeparatorMismatch, ProofError, ProverState, Unit as SpongefishUnit,
};
use std::marker::PhantomData;

use crate::{
    iors::IOR,
    linear_code::{LinearCode, MultiConstrainedLinearCode},
    relations::relation::BundledPESAT,
    WARPError,
};

use spongefish::UnitToBytes;

pub struct PseudoBatchingIORConfig<F: Field + SpongefishUnit, C: LinearCode<F>, MT: Config> {
    code: C,
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
        code: C,
        log_n: usize,
        l: usize,
        t: usize,
        s: usize,
        mt_leaf_hash_params: <MT::LeafHash as CRHScheme>::Parameters,
        mt_two_to_one_hash_params: <MT::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        Self {
            code,
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
    C: LinearCode<F>,
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
        C: LinearCode<F>,
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
        C: LinearCode<F>,
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
    ) -> Result<(Self::OutputInstance, Self::OutputWitness), WARPError>
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
        let mt = MerkleTree::<MT>::new(
            &self.config.mt_leaf_hash_params,
            &self.config.mt_two_to_one_hash_params,
            &witness.chunks(1).collect::<Vec<_>>(),
        )?;

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
        let mut bytes_shift_queries = vec![0; n_shift_queries];

        // TODO: we shouldn't call `map_err`, there might be a trait missing on `ProverState`
        prover_state
            .fill_challenge_bytes(&mut bytes_shift_queries)
            .map_err(|d| ProofError::InvalidDomainSeparator(d))?;

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
                let x_k = alpha_as_bool
                    .iter()
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
            MC::new_with_constraint(
                self.config.code.config(),
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
    use std::error::Error;

    use crate::iors::IOR;
    use ark_bls12_381::Fr;
    use ark_crypto_primitives::{
        crh::CRHScheme, merkle_tree::MerkleTree, sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::{One, PrimeField, UniformRand, Zero};
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension, Polynomial};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
    };
    use ark_std::{log2, test_rng};
    use spongefish::{
        codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField},
        duplex_sponge::DuplexSponge,
        ByteDomainSeparator, DomainSeparator, UnitToBytes,
    };
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;
    use whir::{
        crypto::merkle_tree::blake3::{Blake3LeafHash, Blake3MerkleTreeParams},
        poly_utils::hypercube::{BinaryHypercube, BinaryHypercubePoint},
    };

    use crate::{
        iors::codeword_batching::PseudoBatchingIOR,
        linear_code::{LinearCode, MultiConstrainedReedSolomon, ReedSolomon, ReedSolomonConfig},
        merkle::{poseidon::PoseidonMerkleConfig, poseidon_test_params},
        relations::{r1cs::R1CS, relation::BundledPESAT},
        utils::poly::eq_poly,
    };

    use super::PseudoBatchingIORConfig;

    struct C<F: PrimeField> {
        v: Vec<F>,
        x: F,
    }

    #[test]
    pub fn test_ior_codeword_batching() {
        let message_length = 4;
        let code_length = 16;
        let mut rng = test_rng();
        let (l, s, t) = (5, 5, 5);

        // sample l random codewords
        let codewords: Vec<Vec<Fr>> = (0..l)
            .map(|_| vec![Fr::rand(&mut rng); code_length])
            .collect();
        let gamma = vec![Fr::rand(&mut rng); code_length];

        // compute the rlc
        let mut rlc_codewords = vec![Fr::zero(); code_length];
        for (codeword, gamma) in codewords.iter().zip(gamma) {
            for (i, element) in codeword.iter().enumerate() {
                rlc_codewords[i] += gamma * element;
            }
        }

        let blake3_leaf_hash = Blake3LeafHash::<Fr>::setup(&mut rng).unwrap();
        let code = ReedSolomon::<Fr>::new(ReedSolomonConfig::default(message_length, code_length));
        let config = PseudoBatchingIORConfig::<_, _, Blake3MerkleTreeParams<Fr>>::new(
            code,
            log2(code_length).try_into().unwrap(),
            l,
            t,
            s,
            (),
            (),
        );

        let pseudo_batching_ior = PseudoBatchingIOR::<
            Fr,
            ReedSolomon<Fr>,
            R1CS<Fr>,
            MultiConstrainedReedSolomon<Fr, ReedSolomon<Fr>, R1CS<Fr>>,
            Blake3MerkleTreeParams<Fr>,
        >::new(config);

        // pseudo_batching_ior.prove();
    }

    // A test circuit with 16 constraints
    impl<F: PrimeField> ConstraintSynthesizer<F> for C<F> {
        fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
            let v = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(self.v))?;
            let x = FpVar::new_input(cs.clone(), || Ok(self.x))?;

            let mut r = FpVar::one();

            for i in 0..15 {
                r *= &v[i];
            }

            r.enforce_equal(&x)?;

            Ok(())
        }
    }

    #[test]
    fn test() -> Result<(), Box<dyn Error>> {
        let l = 10;
        const S: usize = 8;
        const T: usize = 7;

        let leaf_hash_param: PoseidonConfig<Fr> = poseidon_test_params();
        let two_to_one_hash_param: PoseidonConfig<Fr> = poseidon_test_params();

        let rng = &mut test_rng();

        let cs = ConstraintSystem::new_ref();

        let witness = (0..15).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let instance = witness.iter().product::<Fr>();
        let circuit = C {
            v: witness.clone(),
            x: instance,
        };
        circuit.generate_constraints(cs.clone())?;
        let r1cs = R1CS::try_from(cs)?;
        const N: usize = 64;
        assert_eq!(N, (r1cs.k * 2).next_power_of_two());

        let code = ReedSolomon::new(ReedSolomonConfig::default(r1cs.k, N));

        // Prepare for l instances and witnesses for twin constraint relation
        let mut alpha_vec = vec![];
        let mut mu_vec = vec![];
        let mut beta_vec = vec![];
        let mut eta_vec = vec![];
        let mut x_vec = vec![];
        let mut w_vec = vec![];
        let mut u_vec = vec![];

        for _ in 0..l {
            let cs = ConstraintSystem::new_ref();

            let witness = (0..15).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let instance = witness.iter().product::<Fr>();
            let circuit = C {
                v: witness.clone(),
                x: instance,
            };
            circuit.generate_constraints(cs.clone())?;

            let cs = cs.into_inner().unwrap();
            let (x, w) = (cs.instance_assignment, cs.witness_assignment);
            let z = [&x[..], &w].concat();

            let beta = (0..r1cs.log_m).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

            let mut beta_eq_evals = Vec::<Fr>::new();
            let hypercube = BinaryHypercube::new(r1cs.log_m);

            for point in hypercube {
                beta_eq_evals.push(eq_poly(&beta, point));
            }

            let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

            let u = code.encode(&w);
            let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
            let alpha = (0..log2(N)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
            let mu = u_mle.evaluate(&alpha);

            alpha_vec.push(alpha);
            mu_vec.push(mu);
            beta_vec.push(beta);
            eta_vec.push(eta);
            x_vec.push(x);
            w_vec.push(w);
            u_vec.push(u);
        }

        // Generate `gamma` for pseudo-batching accumulation relation
        let gamma_vec = (0..log2(l)).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let gamma_eq_evals = (0..l)
            .map(|i| eq_poly(&gamma_vec, BinaryHypercubePoint(i)))
            .collect::<Vec<_>>();

        // Compute the pseudo-batching accumulation relation according to sec 6
        let mut alpha = vec![Fr::zero(); log2(N) as usize];
        for i in 0..l {
            for j in 0..log2(N) as usize {
                alpha[j] += gamma_eq_evals[i] * alpha_vec[i][j];
            }
        }

        let mut u = vec![Fr::zero(); N];
        for i in 0..l {
            for j in 0..N {
                u[j] += gamma_eq_evals[i] * u_vec[i][j];
            }
        }
        let u_mle = DenseMultilinearExtension::from_evaluations_slice(log2(N) as usize, &u);
        let mu = u_mle.evaluate(&alpha);

        let mut beta = vec![Fr::zero(); r1cs.log_m];
        for i in 0..l {
            for j in 0..r1cs.log_m {
                beta[j] += gamma_eq_evals[i] * beta_vec[i][j];
            }
        }

        let mut x = vec![Fr::zero(); r1cs.n - r1cs.k];
        for i in 0..l {
            for j in 0..r1cs.n - r1cs.k {
                x[j] += gamma_eq_evals[i] * x_vec[i][j];
            }
        }

        let mut w = vec![Fr::zero(); r1cs.k];
        for i in 0..l {
            for j in 0..r1cs.k {
                w[j] += gamma_eq_evals[i] * w_vec[i][j];
            }
        }

        let mut beta_eq_evals = Vec::<Fr>::new();
        let hypercube = BinaryHypercube::new(r1cs.log_m);
        for point in hypercube {
            beta_eq_evals.push(eq_poly(&beta, point));
        }

        let z = [&x[..], &w].concat();

        let eta = r1cs.evaluate_bundled(&beta_eq_evals, &z)?;

        // Now impl the IOR from pseudo-batching accumulation relation to multi-evaluation relation with 1 + S + T evaluations
        let domain_separator = DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, Fr>::new(
            "ior::codeword_batching",
        )
        .absorb(1, "root")
        .absorb(1, "mu")
        .absorb(1, "eta")
        .squeeze(S * log2(N) as usize, "alpha")
        .absorb(S, "mus")
        .challenge_bytes((T * log2(N) as usize).div_ceil(8), "x");
        let mut prover_state = domain_separator.to_prover_state();

        // 7.1 step 1, send witness oracle `u` (in non-interactive version, this is a commitment)
        let mt = MerkleTree::<PoseidonMerkleConfig<Fr>>::new(
            &leaf_hash_param,
            &two_to_one_hash_param,
            u.iter().map(|v| vec![*v]).collect::<Vec<_>>(),
        )?;
        prover_state.add_scalars(&[mt.root()])?;
        prover_state.add_scalars(&[mu])?;
        prover_state.add_scalars(&[eta])?;

        // 7.1 step 2, get OOD challenges `alpha_i` for i in [S]
        let alpha_vec = prover_state
            .challenge_scalars::<{ S * log2(N) as usize }>()?
            .chunks(log2(N) as usize)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        // 7.1 step 3, compute OOD answers
        let mu_vec = alpha_vec
            .iter()
            .map(|c| u_mle.fix_variables(c)[0])
            .collect::<Vec<_>>();
        prover_state.add_scalars(&mu_vec)?;

        // 7.1 step 4, get shift query points `x_i` for i in [T]
        // Note that `x_i` should be in range 0..N, not in Fr
        let x_vec = prover_state
            .challenge_bytes::<{ (T * log2(N) as usize).div_ceil(8) }>()?
            .iter()
            .flat_map(|x| (0..8).map(|i| (x >> i) & 1 == 1).collect::<Vec<_>>())
            .take(T * log2(N) as usize)
            .collect::<Vec<_>>()
            .chunks(log2(N) as usize)
            .map(|c| c.to_vec())
            .collect::<Vec<_>>();

        // 7.1 step 5, output new alpha_vec
        let alpha_vec = [
            &[alpha][..],
            &alpha_vec,
            &x_vec
                .iter()
                .map(|x| {
                    x.iter()
                        .map(|&x| if x { Fr::one() } else { Fr::zero() })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        ]
        .concat();
        // 7.1 step 5, output new mu_vec
        let mu_vec = [
            &[mu][..],
            &mu_vec,
            &x_vec
                .iter()
                .map(|x| {
                    let x = x
                        .iter()
                        .enumerate()
                        .map(|(i, &b)| if b { 1 << i } else { 0 })
                        .sum::<usize>();
                    (0..l).map(|i| gamma_eq_evals[i] * u_vec[i][x]).sum()
                })
                .collect::<Vec<_>>(),
        ]
        .concat();

        // The new `mu`s should be exactly the evaluations of u_mle at the new `alpha`s
        for i in 0..1 + S + T {
            assert_eq!(mu_vec[i], u_mle.fix_variables(&alpha_vec[i])[0]);
        }

        Ok(())
    }
}

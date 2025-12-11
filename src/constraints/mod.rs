#[cfg(test)]
pub mod test {
    use std::marker::PhantomData;

    use ark_bls12_381::Fr as BLS12_381;
    use ark_codes::{
        reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
        traits::LinearCode,
    };
    use ark_crypto_primitives::{
        crh::poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        merkle_tree::constraints::PathVar,
    };
    use ark_ff::{PrimeField, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
        poly::polynomial::univariate::dense::DensePolynomialVar,
        uint8::UInt8,
    };
    use ark_relations::r1cs::{ConstraintSystem, SynthesisError};
    use ark_std::log2;
    use rand::thread_rng;
    use spongefish::{duplex_sponge::DuplexSponge, DomainSeparator};
    use spongefish_poseidon::bls12_381::PoseidonPermx5_255_5;

    use crate::{
        crypto::merkle::poseidon::{PoseidonMerkleConfig, PoseidonMerkleConfigGadget},
        protocol::domainsep::{derive_randomness, parse_statement, WARPDomainSeparator},
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
        AccumulationScheme, BoolResult, WARPConfig, WARP,
    };

    pub struct EqPolyVar;

    impl EqPolyVar {
        /// This function builds `eq(x, y)` by fixing `y = r` and outputting the
        /// evaluations over all `x` in `[0, 2^n)`.
        pub fn fix_y_evals<F: PrimeField>(r: &[FpVar<F>]) -> Vec<FpVar<F>> {
            // we build eq(x,r) from its evaluations
            // we want to evaluate eq(x,r) over all binary strings `x` of length `n`
            // for example, with n = 4, x is a binary string of length 4, then
            //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
            //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
            //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
            //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
            //  ....
            //  1 1 1 1 -> r0       * r1        * r2        * r3
            // we will need 2^num_var evaluations

            // initializing the buffer with [1]
            let mut buf = vec![FpVar::one()];

            for i in r.iter().rev() {
                // suppose at the previous step we received [b_1, ..., b_k]
                // for the current step we will need
                // if x_i = 0:   (1-ri) * [b_1, ..., b_k]
                // if x_i = 1:   ri * [b_1, ..., b_k]
                buf = buf
                    .iter()
                    .flat_map(|j| {
                        let v = j * i;
                        [j - &v, v]
                    })
                    .collect();
            }

            buf
        }

        /// Evaluate eq polynomial in circuit.
        pub fn fix_xy_eval<F: PrimeField>(x: &[FpVar<F>], y: &[FpVar<F>]) -> FpVar<F> {
            debug_assert_eq!(x.len(), y.len());
            let mut eval = FpVar::<F>::one();
            for (xi, yi) in x.iter().zip(y.iter()) {
                eval *= (xi + xi) * yi - xi - yi + F::one();
            }
            eval
        }
    }

    #[test]
    pub fn warp_test() -> Result<(), SynthesisError> {
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
        let hash_chain_warp =
            WARP::<BLS12_381, R1CS<BLS12_381>, _, PoseidonMerkleConfig<BLS12_381>>::new(
                warp_config.clone(),
                code.clone(),
                r1cs.clone(),
                poseidon_config.clone(),
                poseidon_config.clone(),
            );

        let (mut acc_roots, mut acc_alphas, mut acc_mus, mut acc_taus, mut acc_xs, mut acc_eta) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        let (mut acc_tds, mut acc_f, mut acc_ws) = (vec![], vec![], vec![]);

        let domainsep =
            DomainSeparator::<DuplexSponge<PoseidonPermx5_255_5>, BLS12_381>::new("test::warp");

        for _ in 0..l1 {
            let domainsep = WARPDomainSeparator::<
                BLS12_381,
                ReedSolomon<BLS12_381>,
                PoseidonMerkleConfig<BLS12_381>,
            >::warp(domainsep.clone(), warp_config.clone());
            let mut prover_state = domainsep.to_prover_state();
            let ((acc_x, acc_w), _pf) = hash_chain_warp
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

        let warp_config =
            WARPConfig::<_, R1CS<BLS12_381>>::new(8, l1, s, t, r1cs.config(), code.code_len());

        let hash_chain_warp =
            WARP::<BLS12_381, R1CS<BLS12_381>, _, PoseidonMerkleConfig<BLS12_381>>::new(
                warp_config.clone(),
                code.clone(),
                r1cs.clone(),
                poseidon_config.clone(),
                poseidon_config.clone(),
            );
        let domainsep = WARPDomainSeparator::<
            BLS12_381,
            ReedSolomon<BLS12_381>,
            PoseidonMerkleConfig<BLS12_381>,
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
                pf.clone(),
            )
            .unwrap();
        hash_chain_warp.decide(acc_w, acc_x.clone()).unwrap();

        //
        //
        //
        //
        //
        //

        let cs = ConstraintSystem::<BLS12_381>::new_ref();

        let poseidon_config_var = CRHParametersVar::new_constant(cs.clone(), poseidon_config)?;
        let acc_instance = (
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&acc_x.0[..]))?,
            acc_x
                .1
                .iter()
                .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
                .collect::<Result<Vec<_>, _>>()?,
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&acc_x.2[..]))?,
            (
                acc_x
                    .3
                     .0
                    .iter()
                    .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
                    .collect::<Result<Vec<_>, _>>()?,
                acc_x
                    .3
                     .1
                    .iter()
                    .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&acc_x.4[..]))?,
        );
        let mut proof = (
            FpVar::new_witness(cs.clone(), || Ok(&pf.0))?,
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&pf.1[..]))?,
            FpVar::new_witness(cs.clone(), || Ok(&pf.2))?,
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&pf.3[..]))?,
            Vec::<PathVar<_, _, PoseidonMerkleConfigGadget<_>>>::new_witness(cs.clone(), || {
                Ok(&pf.4[..])
            })?,
            pf.5.iter()
                .map(|v| {
                    Vec::<PathVar<_, _, PoseidonMerkleConfigGadget<_>>>::new_witness(
                        cs.clone(),
                        || Ok(&v[..]),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            pf.6.iter()
                .map(|v| Vec::new_witness(cs.clone(), || Ok(&v[..])))
                .collect::<Result<Vec<_>, _>>()?,
        );

        let mut verifier_state = domainsep.to_verifier_state(narg_str);

        let config = &hash_chain_warp.config;

        let (l1, l) = (config.l1, config.l);
        let l2 = l - l1;

        ////////////////////////
        // 1. Parsing phase
        ////////////////////////
        // a. verification key
        #[allow(non_snake_case)]
        let (M, N, k, n) = (r1cs.m, r1cs.n, r1cs.k, code.code_len());
        #[allow(non_snake_case)]
        let (log_M, log_l) = (log2(M) as usize, log2(l) as usize);

        let log_n = log2(n) as usize;

        // f. absorb parameters
        let (l1_xs, (l2_roots, l2_alphas, l2_mus, (l2_taus, l2_xs), l2_etas)) =
            parse_statement::<_, PoseidonMerkleConfig<_>>(
                &mut verifier_state,
                l1,
                l2,
                N - k,
                log_n,
                log_M,
            )
            .unwrap();

        let l1_xs = l1_xs
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let l2_roots = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(l2_roots))?;
        let l2_alphas = l2_alphas
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let l2_mus = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&l2_mus[..]))?;
        let l2_taus = l2_taus
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let l2_xs = l2_xs
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let l2_etas = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&l2_etas[..]))?;

        ////////////////////////
        // 2. Derive randomness
        ////////////////////////
        let (
            rt_0,
            l1_mus,
            l1_taus,
            omega,
            tau,
            gamma_sumcheck,
            coeffs_twinc_sumcheck,
            _td,
            eta,
            nus,
            ood_samples,
            bytes_shift_queries,
            xi,
            alpha_sumcheck,
            sums_batching_sumcheck,
        ) = derive_randomness::<_, PoseidonMerkleConfig<_>>(
            &mut verifier_state,
            l1,
            log_n,
            log_l,
            config.s,
            config.t,
            log_M,
        )
        .unwrap();

        let rt_0 = FpVar::new_witness(cs.clone(), || Ok(rt_0))?;
        let l1_mus = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&l1_mus[..]))?;
        let l1_taus = l1_taus
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let omega = FpVar::new_witness(cs.clone(), || Ok(omega))?;
        let tau = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&tau[..]))?;
        let gamma_sumcheck = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&gamma_sumcheck[..]))?;
        let coeffs_twinc_sumcheck = coeffs_twinc_sumcheck
            .iter()
            .map(|v| Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&v[..])))
            .collect::<Result<Vec<_>, _>>()?;
        let eta = FpVar::new_witness(cs.clone(), || Ok(eta))?;
        let mut nus = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&nus[..]))?;
        let ood_samples = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&ood_samples[..]))?;
        let bytes_shift_queries =
            Vec::<UInt8<_>>::new_witness(cs.clone(), || Ok(&bytes_shift_queries[..]))?;
        let xi = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&xi[..]))?;
        let alpha_sumcheck = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(&alpha_sumcheck[..]))?;
        let sums_batching_sumcheck = sums_batching_sumcheck
            .iter()
            .map(|[a, b, c]| {
                Ok([
                    FpVar::new_witness(cs.clone(), || Ok(a))?,
                    FpVar::new_witness(cs.clone(), || Ok(b))?,
                    FpVar::new_witness(cs.clone(), || Ok(c))?,
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;

        let r = 1 + config.s + config.t;

        ////////////////////////
        // 3. Derive values
        ////////////////////////
        // b.
        let alpha_vecs = [&l2_alphas, &vec![vec![FpVar::zero(); log_n]; l1][..]].concat();

        let gamma_eq_evals = EqPolyVar::fix_y_evals(&gamma_sumcheck);

        let zeta_0 = {
            let n = alpha_vecs[0].len();
            let mut result = vec![FpVar::zero(); n];

            alpha_vecs.iter().zip(&gamma_eq_evals).for_each(|(v, a)| {
                result.iter_mut().zip(v).for_each(|(r, x)| *r += a * x);
            });

            result
        };

        // compute \eta_{s + k}
        let mut nu_s_t = vec![FpVar::zero(); config.t];
        for (i, v_jk) in proof.6.iter().enumerate() {
            let res = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(FpVar::zero(), |acc, (v, eq)| acc + eq * v);
            nu_s_t[i] = res;
        }

        nus.extend(nu_s_t);

        // d. set \sigma^{(1)} and \sigma^{(2)}
        // compute eq(\tau, i) and eq(\xi, i)
        let tau_eq_evals = EqPolyVar::fix_y_evals(&tau);

        let etas = [&l2_etas, &vec![FpVar::zero(); l1][..]].concat();

        let sigma_1 = tau_eq_evals
            .into_iter()
            .zip(l2_mus.into_iter().chain(l1_mus.to_vec()).zip(etas))
            .fold(FpVar::zero(), |acc, (eq_tau, (mu, eta))| {
                acc + eq_tau * (mu + &omega * eta)
            });

        let xi_eq_evals = EqPolyVar::fix_y_evals(&xi);

        let sigma_2 = xi_eq_evals
            .iter()
            .zip(&nus)
            .fold(FpVar::zero(), |acc, (xi_eq, nu)| acc + xi_eq * nu);

        ////////////////////////
        // 4. Decision phase
        ////////////////////////
        // a. new code evaluation point
        acc_instance.1[0].enforce_equal(&alpha_sumcheck)?;

        // b. new circuit evaluation point
        let betas = l2_taus
            .into_iter()
            .chain(l1_taus)
            .zip(l2_xs.clone().into_iter().chain(l1_xs))
            .map(|(tau, x)| [&tau[..], &x[..]].concat())
            .collect::<Vec<Vec<_>>>();
        let _beta = {
            let n = betas[0].len();
            let mut result = vec![FpVar::zero(); n];

            betas.iter().zip(&gamma_eq_evals).for_each(|(v, a)| {
                result.iter_mut().zip(v).for_each(|(r, x)| *r += a * x);
            });

            result
        };

        // c. check auth paths
        let binary_shift_queries = bytes_shift_queries
            .iter()
            .flat_map(|i| i.bits.to_vec())
            .take(config.t * log_n)
            .collect::<Vec<_>>();

        let binary_shift_queries = binary_shift_queries.chunks(log_n).collect::<Vec<&[_]>>();

        // check:
        // that the leaf index corresponds to the shift query
        // that the path is correct
        (proof.6.len() == config.t).ok_or_err(SynthesisError::Unsatisfiable)?;

        // proof.4 is auth_0
        for (i, path) in proof.4.iter_mut().enumerate() {
            path.set_leaf_position(binary_shift_queries[i].to_vec());

            path.calculate_root(
                &poseidon_config_var,
                &poseidon_config_var,
                &proof.6[i][l2..], // leaves are evaluations of the l1 codewords
            )?
            .enforce_equal(&rt_0)?;
        }

        // proof.5 holds merkle proofs for l2 accumulated instances
        (proof.5.len() == l2).ok_or_err(SynthesisError::Unsatisfiable)?;
        for (i, paths) in proof.5.iter_mut().enumerate() {
            (paths.len() == config.t).ok_or_err(SynthesisError::Unsatisfiable)?;
            let root = &l2_roots[i];
            for (j, path) in paths.iter_mut().enumerate() {
                path.set_leaf_position(binary_shift_queries[j].to_vec());
                path.calculate_root(
                    &poseidon_config_var,
                    &poseidon_config_var,
                    &[proof.6[j][i].clone()], // proof.6[j][i] holds f_i(x_j)
                )?
                .enforce_equal(root)?;
            }
        }

        // d. sumcheck decisions
        // twin constraints sumcheck
        (coeffs_twinc_sumcheck.len() == log_l).ok_or_err(SynthesisError::Unsatisfiable)?;

        let mut target_1 = sigma_1;
        for (coeffs, gamma) in coeffs_twinc_sumcheck.into_iter().zip(&gamma_sumcheck) {
            (coeffs.iter().sum::<FpVar<_>>() + &coeffs[0]).enforce_equal(&target_1)?;
            let h = DensePolynomialVar::from_coefficients_vec(coeffs);
            target_1 = h.evaluate(gamma)?;
        }

        // multilinear batching sumcheck
        (sums_batching_sumcheck.len() == log_n).ok_or_err(SynthesisError::Unsatisfiable)?;
        let mut target_2 = sigma_2;
        for ([sum_00, sum_11, sum_0110], alpha) in
            sums_batching_sumcheck.into_iter().zip(&alpha_sumcheck)
        {
            (&sum_00 + &sum_11).enforce_equal(&target_2)?;
            target_2 = (target_2 - &sum_0110) * alpha.square()?
                + sum_00 * (FpVar::one() - alpha.double()?)
                + sum_0110 * alpha;
        }

        // e. new target decision
        // build eq^{\star}(\alpha)
        (EqPolyVar::fix_xy_eval(&tau, &gamma_sumcheck) * (&nus[0] + omega * eta))
            .enforce_equal(&target_1)?;

        let mut zeta_eqs = vec![EqPolyVar::fix_xy_eval(&zeta_0, &alpha_sumcheck)];

        zeta_eqs.extend(
            ood_samples
                .chunks(log_n)
                .map(|zeta| EqPolyVar::fix_xy_eval(zeta, &alpha_sumcheck))
                .collect::<Vec<_>>(),
        );
        zeta_eqs.extend(
            binary_shift_queries
                .iter()
                .map(|zeta| {
                    zeta.iter()
                        .map(|b| FpVar::from(b.clone()))
                        .collect::<Vec<_>>()
                })
                .map(|zeta| EqPolyVar::fix_xy_eval(&zeta, &alpha_sumcheck))
                .collect::<Vec<_>>(),
        );
        (zeta_eqs.len() == r).ok_or_err(SynthesisError::Unsatisfiable)?;

        // mul by \mu and compare to target_2
        (&acc_instance.2[0]
            * zeta_eqs
                .into_iter()
                .zip(xi_eq_evals)
                .map(|(a, b)| a * b)
                .sum::<FpVar<_>>())
        .enforce_equal(&target_2)?;

        assert!(cs.is_satisfied()?);
        println!("{}", cs.num_constraints());

        Ok(())
    }
}

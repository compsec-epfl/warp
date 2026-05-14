use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_std::log2;
use ark_vc::mvc::MultiVectorCommitment;
use effsc::hypercube::compute_hypercube_eq_evals;
use rand_core::OsRng;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, VerifierState};
use std::marker::PhantomData;

use crate::accumulation_scheme::accumulator::AccumulatorInstance;
use crate::accumulation_scheme::keys::WarpVerifierKey;
use crate::accumulation_scheme::proof::WarpProof;
use crate::accumulation_scheme::scheme::WarpAccumulationScheme;
use crate::accumulation_scheme::transcript::parse_statement;
use crate::accumulation_scheme::AccumulationScheme;
use crate::error::VerifierError;
use crate::iop::iors::{
    batching::{Batching, BatchingReducedStatement, BatchingStatement, BatchingVerifierInputs},
    bridge::{Bridge, BridgeReducedStatement, BridgeStatement, BridgeVerifierInputs},
    ood::{Ood, OodReducedStatement, OodStatement},
    pesat::{Pesat, PesatReducedStatement, PesatStatement, PesatVerifierOutputs},
    proximity::{Proximity, ProximityStatement, ProximityVerifierInputs},
    sample_queries::{SampleQueries, SampleQueriesReducedStatement, SampleQueriesStatement},
    twin_constraint::{TwinConstraint, TwinConstraintReducedStatement, TwinConstraintStatement},
};
use crate::iop::oracles::indexed::ValidatedOracle;
use crate::relations::PolyPredicate;
use crate::utils::{concat_slices, scale_and_sum};

impl<F, P, C, V> WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    pub fn verify<'a>(
        &self,
        vk: WarpVerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F, V>,
        proof: WarpProof<F, V>,
    ) -> Result<(), VerifierError> {
        let log_l = log2(self.params.config.l_total_fold_factor()) as usize;
        let log_m = log2(vk.m_num_constraints) as usize;
        let n_code_len = self.params.code.code_len();
        let log_n = log2(n_code_len) as usize;
        let n_minus_k = vk.n_num_variables - vk.k_num_witness_vars;

        self.absorb_scheme_prologue_verifier(verifier_state);

        let (l1_xs, parsed_acc) = parse_statement::<F, V>(
            verifier_state,
            self.params.config.l1_first_fold_factor,
            self.params.config.l2_second_fold_factor,
            n_minus_k,
            log_n,
            log_m,
        )?;

        let acc_alpha_first = acc_instance.alpha_fold_vectors[0].clone();
        let acc_beta_0_first = acc_instance.beta_twin_pairs[0].tau.clone();
        let acc_beta_1_first = acc_instance.beta_twin_pairs[0].x.clone();
        let acc_mu_first = acc_instance.mu_claimed_evals[0];
        let l2_taus: Vec<Vec<F>> = parsed_acc
            .beta_twin_pairs
            .iter()
            .map(|p| p.tau.clone())
            .collect();
        let l2_xs: Vec<Vec<F>> = parsed_acc
            .beta_twin_pairs
            .iter()
            .map(|p| p.x.clone())
            .collect();
        let l2_commitments = parsed_acc.rt_commitments.clone();

        let pesat_ior = Pesat::<F, C, V> {
            code: &self.params.code,
            ck: &self.params.ck,
            _phantom: PhantomData,
        };
        let twin_constraint_ior = TwinConstraint::<F, V> {
            r1cs: self.params.predicate.constraints(),
            _phantom: PhantomData,
        };
        let bridge_ior = Bridge::<F, P, V>::default();
        let ood_ior = Ood::<F>::default();
        let sample_queries_ior = SampleQueries::<F>::default();
        let batching_ior = Batching::<F>::default();
        let proximity_ior = Proximity::<F, V> {
            ck: &self.params.ck,
            _phantom: PhantomData,
        };

        let ark_iop::IorVerifyResult {
            reduced:
                PesatReducedStatement {
                    mus_codeword_first_coords,
                    taus_zero_check_challenges,
                },
            outputs: PesatVerifierOutputs {
                rt_0_fresh_commitment,
            },
        } = ark_iop::verify_ior!(
            pesat_ior,
            verifier_state,
            statement: PesatStatement { l1_first_fold_factor: self.params.config.l1_first_fold_factor, log_m },
            inputs: (),
        )?;

        let ark_iop::IorVerifyResult {
            reduced:
                TwinConstraintReducedStatement {
                    gamma_sumcheck_challenges,
                    zeta_0,
                    beta_tau,
                    deferred,
                },
            outputs: _,
        } = ark_iop::verify_ior!(
            twin_constraint_ior,
            verifier_state,
            statement: TwinConstraintStatement {
                acc_instance: parsed_acc,
                l1_mus_codeword_first_coords: mus_codeword_first_coords.clone(),
                l1_taus_zero_check_challenges: taus_zero_check_challenges.clone(),
                log_l,
                log_m,
                log_n,
            },
            inputs: (),
        )?;

        let ark_iop::IorVerifyResult {
            reduced:
                BridgeReducedStatement {
                    eta_predicate_eval: _,
                    nu_0_oracle_eval,
                    td_new_commitment: _,
                },
            outputs: _,
        } = ark_iop::verify_ior!(
            bridge_ior,
            verifier_state,
            statement: BridgeStatement {
                zeta_0: zeta_0.clone(),
                beta_tau,
                log_m,
                n_minus_k,
            },
            inputs: BridgeVerifierInputs {
                deferred: &deferred,
                gamma_twin_constraint_challenges: &gamma_sumcheck_challenges,
            },
        )?;

        if !deferred.is_discharged() {
            return Err(VerifierError::Target);
        }

        let ark_iop::IorVerifyResult {
            reduced:
                OodReducedStatement {
                    samples_flat,
                    answers,
                },
            outputs: _,
        } = ark_iop::verify_ior!(
            ood_ior,
            verifier_state,
            statement: OodStatement { s_num_ood_samples: self.params.config.s_num_ood_samples, log_n },
            inputs: (),
        )?;

        let ark_iop::IorVerifyResult {
            reduced: SampleQueriesReducedStatement { queries },
            outputs: _,
        } = ark_iop::verify_ior!(
            sample_queries_ior,
            verifier_state,
            statement: SampleQueriesStatement { log_n, t_num_queries: self.params.config.t_num_queries },
            inputs: (),
        )?;

        (proof.shift_query_answers.len() == self.params.config.t_num_queries)
            .then_some(())
            .ok_or(VerifierError::NumShiftQueries)?;

        let mut indexed: Vec<(usize, usize)> = queries
            .leaf_positions
            .iter()
            .copied()
            .enumerate()
            .map(|(row, pos)| (pos, row))
            .collect();
        indexed.sort_by_key(|&(pos, _)| pos);
        indexed.dedup_by_key(|&mut (pos, _)| pos);
        let sorted_unique: Vec<usize> = indexed.iter().map(|&(p, _)| p).collect();
        let row_indices: Vec<usize> = indexed.iter().map(|&(_, r)| r).collect();

        // Column tuples for the fresh PESAT commitment: per query, the
        // l1 values from `shift_query_answers[row][l2..]`.
        let fresh_values: Vec<Vec<F>> = row_indices
            .iter()
            .map(|&r| {
                proof.shift_query_answers[r][self.params.config.l2_second_fold_factor..].to_vec()
            })
            .collect();

        // Per-acc column tuples (each acc has m=1 so each tuple is length 1).
        let acc_values: Vec<Vec<Vec<F>>> = (0..self.params.config.l2_second_fold_factor)
            .map(|j| {
                row_indices
                    .iter()
                    .map(|&r| vec![proof.shift_query_answers[r][j]])
                    .collect()
            })
            .collect();

        // Batching consumes its transcript bytes BEFORE the proximity
        // opens (matches the prover's order: ...→Batching→Proximity opens).
        let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &gamma_sumcheck_challenges);
        let mut nu_i_oracle_evals = Vec::with_capacity(
            1 + self.params.config.s_num_ood_samples + self.params.config.t_num_queries,
        );
        nu_i_oracle_evals.push(nu_0_oracle_eval);
        nu_i_oracle_evals.extend(answers);
        for v_jk in proof.shift_query_answers.iter() {
            let nu_st = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(F::zero(), |acc, (v, eq)| acc + *eq * *v);
            nu_i_oracle_evals.push(nu_st);
        }

        let ark_iop::IorVerifyResult {
            reduced:
                BatchingReducedStatement {
                    alpha_sumcheck_challenges,
                },
            outputs: _,
        } = ark_iop::verify_ior!(
            batching_ior,
            verifier_state,
            statement: BatchingStatement::from_ior_outputs(
                zeta_0.clone(),
                &samples_flat,
                &queries.evaluation_points,
                self.params.config.s_num_ood_samples,
                self.params.config.t_num_queries,
                log_n,
            ),
            inputs: BatchingVerifierInputs {
                nus_claimed_evals: nu_i_oracle_evals,
                acc_mu: acc_mu_first,
            },
        )?;

        // Now consume opening proofs from the transcript (in the same
        // order the prover wrote them: fresh first, then each acc).
        let mut rng = OsRng;
        V::check_multiple(
            &self.params.vk,
            &rt_0_fresh_commitment,
            sorted_unique.iter().copied(),
            fresh_values.iter().cloned(),
            &mut rng,
            verifier_state,
        )
        .map_err(|_| VerifierError::ShiftQuery)?;

        for (j, commitment) in l2_commitments.iter().enumerate() {
            V::check_multiple(
                &self.params.vk,
                commitment,
                sorted_unique.iter().copied(),
                acc_values[j].iter().cloned(),
                &mut rng,
                verifier_state,
            )
            .map_err(|_| VerifierError::ShiftQuery)?;
        }

        // Hand pre-validated lookup handles to the proximity IOR.
        let fresh_handle = ValidatedOracle::new(sorted_unique.clone(), fresh_values);
        let acc_handles: Vec<ValidatedOracle<F>> = acc_values
            .into_iter()
            .map(|vals| ValidatedOracle::new(sorted_unique.clone(), vals))
            .collect();

        ark_iop::verify_ior!(
            proximity_ior,
            verifier_state,
            statement: ProximityStatement {
                queries: queries.clone(),
                l2_second_fold_factor: self.params.config.l2_second_fold_factor,
                t_num_queries: self.params.config.t_num_queries,
                n_code_len,
            },
            inputs: ProximityVerifierInputs {
                fresh: &fresh_handle,
                acc: &acc_handles,
                _f: PhantomData,
            },
        )?;

        (acc_alpha_first == alpha_sumcheck_challenges)
            .then_some(())
            .ok_or(VerifierError::CodeEvaluationPoint)?;

        let betas = l2_taus
            .into_iter()
            .chain(taus_zero_check_challenges)
            .zip(l2_xs.into_iter().chain(l1_xs))
            .map(|(tau_i, x)| concat_slices(&tau_i, &x))
            .collect::<Vec<Vec<F>>>();
        let beta = scale_and_sum(&betas, &gamma_eq_evals);
        let expected_beta = concat_slices(&acc_beta_0_first, &acc_beta_1_first);
        (expected_beta == beta)
            .then_some(())
            .ok_or(VerifierError::CircuitEvaluationPoint)?;

        Ok(())
    }
}

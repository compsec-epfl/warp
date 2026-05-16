use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_std::log2;
use ark_vc::mvc::MultiVectorCommitment;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};
use std::marker::PhantomData;

use crate::accumulation_scheme::accumulator::{
    AccumulatorInstance, AccumulatorWitness, BetaTwinPair,
};
use crate::accumulation_scheme::keys::WarpProverKey;
use crate::accumulation_scheme::proof::{ProveResult, WarpProof};
use crate::accumulation_scheme::scheme::WarpAccumulationScheme;
use crate::accumulation_scheme::transcript::absorb_instances;
use crate::accumulation_scheme::AccumulationScheme;
use crate::count_ops;
use crate::error::ProverError;
use crate::iop::iors::{
    batching::{
        Batching, BatchingProverInputs, BatchingReducedStatement, BatchingReducedWitness,
        BatchingStatement,
    },
    bridge::{
        Bridge, BridgeProverInputs, BridgeReducedStatement, BridgeReducedWitness, BridgeStatement,
        BridgeWitness,
    },
    ood::{Ood, OodProverInputs, OodReducedStatement, OodStatement},
    pesat::{Pesat, PesatReducedStatement, PesatReducedWitness, PesatStatement, PesatWitness},
    proximity::{Proximity, ProximityProofString, ProximityProverInputs, ProximityStatement},
    sample_queries::{SampleQueries, SampleQueriesReducedStatement, SampleQueriesStatement},
    twin_constraint::{
        TwinConstraint, TwinConstraintProverInputs, TwinConstraintReducedStatement,
        TwinConstraintReducedWitness, TwinConstraintStatement, TwinConstraintWitness,
    },
};
use crate::relations::PolyPredicate;

impl<F, P, C, V> WarpAccumulationScheme<F, P, C, V>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + PolyPredicate<F, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    V: MultiVectorCommitment<Alphabet = F, Index = usize>,
    V::Commitment: Encoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    fn validate_prover_inputs(
        &self,
        pk: &WarpProverKey<P>,
        instances: &[Vec<F>],
        witnesses: &[Vec<F>],
        acc_instance: &AccumulatorInstance<F, V>,
        acc_witness: &AccumulatorWitness<F, V>,
    ) -> Result<(), ProverError> {
        if instances.len() < 2 {
            return Err(ProverError::InsufficientInstances {
                got: instances.len(),
            });
        }
        if witnesses.len() != instances.len() {
            return Err(ProverError::InstanceWitnessLengthMismatch {
                instances: instances.len(),
                witnesses: witnesses.len(),
            });
        }
        if acc_witness.td_committed_codewords.len() != acc_instance.rt_commitments.len() {
            return Err(ProverError::AccumulatorShapeMismatch {
                instances: acc_instance.rt_commitments.len(),
                roots: acc_witness.td_committed_codewords.len(),
            });
        }
        let l = self.params.config.l_total_fold_factor();
        if !l.is_power_of_two() {
            return Err(ProverError::ConfigParameterInvalid {
                reason: format!(
                    "l1_first_fold_factor + l2_second_fold_factor = {l} is not a power of two"
                ),
            });
        }
        if pk.m_num_constraints == 0 || pk.n_num_variables == 0 {
            return Err(ProverError::ConfigParameterInvalid {
                reason: format!(
                    "pk.m_num_constraints = {} and pk.n_num_variables = {} must both be > 0",
                    pk.m_num_constraints, pk.n_num_variables
                ),
            });
        }
        if pk.n_num_variables < pk.k_num_witness_vars {
            return Err(ProverError::ConfigParameterInvalid {
                reason: format!(
                    "pk.n_num_variables ({}) < pk.k_num_witness_vars ({})",
                    pk.n_num_variables, pk.k_num_witness_vars
                ),
            });
        }
        let expected_instance_len = pk.n_num_variables - pk.k_num_witness_vars;
        if instances[0].len() != expected_instance_len {
            return Err(ProverError::InstanceLengthMismatch {
                expected: expected_instance_len,
                got: instances[0].len(),
            });
        }
        Ok(())
    }

    #[tracing::instrument(name = "warp.prove", skip_all)]
    pub fn prove(
        &self,
        pk: WarpProverKey<P>,
        prover_state: &mut ProverState,
        witnesses: Vec<Vec<F>>,
        instances: Vec<Vec<F>>,
        acc_instance: AccumulatorInstance<F, V>,
        acc_witness: AccumulatorWitness<F, V>,
    ) -> ProveResult<F, V> {
        self.validate_prover_inputs(&pk, &instances, &witnesses, &acc_instance, &acc_witness)?;

        let log_l = log2(self.params.config.l_total_fold_factor()) as usize;
        let log_m = log2(pk.m_num_constraints) as usize;
        let n_code_len = self.params.code.code_len();
        let log_n = log2(n_code_len) as usize;
        let n_minus_k = pk.n_num_variables - pk.k_num_witness_vars;

        self.absorb_scheme_prologue_prover(prover_state);

        absorb_instances(prover_state, &instances);
        acc_instance.absorb_into(prover_state);

        let AccumulatorWitness {
            td_committed_codewords: acc_tds,
            w_witnesses: acc_ws,
        } = acc_witness;
        let acc_fs: Vec<Vec<F>> = acc_tds.iter().map(|td| td.codewords[0].clone()).collect();

        let pesat_ior = Pesat::<F, C, V> {
            code: &self.params.code,
            ck: &self.params.ck,
        };
        let twin_constraint_ior = TwinConstraint::<F, V>::new(self.params.predicate.constraints());
        let bridge_ior = Bridge::<F, P, V>::default();
        let ood_ior = Ood::<F>::default();
        let sample_queries_ior = SampleQueries::<F>::default();
        let batching_ior = Batching::<F>::default();
        let proximity_ior = Proximity::<F>::default();

        let ark_iop::IorProveResult {
            reduced:
                PesatReducedStatement {
                    mus_codeword_first_coords,
                    taus_zero_check_challenges,
                },
            proof: _,
            witness:
                PesatReducedWitness {
                    codewords,
                    td_0_committed_codeword,
                },
        } = ark_iop::prove_ior!(
            pesat_ior,
            prover_state,
            statement: PesatStatement {
                l1_first_fold_factor: self.params.config.l1_first_fold_factor,
                log_m,
            },
            witness: PesatWitness { witnesses: &witnesses },
            inputs: (),
        )?;

        let ark_iop::IorProveResult {
            reduced:
                TwinConstraintReducedStatement {
                    gamma_sumcheck_challenges: _,
                    zeta_0,
                    beta_tau,
                    deferred: _,
                },
            proof: _,
            witness:
                TwinConstraintReducedWitness {
                    f_oracle,
                    z_witness_assignment,
                },
        } = ark_iop::prove_ior!(
            twin_constraint_ior,
            prover_state,
            statement: TwinConstraintStatement {
                acc_instance,
                l1_mus_codeword_first_coords: mus_codeword_first_coords.clone(),
                l1_taus_zero_check_challenges: taus_zero_check_challenges,
                log_l,
                log_m,
                log_n,
            },
            witness: TwinConstraintWitness {
                acc_witness_w: &acc_ws,
                instances: &instances,
                witnesses: &witnesses,
            },
            inputs: TwinConstraintProverInputs {
                fresh_codewords: &codewords,
                acc_codewords: &acc_fs,
            },
        )?;

        let ark_iop::IorProveResult {
            reduced:
                BridgeReducedStatement {
                    eta_predicate_eval,
                    nu_0_oracle_eval,
                    td_new_commitment: _,
                },
            proof: _,
            witness:
                BridgeReducedWitness {
                    td_new,
                    new_x,
                    new_w,
                },
        } = ark_iop::prove_ior!(
            bridge_ior,
            prover_state,
            statement: BridgeStatement {
                zeta_0: zeta_0.clone(),
                beta_tau: beta_tau.clone(),
                log_m,
                n_minus_k,
            },
            witness: BridgeWitness {
                z_witness_assignment: &z_witness_assignment,
                f_oracle: &f_oracle,
            },
            inputs: BridgeProverInputs {
                predicate: &self.params.predicate,
                ck: &self.params.ck,
                _f: PhantomData,
            },
        )?;

        let ark_iop::IorProveResult {
            reduced:
                OodReducedStatement {
                    samples_flat,
                    answers,
                },
            proof: _,
            witness: _,
        } = ark_iop::prove_ior!(
            ood_ior,
            prover_state,
            statement: OodStatement { s_num_ood_samples: self.params.config.s_num_ood_samples, log_n },
            witness: (),
            inputs: OodProverInputs { oracle: &f_oracle },
        )?;

        let ark_iop::IorProveResult {
            reduced: SampleQueriesReducedStatement { queries },
            proof: _,
            witness: _,
        } = ark_iop::prove_ior!(
            sample_queries_ior,
            prover_state,
            statement: SampleQueriesStatement { log_n, t_num_queries: self.params.config.t_num_queries },
            witness: (),
            inputs: (),
        )?;

        let ark_iop::IorProveResult {
            reduced:
                BatchingReducedStatement {
                    alpha_sumcheck_challenges,
                },
            proof: _,
            witness: BatchingReducedWitness { mu_claimed_eval },
        } = ark_iop::prove_ior!(
            batching_ior,
            prover_state,
            statement: BatchingStatement::from_ior_outputs(
                zeta_0.clone(),
                &samples_flat,
                &queries.evaluation_points,
                self.params.config.s_num_ood_samples,
                self.params.config.t_num_queries,
                log_n,
            ),
            witness: (),
            inputs: BatchingProverInputs { oracle: &f_oracle },
        )?;

        let acc_codewords_refs: Vec<&[Vec<F>]> =
            acc_tds.iter().map(|td| td.codewords.as_slice()).collect();
        let fresh_codewords_ref: &[Vec<F>] = td_0_committed_codeword.codewords.as_slice();

        let ark_iop::IorProveResult {
            reduced: _,
            proof: ProximityProofString {
                shift_query_answers,
            },
            witness: _,
        } = ark_iop::prove_ior!(
            proximity_ior,
            prover_state,
            statement: ProximityStatement {
                queries: queries.clone(),
                l2_second_fold_factor: self.params.config.l2_second_fold_factor,
                t_num_queries: self.params.config.t_num_queries,
                n_code_len,
            },
            witness: (),
            inputs: ProximityProverInputs {
                acc_codewords: &acc_codewords_refs,
                fresh_codewords: fresh_codewords_ref,
            },
        )?;

        // FS ordering: Proximity prologue → auth paths. Opens live in the
        // orchestrator (not in Proximity) so the IOR stays VC-agnostic.
        // Verifier mirror at the matching site in `verify.rs`.
        let leaf_positions = &queries.leaf_positions;
        let mut sorted_unique = leaf_positions.clone();
        sorted_unique.sort_unstable();
        sorted_unique.dedup();
        let column_tuples = |codewords: &[Vec<F>]| -> Vec<Vec<F>> {
            sorted_unique
                .iter()
                .map(|&i| codewords.iter().map(|c| c[i]).collect())
                .collect()
        };

        {
            let _s = tracing::info_span!("proximity.auth_0").entered();
            count_ops!(MerklePathsGenerated, sorted_unique.len() as u64);
            let values = column_tuples(&td_0_committed_codeword.codewords);
            V::open_multiple(
                &self.params.ck,
                td_0_committed_codeword.codewords.iter().map(|c| c.iter()),
                &td_0_committed_codeword.commitment,
                sorted_unique.iter().copied(),
                values.into_iter(),
                &td_0_committed_codeword.state,
                prover_state,
            )
            .map_err(|_| ProverError::SpongeFish)?;
        }

        {
            let _s = tracing::info_span!("proximity.auth_j").entered();
            count_ops!(
                MerklePathsGenerated,
                (acc_tds.len() * sorted_unique.len()) as u64
            );
            for td in acc_tds.iter() {
                let values = column_tuples(&td.codewords);
                V::open_multiple(
                    &self.params.ck,
                    td.codewords.iter().map(|c| c.iter()),
                    &td.commitment,
                    sorted_unique.iter().copied(),
                    values.into_iter(),
                    &td.state,
                    prover_state,
                )
                .map_err(|_| ProverError::SpongeFish)?;
            }
        }

        let mut nu_i_oracle_evals = Vec::with_capacity(1 + self.params.config.s_num_ood_samples);
        nu_i_oracle_evals.push(nu_0_oracle_eval);
        nu_i_oracle_evals.extend(answers);

        let new_acc_instance = AccumulatorInstance {
            rt_commitments: vec![td_new.commitment.clone()],
            alpha_fold_vectors: vec![alpha_sumcheck_challenges],
            mu_claimed_evals: vec![mu_claimed_eval],
            beta_twin_pairs: vec![BetaTwinPair {
                tau: beta_tau,
                x: new_x,
            }],
            eta_predicate_evals: vec![eta_predicate_eval],
        };
        let new_acc_witness = AccumulatorWitness {
            td_committed_codewords: vec![td_new],
            w_witnesses: vec![new_w],
        };
        let proof = WarpProof {
            rt_0_fresh_commitment: td_0_committed_codeword.commitment.clone(),
            mu_i_first_codeword_coords: mus_codeword_first_coords,
            nu_0_oracle_eval,
            nu_i_oracle_evals,
            shift_query_answers,
        };

        Ok(((new_acc_instance, new_acc_witness), proof))
    }
}

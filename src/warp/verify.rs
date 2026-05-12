use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use ark_std::log2;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, VerifierState};
use std::marker::PhantomData;

use crate::crypto::merkle::warp_scheme;
use crate::error::VerifierError;
use crate::protocol::ior::IorVerifyResult;
use crate::protocol::iors::{
    batching::{
        Batching, BatchingReducedStatement, BatchingStatement, BatchingVerifierInputs,
    },
    bridge::{Bridge, BridgeReducedStatement, BridgeStatement, BridgeVerifierInputs},
    ood::{Ood, OodReducedStatement, OodStatement},
    pesat::{Pesat, PesatReducedStatement, PesatStatement, PesatVerifierOutputs},
    proximity::{Proximity, ProximityStatement, ProximityVerifierInputs},
    sample_queries::{SampleQueries, SampleQueriesReducedStatement, SampleQueriesStatement},
    twin_constraint::{TwinConstraint, TwinConstraintReducedStatement, TwinConstraintStatement},
};
use crate::protocol::oracles::indexed_merkle::MerkleIndexedOracle;
use crate::protocol::transcript::parse_statement;
use crate::relations::{r1cs::R1CSConstraints, BundledPESAT};
use crate::utils::{concat_slices, scale_and_sum};
use crate::verify_ior;
use crate::warp::accumulator::AccumulatorInstance;
use crate::warp::keys::WARPVerifierKey;
use crate::warp::proof::WARPProof;
use crate::warp::scheme::WARP;

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    pub(crate) fn verify_impl<'a>(
        &self,
        vk: WARPVerifierKey,
        verifier_state: &mut VerifierState<'a>,
        acc_instance: AccumulatorInstance<F, H>,
        proof: WARPProof<F, H>,
    ) -> Result<(), VerifierError> {
        let (l1, l) = (self.params.config.l1, self.params.config.l);
        let l2 = l - l1;

        #[allow(non_snake_case)]
        let (M, N, k) = (vk.m, vk.n, vk.k);
        let (log_m, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.params.code.code_len();
        let log_n = log2(n) as usize;

        let (l1_xs, parsed_acc) =
            parse_statement::<F, H>(verifier_state, l1, l2, N - k, log_n, log_m)?;

        let acc_alpha_first = acc_instance.alpha[0].clone();
        let acc_beta_0_first = acc_instance.beta.0[0].clone();
        let acc_beta_1_first = acc_instance.beta.1[0].clone();
        let acc_mu_first = acc_instance.mu[0];
        let l2_taus = parsed_acc.beta.0.clone();
        let l2_xs = parsed_acc.beta.1.clone();
        let l2_roots = parsed_acc.rt.clone();

        let pesat_ior = Pesat::<F, C, H> {
            code: &self.params.code,
            hasher: &self.params.hasher,
            _phantom: PhantomData,
        };
        let twin_constraint_ior = TwinConstraint::<F, H> {
            r1cs: self.params.p.constraints(),
            _phantom: PhantomData,
        };
        let bridge_ior = Bridge::<F, P, H>::new();
        let ood_ior = Ood::<F>::new();
        let sample_queries_ior = SampleQueries::<F>::new();
        let batching_ior = Batching::<F>::new();
        let proximity_ior = Proximity::<F, H> {
            hasher: &self.params.hasher,
            _phantom: PhantomData,
        };

        // ── IOR 1: PESAT ─────────────────────────────────────────────
        let IorVerifyResult {
            reduced: PesatReducedStatement {
                mus: l1_mus,
                taus: l1_taus,
            },
            outputs: PesatVerifierOutputs { rt_0 },
        } = verify_ior!(
            pesat_ior,
            verifier_state,
            statement: PesatStatement { l1, log_m },
            inputs: (),
        )?;

        // ── IOR 2: TwinConstraint ────────────────────────────────────
        let IorVerifyResult {
            reduced: TwinConstraintReducedStatement {
                gamma,
                zeta_0,
                beta_tau,
                deferred,
            },
            outputs: _,
        } = verify_ior!(
            twin_constraint_ior,
            verifier_state,
            statement: TwinConstraintStatement {
                acc_instance: parsed_acc,
                l1_mus: l1_mus.clone(),
                l1_taus: l1_taus.clone(),
                log_l,
                log_m,
                log_n,
            },
            inputs: (),
        )?;

        // ── IOR 3: Bridge ────────────────────────────────────────────
        let IorVerifyResult {
            reduced: BridgeReducedStatement {
                eta: _,
                nu_0,
                td_new_root: _,
            },
            outputs: _,
        } = verify_ior!(
            bridge_ior,
            verifier_state,
            statement: BridgeStatement {
                zeta_0: zeta_0.clone(),
                beta_tau,
                log_m,
                n_minus_k: N - k,
            },
            inputs: BridgeVerifierInputs {
                deferred: &deferred,
                gamma: &gamma,
            },
        )?;

        // ── IOR 4: OOD ───────────────────────────────────────────────
        let IorVerifyResult {
            reduced: OodReducedStatement { samples_flat, answers },
            outputs: _,
        } = verify_ior!(
            ood_ior,
            verifier_state,
            statement: OodStatement { s: self.params.config.s, log_n },
            inputs: (),
        )?;

        // ── IOR 5: SampleQueries ─────────────────────────────────────
        let IorVerifyResult {
            reduced: SampleQueriesReducedStatement { queries },
            outputs: _,
        } = verify_ior!(
            sample_queries_ior,
            verifier_state,
            statement: SampleQueriesStatement { log_n, t: self.params.config.t },
            inputs: (),
        )?;

        (proof.shift_query_answers.len() == self.params.config.t)
            .then_some(())
            .ok_or(VerifierError::NumShiftQueries)?;
        (proof.auth_j.len() == l2)
            .then_some(())
            .ok_or(VerifierError::NumL2Instances)?;

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

        let fresh_values: Vec<Vec<F>> = row_indices
            .iter()
            .map(|&r| proof.shift_query_answers[r][l2..].to_vec())
            .collect();
        let fresh_handle = MerkleIndexedOracle::new(
            warp_scheme::<H, F>(self.params.hasher.clone(), n),
            &rt_0,
            &proof.auth_0,
            sorted_unique.clone(),
            fresh_values,
        );

        let acc_handles: Vec<MerkleIndexedOracle<F, H>> = (0..l2)
            .map(|j| {
                let acc_values: Vec<Vec<F>> = row_indices
                    .iter()
                    .map(|&r| vec![proof.shift_query_answers[r][j]])
                    .collect();
                MerkleIndexedOracle::new(
                    warp_scheme::<H, F>(self.params.hasher.clone(), n),
                    &l2_roots[j],
                    &proof.auth_j[j],
                    sorted_unique.clone(),
                    acc_values,
                )
            })
            .collect();

        // ── IOR 7: Proximity ─────────────────────────────────────────
        verify_ior!(
            proximity_ior,
            verifier_state,
            statement: ProximityStatement {
                queries: queries.clone(),
                l2,
                t: self.params.config.t,
                n,
            },
            inputs: ProximityVerifierInputs {
                fresh: &fresh_handle,
                acc: &acc_handles,
                _f: PhantomData,
            },
        )?;

        let gamma_eq_evals = compute_hypercube_eq_evals(log_l, &gamma);
        let mut nus = Vec::with_capacity(1 + self.params.config.s + self.params.config.t);
        nus.push(nu_0);
        nus.extend(answers);
        for v_jk in proof.shift_query_answers.iter() {
            let nu_st = v_jk
                .iter()
                .zip(&gamma_eq_evals)
                .fold(F::zero(), |acc, (v, eq)| acc + *eq * *v);
            nus.push(nu_st);
        }

        // ── IOR 6: Batching ──────────────────────────────────────────
        let IorVerifyResult {
            reduced: BatchingReducedStatement { alpha },
            outputs: _,
        } = verify_ior!(
            batching_ior,
            verifier_state,
            statement: BatchingStatement::from_ior_outputs(
                zeta_0.clone(),
                &samples_flat,
                &queries.evaluation_points,
                self.params.config.s,
                self.params.config.t,
                log_n,
            ),
            inputs: BatchingVerifierInputs {
                nus,
                acc_mu: acc_mu_first,
            },
        )?;

        (acc_alpha_first == alpha)
            .then_some(())
            .ok_or(VerifierError::CodeEvaluationPoint)?;

        let betas = l2_taus
            .into_iter()
            .chain(l1_taus)
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

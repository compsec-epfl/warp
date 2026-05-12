use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use ark_std::log2;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState};
use std::marker::PhantomData;

use crate::error::ProverError;
use crate::prove_ior;
use crate::protocol::ior::IorProveResult;
use crate::protocol::iors::{
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
use crate::protocol::transcript::absorb_instances;
use crate::relations::{r1cs::R1CSConstraints, BundledPESAT};
use crate::warp::accumulator::{AccumulatorInstance, AccumulatorWitness};
use crate::warp::keys::WARPProverKey;
use crate::warp::proof::{ProveResult, WARPProof};
use crate::warp::scheme::WARP;

impl<F, P, C, H> WARP<F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: Clone + BundledPESAT<F, Constraints = R1CSConstraints<F>, Config = (usize, usize, usize)>,
    C: LinearCode<F> + Clone,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargSerialize + NargDeserialize + Clone + Eq,
{
    #[tracing::instrument(name = "warp.prove", skip_all)]
    pub(crate) fn prove_impl(
        &self,
        pk: WARPProverKey<P>,
        prover_state: &mut ProverState,
        witnesses: Vec<Vec<F>>,
        instances: Vec<Vec<F>>,
        acc_instance: AccumulatorInstance<F, H>,
        acc_witness: AccumulatorWitness<F, H>,
    ) -> ProveResult<F, H> {
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
        if acc_witness.td.len() != acc_instance.rt.len() {
            return Err(ProverError::AccumulatorShapeMismatch {
                instances: acc_instance.rt.len(),
                roots: acc_witness.td.len(),
            });
        }

        let (l1, l) = (self.params.config.l1, self.params.config.l);
        let l2 = l - l1;
        if !l.is_power_of_two() {
            return Err(ProverError::ConfigParameterInvalid {
                reason: format!("config.l = {l} is not a power of two"),
            });
        }

        #[allow(non_snake_case)]
        let (M, N, k) = (pk.m, pk.n, pk.k);
        let (log_m, log_l) = (log2(M) as usize, log2(l) as usize);
        let n = self.params.code.code_len();
        let log_n = log2(n) as usize;

        if instances[0].len() != N - k {
            return Err(ProverError::InstanceLengthMismatch {
                expected: N - k,
                got: instances[0].len(),
            });
        }
        absorb_instances(prover_state, &instances);
        acc_instance.absorb_into(prover_state);

        let AccumulatorWitness {
            td: acc_tds,
            w: acc_ws,
        } = acc_witness;
        let acc_fs: Vec<Vec<F>> = acc_tds.iter().map(|td| td.codewords()[0].clone()).collect();

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
        let IorProveResult {
            reduced: PesatReducedStatement { mus, taus },
            proof: _,
            witness: PesatReducedWitness { codewords, td_0 },
        } = prove_ior!(
            pesat_ior,
            prover_state,
            statement: PesatStatement { l1, log_m },
            witness: PesatWitness { witnesses: &witnesses },
            inputs: (),
        )?;

        // ── IOR 2: TwinConstraint ────────────────────────────────────
        let IorProveResult {
            reduced: TwinConstraintReducedStatement {
                gamma: _,
                zeta_0,
                beta_tau,
                deferred: _,
            },
            proof: _,
            witness: TwinConstraintReducedWitness { f, z },
        } = prove_ior!(
            twin_constraint_ior,
            prover_state,
            statement: TwinConstraintStatement {
                acc_instance,
                l1_mus: mus.clone(),
                l1_taus: taus,
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

        // ── IOR 3: Bridge ────────────────────────────────────────────
        let IorProveResult {
            reduced: BridgeReducedStatement {
                eta,
                nu_0,
                td_new_root: _,
            },
            proof: _,
            witness: BridgeReducedWitness { td_new, new_x, new_w },
        } = prove_ior!(
            bridge_ior,
            prover_state,
            statement: BridgeStatement {
                zeta_0: zeta_0.clone(),
                beta_tau: beta_tau.clone(),
                log_m,
                n_minus_k: N - k,
            },
            witness: BridgeWitness { z: &z, f: &f },
            inputs: BridgeProverInputs {
                bundled_pesat: &self.params.p,
                hasher: &self.params.hasher,
                code_len: n,
                _f: PhantomData,
            },
        )?;

        // ── IOR 4: OOD ───────────────────────────────────────────────
        let IorProveResult {
            reduced: OodReducedStatement { samples_flat, answers },
            proof: _,
            witness: _,
        } = prove_ior!(
            ood_ior,
            prover_state,
            statement: OodStatement { s: self.params.config.s, log_n },
            witness: (),
            inputs: OodProverInputs { oracle: &f },
        )?;

        // ── IOR 5: SampleQueries ─────────────────────────────────────
        let IorProveResult {
            reduced: SampleQueriesReducedStatement { queries },
            proof: _,
            witness: _,
        } = prove_ior!(
            sample_queries_ior,
            prover_state,
            statement: SampleQueriesStatement { log_n, t: self.params.config.t },
            witness: (),
            inputs: (),
        )?;

        // ── IOR 6: Batching ──────────────────────────────────────────
        let IorProveResult {
            reduced: BatchingReducedStatement { alpha },
            proof: _,
            witness: BatchingReducedWitness { mu },
        } = prove_ior!(
            batching_ior,
            prover_state,
            statement: BatchingStatement::from_ior_outputs(
                zeta_0.clone(),
                &samples_flat,
                &queries.evaluation_points,
                self.params.config.s,
                self.params.config.t,
                log_n,
            ),
            witness: (),
            inputs: BatchingProverInputs { oracle: &f },
        )?;

        // ── IOR 7: Proximity ─────────────────────────────────────────
        let IorProveResult {
            reduced: _,
            proof: ProximityProofString {
                auth_0,
                auth_j,
                shift_query_answers,
            },
            witness: _,
        } = prove_ior!(
            proximity_ior,
            prover_state,
            statement: ProximityStatement {
                queries: queries.clone(),
                l2,
                t: self.params.config.t,
                n,
            },
            witness: (),
            inputs: ProximityProverInputs {
                td_0: &td_0,
                acc_td: &acc_tds,
            },
        )?;

        let mut nus = Vec::with_capacity(1 + self.params.config.s);
        nus.push(nu_0);
        nus.extend(answers);

        let new_acc_instance = AccumulatorInstance {
            rt: vec![td_new.root().clone()],
            alpha: vec![alpha],
            mu: vec![mu],
            beta: (vec![beta_tau], vec![new_x]),
            eta: vec![eta],
        };
        let new_acc_witness = AccumulatorWitness {
            td: vec![td_new],
            w: vec![new_w],
        };
        let proof = WARPProof {
            rt_0: td_0.root().clone(),
            mu_i: mus,
            nu_0,
            nu_i: nus,
            auth_0,
            auth_j,
            shift_query_answers,
        };

        Ok(((new_acc_instance, new_acc_witness), proof))
    }
}

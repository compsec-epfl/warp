//! Negative-path verifier tests: tamper one field of a valid proof, assert
//! the specific expected `VerifierError`. `SpongeFish` / `SumcheckRound`
//! aren't reachable via proof-object tampering and aren't covered here.

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use ark_vc::{mvc::MultiVectorCommitment, vc::VectorCommitment};

use warp::accumulation_scheme::{
    AccumulatorInstance, AccumulatorWitness, WarpProof, WarpProverKey, WarpVerifierKey,
};
use warp::config::WarpConfig;
use warp::error::VerifierError;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Arithmetize, Relation,
};
use warp::utils::poseidon;
use warp::WarpAccumulationScheme;

type F = BLS12_381;
type V = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;
type WarpT = WarpAccumulationScheme<F, R1CS<F>, ReedSolomon<F>, V>;

fn build_keys(
    code_len: usize,
    num_queries: usize,
) -> (
    <V as VectorCommitment>::CommitterKey,
    <V as VectorCommitment>::VerifierKey,
) {
    let mut rng = thread_rng();
    let pp = <V as MultiVectorCommitment>::setup_multiple(0, code_len, num_queries, &mut rng)
        .expect("setup_multiple");
    <V as MultiVectorCommitment>::trim_multiple(&pp, 0, code_len, num_queries)
        .expect("trim_multiple")
}

/// Everything the verifier needs to re-check, plus enough dimensions
/// to re-derive the verifier state.
struct Fixture {
    warp: WarpT,
    vk: WarpVerifierKey,
    acc_x: AccumulatorInstance<F, V>,
    proof: WarpProof<F, V>,
    narg_str: Vec<u8>,
}

impl Fixture {
    fn verify(
        &self,
        acc_x: AccumulatorInstance<F, V>,
        proof: WarpProof<F, V>,
    ) -> Result<(), VerifierError> {
        let domainsep_v = spongefish::domain_separator!("test::warp::negative");
        let mut verifier_state = domainsep_v
            .without_session()
            .instance(&0u32)
            .std_verifier(&self.narg_str);
        self.warp.verify(self.vk, &mut verifier_state, acc_x, proof)
    }
}

/// Build a real proof against the hash-chain relation, with both fresh
/// and accumulated components so negative tests can target any field.
fn make_fixture() -> Fixture {
    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<F>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    );
    let code = ReedSolomon::new(code_config);

    let (instances, witnesses): (Vec<_>, Vec<_>) = (0..l1)
        .map(|_| {
            let preimage = vec![F::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<F, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hash_chain_size,
                ),
            };
            let witness = HashChainWitness::<F, CRH<F>>::new(preimage);
            let relation = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    // Phase 1: produce `l1` single-round acc states so we have a non-trivial
    // accumulator to feed phase 2 (l2 > 0 so NumL2Instances is reachable).
    let warp_cfg1 = WarpConfig::new(l1, 0, s, t);
    let (ck1, vk1) = build_keys(code.code_len(), t);
    let w1 = WarpAccumulationScheme::<F, R1CS<F>, _, V>::new(
        warp_cfg1,
        code.clone(),
        r1cs.clone(),
        ck1,
        vk1,
    );

    let mut acc_x = AccumulatorInstance::empty();
    let mut acc_w = AccumulatorWitness::empty();

    for _ in 0..l1 {
        let ds = spongefish::domain_separator!("test::warp::negative");
        let mut ps = ds.without_session().instance(&0u32).std_prover();
        let ((new_x, new_w), _) = w1
            .prove(
                WarpProverKey {
                    index: r1cs.clone(),
                    m_num_constraints: r1cs.m_num_constraints,
                    n_num_variables: r1cs.n_num_variables,
                    k_num_witness_vars: r1cs.k_num_witness_vars,
                },
                &mut ps,
                witnesses.clone(),
                instances.clone(),
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap();
        acc_x = acc_x.extend(new_x);
        acc_w = acc_w.extend(new_w);
    }

    // Phase 2: the "real" prove with l2 > 0 accumulated instances.
    let warp_cfg2 = WarpConfig::<_, R1CS<F>>::new(l1, 4, s, t);
    let (ck2, vk2) = build_keys(code.code_len(), t);
    let warp =
        WarpAccumulationScheme::<F, R1CS<F>, _, V>::new(warp_cfg2, code, r1cs.clone(), ck2, vk2);

    let ds = spongefish::domain_separator!("test::warp::negative");
    let mut ps = ds.without_session().instance(&0u32).std_prover();
    let ((acc_x, _acc_w), proof) = warp
        .prove(
            WarpProverKey {
                index: r1cs.clone(),
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut ps,
            witnesses,
            instances,
            acc_x,
            acc_w,
        )
        .unwrap();

    Fixture {
        warp,
        vk: WarpVerifierKey {
            m_num_constraints: r1cs.m_num_constraints,
            n_num_variables: r1cs.n_num_variables,
            k_num_witness_vars: r1cs.k_num_witness_vars,
        },
        acc_x,
        proof,
        narg_str: ps.narg_string().to_vec(),
    }
}

fn assert_err(result: Result<(), VerifierError>, expected: &str) {
    match result {
        Ok(()) => panic!("expected `{expected}`, got Ok(())"),
        Err(err) => {
            let dbg = format!("{err:?}");
            assert!(dbg.contains(expected), "expected `{expected}`, got `{dbg}`");
        }
    }
}

// Sanity check: a fresh fixture always verifies.
#[test]
fn happy_path_verifies() {
    let fix = make_fixture();
    fix.verify(fix.acc_x.clone(), fix.proof.clone())
        .expect("untampered proof must verify");
}

#[test]
fn tampered_alpha_raises_code_evaluation_point() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.alpha_fold_vectors[0][0] += F::from(1u64);
    assert_err(fix.verify(acc_x, fix.proof.clone()), "CodeEvaluationPoint");
}

#[test]
fn tampered_beta_tau_raises_circuit_evaluation_point() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.beta_twin_pairs[0].tau[0] += F::from(1u64);
    assert_err(
        fix.verify(acc_x, fix.proof.clone()),
        "CircuitEvaluationPoint",
    );
}

#[test]
fn tampered_beta_x_raises_circuit_evaluation_point() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.beta_twin_pairs[0].x[0] += F::from(1u64);
    assert_err(
        fix.verify(acc_x, fix.proof.clone()),
        "CircuitEvaluationPoint",
    );
}

#[test]
fn truncated_shift_query_answers_raises_num_shift_queries() {
    let fix = make_fixture();
    let mut proof = fix.proof.clone();
    proof.shift_query_answers.pop();
    assert_err(fix.verify(fix.acc_x.clone(), proof), "NumShiftQueries");
}

#[test]
fn tampered_shift_query_answer_raises_target() {
    let fix = make_fixture();
    let mut proof = fix.proof.clone();
    // With verify ordering Batching → check_multiple, Batching's final-claim
    // check (`Target`) fires before `check_multiple`'s root mismatch.
    proof.shift_query_answers[0][0] += F::from(1u64);
    assert_err(fix.verify(fix.acc_x.clone(), proof), "Target");
}

#[test]
fn tampered_mu_raises_target() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.mu_claimed_evals[0] += F::from(1u64);
    assert_err(fix.verify(acc_x, fix.proof.clone()), "Target");
}

#[test]
fn prove_rejects_mismatched_instance_witness_lengths() {
    use warp::error::ProverError;

    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 4;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<F>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    );
    let code = ReedSolomon::new(code_config);

    let (instances, witnesses): (Vec<_>, Vec<_>) = (0..l1)
        .map(|_| {
            let preimage = vec![F::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<F, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hash_chain_size,
                ),
            };
            let witness = HashChainWitness::<F, CRH<F>>::new(preimage);
            let relation = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    let warp_cfg = WarpConfig::new(l1, 0, s, t);
    let (ck, vk) = build_keys(code.code_len(), t);
    let warp =
        WarpAccumulationScheme::<F, R1CS<F>, _, V>::new(warp_cfg, code, r1cs.clone(), ck, vk);

    let mut witnesses_short = witnesses;
    witnesses_short.pop();

    let ds = spongefish::domain_separator!("test::warp::prove_negative");
    let mut ps = ds.without_session().instance(&0u32).std_prover();
    let result = warp.prove(
        WarpProverKey {
            index: r1cs.clone(),
            m_num_constraints: r1cs.m_num_constraints,
            n_num_variables: r1cs.n_num_variables,
            k_num_witness_vars: r1cs.k_num_witness_vars,
        },
        &mut ps,
        witnesses_short,
        instances,
        AccumulatorInstance::empty(),
        AccumulatorWitness::empty(),
    );

    let err = result
        .err()
        .expect("prove must reject mismatched instance/witness lengths");
    match err {
        ProverError::InstanceWitnessLengthMismatch {
            instances,
            witnesses,
        } => {
            assert_eq!(instances, l1);
            assert_eq!(witnesses, l1 - 1);
        }
        other => panic!("expected InstanceWitnessLengthMismatch, got {other:?}"),
    }
}

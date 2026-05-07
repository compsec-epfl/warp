//! Negative-path verifier tests.
//!
//! The existing `warp_test` exercises only the happy path. This file
//! covers the other direction: for each cleanly-triggerable
//! [`warp::error::VerifierError`] variant, produce a valid proof, tamper
//! with one field, and assert the verifier rejects the proof with the
//! *specific* expected error.
//!
//! Catches a class of bug that's otherwise invisible: "verifier looks
//! correct on valid proofs but accepts broken ones." Several real-world
//! SNARKs have shipped that way.
//!
//! Not every error variant is reachable through a one-field tamper.
//! Variants we don't cover here:
//!
//! - `SpongeFish` / `ArkError` wrap underlying errors; hitting them
//!   requires transcript-byte-level corruption rather than proof-object
//!   tampering, which would exercise spongefish/arkworks, not our code.
//! - `NumSumcheckRounds` is derived from the transcript; a sibling of
//!   `SpongeFish`.
//! - `SumcheckRound` is not raised from any code path right now.

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_mt::blake3::Blake3FieldHasher;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;

use warp::config::WARPConfig;
use warp::error::VerifierError;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    BundledPESAT, Relation, ToPolySystem,
};
use warp::traits::AccumulationScheme;
use warp::types::{AccumulatorInstance, AccumulatorWitness, WARPProof, WARPProverKey, WARPVerifierKey};
use warp::utils::poseidon;
use warp::WARP;

type F = BLS12_381;
type H = Blake3FieldHasher<F>;
type WarpT = WARP<F, R1CS<F>, ReedSolomon<F>, H>;

/// Everything the verifier needs to re-check, plus enough dimensions
/// to re-derive the verifier state.
struct Fixture {
    warp: WarpT,
    vk: WARPVerifierKey,
    acc_x: AccumulatorInstance<F, H>,
    proof: WARPProof<F, H>,
    narg_str: Vec<u8>,
}

impl Fixture {
    fn verify(
        &self,
        acc_x: AccumulatorInstance<F, H>,
        proof: WARPProof<F, H>,
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
    let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two());
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
    let warp_cfg1 = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
    let w1 = WARP::<F, R1CS<F>, _, H>::new(
        warp_cfg1,
        code.clone(),
        r1cs.clone(),
        Blake3FieldHasher::<F>::new(),
    );

    let mut acc_x = AccumulatorInstance::empty();
    let mut acc_w = AccumulatorWitness::empty();

    for _ in 0..l1 {
        let ds = spongefish::domain_separator!("test::warp::negative");
        let mut ps = ds.without_session().instance(&0u32).std_prover();
        let ((new_x, new_w), _) = w1
            .prove(
                WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
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
    let warp_cfg2 = WARPConfig::<_, R1CS<F>>::new(8, l1, s, t, r1cs.config(), code.code_len());
    let warp =
        WARP::<F, R1CS<F>, _, H>::new(warp_cfg2, code, r1cs.clone(), Blake3FieldHasher::<F>::new());

    let ds = spongefish::domain_separator!("test::warp::negative");
    let mut ps = ds.without_session().instance(&0u32).std_prover();
    let ((acc_x, _acc_w), proof) = warp
        .prove(
            WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
            &mut ps,
            witnesses,
            instances,
            acc_x,
            acc_w,
        )
        .unwrap();

    Fixture {
        warp,
        vk: WARPVerifierKey { m: r1cs.m, n: r1cs.n, k: r1cs.k },
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
    acc_x.alpha[0][0] += F::from(1u64);
    assert_err(fix.verify(acc_x, fix.proof.clone()), "CodeEvaluationPoint");
}

#[test]
fn tampered_beta_tau_raises_circuit_evaluation_point() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.beta.0[0][0] += F::from(1u64);
    assert_err(
        fix.verify(acc_x, fix.proof.clone()),
        "CircuitEvaluationPoint",
    );
}

#[test]
fn tampered_beta_x_raises_circuit_evaluation_point() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.beta.1[0][0] += F::from(1u64);
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
fn tampered_shift_query_answer_raises_shift_query() {
    let fix = make_fixture();
    let mut proof = fix.proof.clone();
    // Each row of shift_query_answers has l2 + l1 entries; tampering any
    // of them makes path.verify fail because the leaf hash no longer
    // matches the committed root.
    proof.shift_query_answers[0][0] += F::from(1u64);
    assert_err(fix.verify(fix.acc_x.clone(), proof), "ShiftQuery");
}

#[test]
fn truncated_auth_j_raises_num_l2_instances() {
    let fix = make_fixture();
    let mut proof = fix.proof.clone();
    proof.auth_j.pop();
    assert_err(fix.verify(fix.acc_x.clone(), proof), "NumL2Instances");
}

#[test]
fn tampered_mu_raises_target() {
    let fix = make_fixture();
    let mut acc_x = fix.acc_x.clone();
    acc_x.mu[0] += F::from(1u64);
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
    let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<F>::default(r1cs.k, r1cs.k.next_power_of_two());
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

    let warp_cfg = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
    let warp = WARP::<F, R1CS<F>, _, H>::new(
        warp_cfg,
        code,
        r1cs.clone(),
        Blake3FieldHasher::<F>::new(),
    );

    let mut witnesses_short = witnesses;
    witnesses_short.pop();

    let ds = spongefish::domain_separator!("test::warp::prove_negative");
    let mut ps = ds.without_session().instance(&0u32).std_prover();
    let result = warp.prove(
        WARPProverKey { index: r1cs.clone(), m: r1cs.m, n: r1cs.n, k: r1cs.k },
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

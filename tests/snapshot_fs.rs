//! Fiat-Shamir snapshot test — regression oracle for the ark-iop extraction.
//!
//! Captures byte-identical hashes of `narg_string` (transcript) and the
//! serialized proof for a fixed-seed warp run. Any change to the transcript
//! semantics (encoding order, byte layout, missing absorb, etc.) breaks this
//! test before it corrupts a real prover.

use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_ff::UniformRand;
use ark_mt::{
    blake3::Blake3FieldHasher, hash_region::HashRegion, scheme::MerkleCommitment,
    shape::PerfectBinary,
};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_vc::mvc::MultiVectorCommitment;

use warp::accumulation_scheme::{
    AccumulatorInstance, AccumulatorWitness, WarpProverKey, WarpVerifierKey,
};
use warp::config::WarpConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Arithmetize, Relation,
};
use warp::utils::{fields::Goldilocks, poseidon};
use warp::WarpAccumulationScheme;

type F = Goldilocks;
type VC = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

fn hex_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

// Snapshot constants; bump on intentional FS changes.
const EXPECTED_NARG_HASH: Option<&str> =
    Some("83e5f65136d0ab5571a4f4c49e254a6bc178a264def7fba256cbdbd444b0f80d");
const EXPECTED_NARG_LEN: Option<usize> = Some(1616);
const EXPECTED_PROOF_HASH: Option<&str> =
    Some("68aec437a44825f513f3b5bfa55049e2c466b533bb0aede65dc63c6f76b7ec9c");
const EXPECTED_PROOF_LEN: Option<usize> = Some(224);
// Sponge state at end-of-protocol must match prover ↔ verifier; squeezing a
// post-protocol challenge from each catches asymmetric `public_message`
// absorption that doesn't affect `narg_string` (e.g. swapped IOR prologue
// order around a delegated VC open).
const EXPECTED_SENTINEL: Option<&str> =
    Some("746e75e17fc638b3cc7d07e7bc8b21f4efa254faae123f13b9d5ee1fbadc22b4");

#[test]
fn fs_transcript_snapshot_goldilocks() {
    let mut rng = StdRng::seed_from_u64(0xFA1A_F542);
    // Compact but representative: exercises all 5 IORs at least once.
    let l1 = 2;
    let s = 2;
    let t = 4;
    let hash_chain_size = 4;

    let poseidon_config = poseidon::initialize_poseidon_config::<F>();
    let r1cs = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let code = ReedSolomon::new(ReedSolomonConfig::<F>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    ));

    let instances_witnesses: (Vec<Vec<F>>, Vec<Vec<F>>) = (0..l1)
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
            let rel = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (rel.x, rel.w)
        })
        .unzip();

    let warp_config = WarpConfig::new(l1, 0, s, t);
    let pp = <VC as MultiVectorCommitment>::setup_multiple(0, code.code_len(), t, &mut rng)
        .expect("setup_multiple");
    let (ck, vk) = <VC as MultiVectorCommitment>::trim_multiple(&pp, 0, code.code_len(), t)
        .expect("trim_multiple");
    let warp_inst =
        WarpAccumulationScheme::<F, R1CS<F>, _, VC>::new(warp_config, code, r1cs.clone(), ck, vk);

    let domainsep = spongefish::domain_separator!("test::snapshot");
    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
    let ((acc_x, _acc_w), pf) = warp_inst
        .prove(
            WarpProverKey {
                index: r1cs.clone(),
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut prover_state,
            instances_witnesses.1,
            instances_witnesses.0,
            AccumulatorInstance::empty(),
            AccumulatorWitness::empty(),
        )
        .unwrap();

    let narg = prover_state.narg_string().to_vec();
    let mut pf_bytes = Vec::new();
    pf.serialize_with_mode(&mut pf_bytes, Compress::Yes)
        .unwrap();

    let narg_hash = hex_hash(&narg);
    let pf_hash = hex_hash(&pf_bytes);

    // Run verify with the same domain separator and check the post-protocol
    // sponge state matches the prover's by squeezing a sentinel challenge.
    let domainsep_v = spongefish::domain_separator!("test::snapshot");
    let mut verifier_state = domainsep_v
        .without_session()
        .instance(&0u32)
        .std_verifier(&narg);
    warp_inst
        .verify(
            WarpVerifierKey {
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut verifier_state,
            acc_x.clone(),
            pf.clone(),
        )
        .unwrap();

    let sentinel_prover: F = prover_state.verifier_message::<F>();
    let sentinel_verifier: F = verifier_state.verifier_message::<F>();
    assert_eq!(
        sentinel_prover, sentinel_verifier,
        "post-protocol sponge state diverged (asymmetric public_message absorption?)"
    );
    let sentinel_hex = {
        let mut b = Vec::new();
        sentinel_prover.serialize_with_mode(&mut b, Compress::Yes).unwrap();
        hex_hash(&b)
    };

    println!(
        "fs_snapshot:\n  narg_len  = {}\n  narg_hash = {}\n  proof_len = {}\n  proof_hash = {}\n  sentinel = {}",
        narg.len(),
        narg_hash,
        pf_bytes.len(),
        pf_hash,
        sentinel_hex,
    );

    if let Some(expected) = EXPECTED_NARG_LEN {
        assert_eq!(narg.len(), expected, "narg_string length changed");
    }
    if let Some(expected) = EXPECTED_NARG_HASH {
        assert_eq!(narg_hash, expected, "Fiat-Shamir transcript drift detected");
    }
    if let Some(expected) = EXPECTED_PROOF_LEN {
        assert_eq!(pf_bytes.len(), expected, "proof serialized length changed");
    }
    if let Some(expected) = EXPECTED_PROOF_HASH {
        assert_eq!(pf_hash, expected, "proof bytes changed");
    }
    if let Some(expected) = EXPECTED_SENTINEL {
        assert_eq!(sentinel_hex, expected, "post-protocol sponge value changed");
    }
}

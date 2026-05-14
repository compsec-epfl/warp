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

use warp::accumulation_scheme::{AccumulatorInstance, AccumulatorWitness, WarpProverKey};
use warp::config::WarpConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Arithmetize, PolyPredicate, Relation,
};
use warp::utils::{fields::Goldilocks, poseidon};
use warp::WarpAccumulationScheme;

type F = Goldilocks;
type VC = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

fn hex_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// After capturing initial values, set these to `Some(...)`. Until then the
/// test prints the observed values and skips assertion — useful for the
/// first run after upgrading dependencies.
// Bumped on AccumulationScheme prologue replacing IOP prologue at the
// orchestrator level. Adds `AS:WarpAccumulationScheme-AccScheme|` prefix + the inner IOP
// NAME (`WarpAccumulationScheme|`) before the IOR list — 32 extra bytes vs the prior
// IOP-only prologue.
const EXPECTED_NARG_HASH: Option<&str> =
    Some("83e5f65136d0ab5571a4f4c49e254a6bc178a264def7fba256cbdbd444b0f80d");
const EXPECTED_NARG_LEN: Option<usize> = Some(1616);
const EXPECTED_PROOF_HASH: Option<&str> =
    Some("68aec437a44825f513f3b5bfa55049e2c466b533bb0aede65dc63c6f76b7ec9c");
const EXPECTED_PROOF_LEN: Option<usize> = Some(224);

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

    let warp_config = WarpConfig::new(l1, 0, s, t, r1cs.config(), code.code_len());
    let pp = <VC as MultiVectorCommitment>::setup_multiple(0, code.code_len(), t, &mut rng)
        .expect("setup_multiple");
    let (ck, vk) = <VC as MultiVectorCommitment>::trim_multiple(&pp, 0, code.code_len(), t)
        .expect("trim_multiple");
    let warp_inst =
        WarpAccumulationScheme::<F, R1CS<F>, _, VC>::new(warp_config, code, r1cs.clone(), ck, vk);

    let domainsep = spongefish::domain_separator!("test::snapshot");
    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
    let (_acc, pf) = warp_inst
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

    println!(
        "fs_snapshot:\n  narg_len  = {}\n  narg_hash = {}\n  proof_len = {}\n  proof_hash = {}",
        narg.len(),
        narg_hash,
        pf_bytes.len(),
        pf_hash,
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
}

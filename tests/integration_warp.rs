//! End-to-end integration tests for the full WARP prove / verify / decide
//! cycle. Previously lived in `src/lib.rs` as an inline `#[cfg(test)]`
//! module; moved here so `src/lib.rs` stays focused on the orchestrator.
//!
//! Two suites:
//!
//! - `warp_test` on BLS12-381 (≈254-bit multi-limb)
//! - `warp_test_goldilocks` on Goldilocks (64-bit SmallFp)
//!
//! The suites are deliberately duplicated rather than generic-over-`F`:
//! their associated-type bounds (Merkle config, poseidon config, etc.)
//! differ enough that a single generic function would need a long
//! `where` clause for marginal DRY gain.

use ark_bls12_381::Fr as BLS12_381;
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
use ark_std::rand::thread_rng;
use ark_vc::{mvc::MultiVectorCommitment, vc::VectorCommitment};

use warp::config::WARPConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    Arithmetize, PolyPredicate, Relation,
};
use warp::serialize::acc_witness_size;
use warp::utils::poseidon;
use warp::warp::{AccumulatorInstance, AccumulatorWitness, WARPProverKey, WARPVerifierKey};
use warp::WARP;

/// Concrete Merkle scheme used by the tests below. Plain perfect-binary
/// tree with a Blake3 field-symbol hasher — no caps, no multi-region.
type MerkleVc<F> = MerkleCommitment<HashRegion<Blake3FieldHasher<F>>, PerfectBinary>;

fn build_keys<F>(
    code_len: usize,
    num_queries: usize,
) -> (
    <MerkleVc<F> as VectorCommitment>::CommitterKey,
    <MerkleVc<F> as VectorCommitment>::VerifierKey,
)
where
    F: ark_ff::PrimeField,
    Blake3FieldHasher<F>: Default + Clone + 'static,
{
    let mut rng = thread_rng();
    let pp =
        <MerkleVc<F> as MultiVectorCommitment>::setup_multiple(0, code_len, num_queries, &mut rng)
            .expect("setup_multiple");
    <MerkleVc<F> as MultiVectorCommitment>::trim_multiple(&pp, 0, code_len, num_queries)
        .expect("trim_multiple")
}

#[test]
fn warp_test() {
    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<BLS12_381>();
    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<BLS12_381>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    );
    let code = ReedSolomon::new(code_config.clone());

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
            let witness = HashChainWitness::<BLS12_381, CRH<BLS12_381>>::new(preimage);
            let relation = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    let r1cs = HashChainRelation::<BLS12_381, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let warp_config = WARPConfig::new(l1, 0, s, t, r1cs.config(), code.code_len());
    let (ck, vk) = build_keys::<BLS12_381>(code.code_len(), t);
    let hash_chain_warp = WARP::<BLS12_381, R1CS<BLS12_381>, _, MerkleVc<BLS12_381>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        ck,
        vk,
    );

    let mut acc_x = AccumulatorInstance::empty();
    let mut acc_w = AccumulatorWitness::empty();

    for _ in 0..l1 {
        let domainsep = spongefish::domain_separator!("test::warp");
        let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
        let ((new_x, new_w), _pf) = hash_chain_warp
            .prove(
                WARPProverKey {
                    index: r1cs.clone(),
                    m_num_constraints: r1cs.m_num_constraints,
                    n_num_variables: r1cs.n_num_variables,
                    k_num_witness_vars: r1cs.k_num_witness_vars,
                },
                &mut prover_state,
                instances_witnesses.1.clone(),
                instances_witnesses.0.clone(),
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap();
        acc_x = acc_x.extend(new_x);
        acc_w = acc_w.extend(new_w);
    }

    let domainsep = spongefish::domain_separator!("test::warp");
    let warp_config =
        WARPConfig::<_, R1CS<BLS12_381>>::new(l1, 4, s, t, r1cs.config(), code.code_len());

    let (ck, vk) = build_keys::<BLS12_381>(code.code_len(), t);
    let hash_chain_warp = WARP::<BLS12_381, R1CS<BLS12_381>, _, MerkleVc<BLS12_381>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        ck,
        vk,
    );

    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
    let ((acc_x, acc_w), pf) = hash_chain_warp
        .prove(
            WARPProverKey {
                index: r1cs.clone(),
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut prover_state,
            instances_witnesses.1,
            instances_witnesses.0,
            acc_x,
            acc_w,
        )
        .unwrap();

    let narg_str = prover_state.narg_string().to_vec();
    let domainsep_v = spongefish::domain_separator!("test::warp");
    let mut verifier_state = domainsep_v
        .without_session()
        .instance(&0u32)
        .std_verifier(&narg_str);
    hash_chain_warp
        .verify(
            WARPVerifierKey {
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut verifier_state,
            acc_x.clone(),
            pf.clone(),
        )
        .unwrap();
    hash_chain_warp
        .decide(acc_w.clone(), acc_x.clone())
        .unwrap();

    println!("acc_x size: {}", acc_x.serialized_size(Compress::Yes));
    println!("acc_w size: {}", acc_witness_size(&acc_w, Compress::Yes));
    println!("proof size: {}", pf.serialized_size(Compress::Yes));
    println!("narg_str size: {}", narg_str.len());
}

#[test]
fn warp_test_goldilocks() {
    use warp::utils::fields::Goldilocks;

    let l1 = 4;
    let s = 8;
    let t = 7;
    let hash_chain_size = 10;
    let mut rng = thread_rng();
    let poseidon_config = poseidon::initialize_poseidon_config::<Goldilocks>();
    let r1cs = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<Goldilocks>::default(
        r1cs.k_num_witness_vars,
        r1cs.k_num_witness_vars.next_power_of_two(),
    );
    let code = ReedSolomon::new(code_config);

    let instances_witnesses: (Vec<Vec<Goldilocks>>, Vec<Vec<Goldilocks>>) = (0..l1)
        .map(|_| {
            let preimage = vec![Goldilocks::rand(&mut rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<Goldilocks, CRH<_>>(
                    &poseidon_config,
                    &preimage,
                    hash_chain_size,
                ),
            };
            let witness = HashChainWitness::<Goldilocks, CRH<Goldilocks>>::new(preimage);
            let relation = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    let r1cs = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::arithmetize(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let warp_config = WARPConfig::new(l1, 0, s, t, r1cs.config(), code.code_len());
    let (ck, vk) = build_keys::<Goldilocks>(code.code_len(), t);
    let hash_chain_warp = WARP::<Goldilocks, R1CS<Goldilocks>, _, MerkleVc<Goldilocks>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        ck,
        vk,
    );

    let mut acc_x = AccumulatorInstance::empty();
    let mut acc_w = AccumulatorWitness::empty();

    for _ in 0..l1 {
        let domainsep = spongefish::domain_separator!("test::warp");
        let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
        let ((new_x, new_w), _pf) = hash_chain_warp
            .prove(
                WARPProverKey {
                    index: r1cs.clone(),
                    m_num_constraints: r1cs.m_num_constraints,
                    n_num_variables: r1cs.n_num_variables,
                    k_num_witness_vars: r1cs.k_num_witness_vars,
                },
                &mut prover_state,
                instances_witnesses.1.clone(),
                instances_witnesses.0.clone(),
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap();
        acc_x = acc_x.extend(new_x);
        acc_w = acc_w.extend(new_w);
    }

    let domainsep = spongefish::domain_separator!("test::warp");
    // Use 8 (2*l1) for the total accumulation size to test multi-instance accumulation
    let warp_config =
        WARPConfig::<_, R1CS<Goldilocks>>::new(l1, 4, s, t, r1cs.config(), code.code_len());

    let (ck, vk) = build_keys::<Goldilocks>(code.code_len(), t);
    let hash_chain_warp = WARP::<Goldilocks, R1CS<Goldilocks>, _, MerkleVc<Goldilocks>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        ck,
        vk,
    );

    let mut prover_state = domainsep.without_session().instance(&0u32).std_prover();
    let ((acc_x, acc_w), pf) = hash_chain_warp
        .prove(
            WARPProverKey {
                index: r1cs.clone(),
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut prover_state,
            instances_witnesses.1,
            instances_witnesses.0,
            acc_x,
            acc_w,
        )
        .unwrap();

    let narg_str = prover_state.narg_string().to_vec();
    let domainsep_v = spongefish::domain_separator!("test::warp");
    let mut verifier_state = domainsep_v
        .without_session()
        .instance(&0u32)
        .std_verifier(&narg_str);
    hash_chain_warp
        .verify(
            WARPVerifierKey {
                m_num_constraints: r1cs.m_num_constraints,
                n_num_variables: r1cs.n_num_variables,
                k_num_witness_vars: r1cs.k_num_witness_vars,
            },
            &mut verifier_state,
            acc_x.clone(),
            pf.clone(),
        )
        .unwrap();
    hash_chain_warp
        .decide(acc_w.clone(), acc_x.clone())
        .unwrap();

    println!(
        "Goldilocks acc_x size: {}",
        acc_x.serialized_size(Compress::Yes)
    );
    println!(
        "Goldilocks acc_w size: {}",
        acc_witness_size(&acc_w, Compress::Yes)
    );
    println!(
        "Goldilocks proof size: {}",
        pf.serialized_size(Compress::Yes)
    );
    println!("Goldilocks narg_str size: {}", narg_str.len());
}

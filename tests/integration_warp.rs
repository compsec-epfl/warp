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

use std::marker::PhantomData;

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_std::rand::thread_rng;
use ark_vc::blake3::Blake3FieldHasher;

use warp::config::WARPConfig;
use warp::relations::{
    r1cs::{
        hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
        R1CS,
    },
    BundledPESAT, Relation, ToPolySystem,
};
use warp::serialize::{AccInstanceSerializer, AccWitnessSerializer, ProofSerializer};
use warp::traits::AccumulationScheme;
use warp::types::{AccumulatorInstance, AccumulatorWitness};
use warp::utils::poseidon;
use warp::WARP;

#[test]
fn warp_test() {
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
    let code_config = ReedSolomonConfig::<BLS12_381>::default(r1cs.k, r1cs.k.next_power_of_two());
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
    let hash_chain_warp = WARP::<BLS12_381, R1CS<BLS12_381>, _, Blake3FieldHasher<BLS12_381>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        Blake3FieldHasher::<BLS12_381>::new(),
    );

    let (mut acc_roots, mut acc_alphas, mut acc_mus, mut acc_taus, mut acc_xs, mut acc_eta) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    let (mut acc_tds, mut acc_f, mut acc_ws) = (vec![], vec![], vec![]);

    for _ in 0..l1 {
        let domainsep = spongefish::domain_separator!("test::warp");
        let mut prover_state = domainsep.instance(&0u32).std_prover();
        let ((acc_x, acc_w), _pf) = hash_chain_warp
            .prove(
                (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                &mut prover_state,
                instances_witnesses.1.clone(),
                instances_witnesses.0.clone(),
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap();
        acc_roots.push(acc_x.rt[0]);
        acc_alphas.push(acc_x.alpha[0].clone());
        acc_mus.push(acc_x.mu[0]);
        acc_taus.push(acc_x.beta.0[0].clone());
        acc_xs.push(acc_x.beta.1[0].clone());
        acc_eta.push(acc_x.eta[0]);

        // ark-vc `Committed` is not Clone; destructure and move the
        // single-element Vecs out of acc_w instead of cloning in place.
        let AccumulatorWitness {
            mut td,
            mut f,
            mut w,
        } = acc_w;
        acc_tds.push(td.pop().unwrap());
        acc_f.push(f.pop().unwrap());
        acc_ws.push(w.pop().unwrap());
    }

    let domainsep = spongefish::domain_separator!("test::warp");
    let warp_config =
        WARPConfig::<_, R1CS<BLS12_381>>::new(8, l1, s, t, r1cs.config(), code.code_len());

    let hash_chain_warp = WARP::<BLS12_381, R1CS<BLS12_381>, _, Blake3FieldHasher<BLS12_381>>::new(
        warp_config.clone(),
        code.clone(),
        r1cs.clone(),
        Blake3FieldHasher::<BLS12_381>::new(),
    );

    let mut prover_state = domainsep.instance(&0u32).std_prover();
    let ((acc_x, acc_w), pf) = hash_chain_warp
        .prove(
            (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
            &mut prover_state,
            instances_witnesses.1,
            instances_witnesses.0,
            AccumulatorInstance {
                rt: acc_roots,
                alpha: acc_alphas,
                mu: acc_mus,
                beta: (acc_taus, acc_xs),
                eta: acc_eta,
            },
            AccumulatorWitness {
                td: acc_tds,
                f: acc_f,
                w: acc_ws,
            },
        )
        .unwrap();

    let narg_str = prover_state.narg_string().to_vec();
    let domainsep_v = spongefish::domain_separator!("test::warp");
    let mut verifier_state = domainsep_v.instance(&0u32).std_verifier(&narg_str);
    hash_chain_warp
        .verify(
            (r1cs.m, r1cs.n, r1cs.k),
            &mut verifier_state,
            acc_x.clone(),
            pf.clone(),
        )
        .unwrap();
    // Serializers take refs (AccumulatorWitness is not Clone: ark-vc
    // `Committed` lacks a Clone impl). Compute sizes first, then consume
    // acc_w / acc_x into decide.
    let acc_x_to_serde = AccInstanceSerializer::new(&acc_x).unwrap();
    let acc_w_to_serde = AccWitnessSerializer::new(&acc_w).unwrap();
    let proof_to_serde = ProofSerializer::new(&pf);

    hash_chain_warp.decide(acc_w, acc_x).unwrap();

    println!(
        "acc_x size: {}",
        acc_x_to_serde.serialized_size(Compress::Yes)
    );
    println!(
        "acc_w size: {}",
        acc_w_to_serde.serialized_size(Compress::Yes)
    );
    println!(
        "proof size: {}",
        proof_to_serde.serialized_size(Compress::Yes)
    );
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
    let r1cs = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();
    let code_config = ReedSolomonConfig::<Goldilocks>::default(r1cs.k, r1cs.k.next_power_of_two());
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
            let witness = HashChainWitness {
                preimage,
                _crhs_scheme: PhantomData::<CRH<Goldilocks>>,
            };
            let relation = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip();

    let r1cs = HashChainRelation::<Goldilocks, CRH<_>, CRHGadget<_>>::into_r1cs(&(
        poseidon_config.clone(),
        hash_chain_size,
    ))
    .unwrap();

    let warp_config = WARPConfig::new(l1, l1, s, t, r1cs.config(), code.code_len());
    let hash_chain_warp =
        WARP::<Goldilocks, R1CS<Goldilocks>, _, Blake3FieldHasher<Goldilocks>>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            Blake3FieldHasher::<Goldilocks>::new(),
        );

    let (mut acc_roots, mut acc_alphas, mut acc_mus, mut acc_taus, mut acc_xs, mut acc_eta) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    let (mut acc_tds, mut acc_f, mut acc_ws) = (vec![], vec![], vec![]);

    for _ in 0..l1 {
        let domainsep = spongefish::domain_separator!("test::warp");
        let mut prover_state = domainsep.instance(&0u32).std_prover();
        let ((acc_x, acc_w), _pf) = hash_chain_warp
            .prove(
                (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
                &mut prover_state,
                instances_witnesses.1.clone(),
                instances_witnesses.0.clone(),
                AccumulatorInstance::empty(),
                AccumulatorWitness::empty(),
            )
            .unwrap();
        acc_roots.push(acc_x.rt[0]);
        acc_alphas.push(acc_x.alpha[0].clone());
        acc_mus.push(acc_x.mu[0]);
        acc_taus.push(acc_x.beta.0[0].clone());
        acc_xs.push(acc_x.beta.1[0].clone());
        acc_eta.push(acc_x.eta[0]);

        // ark-vc `Committed` is not Clone; destructure and move the
        // single-element Vecs out of acc_w instead of cloning in place.
        let AccumulatorWitness {
            mut td,
            mut f,
            mut w,
        } = acc_w;
        acc_tds.push(td.pop().unwrap());
        acc_f.push(f.pop().unwrap());
        acc_ws.push(w.pop().unwrap());
    }

    let domainsep = spongefish::domain_separator!("test::warp");
    // Use 8 (2*l1) for the total accumulation size to test multi-instance accumulation
    let warp_config =
        WARPConfig::<_, R1CS<Goldilocks>>::new(8, l1, s, t, r1cs.config(), code.code_len());

    let hash_chain_warp =
        WARP::<Goldilocks, R1CS<Goldilocks>, _, Blake3FieldHasher<Goldilocks>>::new(
            warp_config.clone(),
            code.clone(),
            r1cs.clone(),
            Blake3FieldHasher::<Goldilocks>::new(),
        );

    let mut prover_state = domainsep.instance(&0u32).std_prover();
    let ((acc_x, acc_w), pf) = hash_chain_warp
        .prove(
            (r1cs.clone(), r1cs.m, r1cs.n, r1cs.k),
            &mut prover_state,
            instances_witnesses.1,
            instances_witnesses.0,
            AccumulatorInstance {
                rt: acc_roots,
                alpha: acc_alphas,
                mu: acc_mus,
                beta: (acc_taus, acc_xs),
                eta: acc_eta,
            },
            AccumulatorWitness {
                td: acc_tds,
                f: acc_f,
                w: acc_ws,
            },
        )
        .unwrap();

    let narg_str = prover_state.narg_string().to_vec();
    let domainsep_v = spongefish::domain_separator!("test::warp");
    let mut verifier_state = domainsep_v.instance(&0u32).std_verifier(&narg_str);
    hash_chain_warp
        .verify(
            (r1cs.m, r1cs.n, r1cs.k),
            &mut verifier_state,
            acc_x.clone(),
            pf.clone(),
        )
        .unwrap();
    // Serializers take refs (AccumulatorWitness is not Clone: ark-vc
    // `Committed` lacks a Clone impl). Compute sizes first, then consume
    // acc_w / acc_x into decide.
    let acc_x_to_serde = AccInstanceSerializer::new(&acc_x).unwrap();
    let acc_w_to_serde = AccWitnessSerializer::new(&acc_w).unwrap();
    let proof_to_serde = ProofSerializer::new(&pf);

    hash_chain_warp.decide(acc_w, acc_x).unwrap();

    println!(
        "Goldilocks acc_x size: {}",
        acc_x_to_serde.serialized_size(Compress::Yes)
    );
    println!(
        "Goldilocks acc_w size: {}",
        acc_w_to_serde.serialized_size(Compress::Yes)
    );
    println!(
        "Goldilocks proof size: {}",
        proof_to_serde.serialized_size(Compress::Yes)
    );
    println!("Goldilocks narg_str size: {}", narg_str.len());
}

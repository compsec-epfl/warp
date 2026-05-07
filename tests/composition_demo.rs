//! Demo test for `PesatTwinConstraint` — the first concrete composition
//! built on the GAT-decoupled `IOR` trait.
//!
//! What this validates:
//!
//! 1. The pipeline value holds both phases (`Pesat` + `TwinConstraint`)
//!    by data, with their `'phase` lifetime tied to long-lived params.
//! 2. `pipeline.prove(...)` is callable many times in the same scope
//!    with **different short-lived witnesses each time**. Pre-GAT
//!    migration this would not compile — the witness's lifetime was
//!    forced to match the phase struct's lifetime, so the first call's
//!    borrows would have been pinned to the pipeline's lifetime, and
//!    a second call with different inputs wouldn't have type-checked.
//! 3. The Pesat → TwinConstraint data flow is wired correctly:
//!    `pesat_red.mus` / `pesat_red.taus` feed into TC's statement, and
//!    `pesat_red_wit.codewords` feeds into TC's prover inputs by
//!    reference (no clone).

use ark_bls12_381::Fr as BLS12_381;
use ark_codes::{
    reed_solomon::{config::ReedSolomonConfig, ReedSolomon},
    traits::LinearCode,
};
use ark_crypto_primitives::crh::poseidon::{constraints::CRHGadget, CRH};
use ark_ff::UniformRand;
use ark_mt::blake3::Blake3FieldHasher;
use ark_std::rand::thread_rng;

use warp::protocol::composition::{WarpPipeline, WarpPipelineConfig, WarpPipelineInputs};
use warp::relations::{
    r1cs::hashchain::{compute_hash_chain, HashChainInstance, HashChainRelation, HashChainWitness},
    BundledPESAT, Relation, ToPolySystem,
};
use warp::types::AccumulatorInstance;
use warp::utils::poseidon;

type F = BLS12_381;
type H = Blake3FieldHasher<F>;

/// Build one `(instance, witness)` batch of size `l1`.
fn make_batch(
    l1: usize,
    poseidon_config: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>,
    hash_chain_size: usize,
    rng: &mut impl ark_std::rand::Rng,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    (0..l1)
        .map(|_| {
            let preimage = vec![F::rand(rng)];
            let instance = HashChainInstance {
                digest: compute_hash_chain::<F, CRH<_>>(poseidon_config, &preimage, hash_chain_size),
            };
            let witness = HashChainWitness::<F, CRH<F>>::new(preimage);
            let relation = HashChainRelation::<F, CRH<_>, CRHGadget<_>>::new(
                instance,
                witness,
                (poseidon_config.clone(), hash_chain_size),
            );
            (relation.x, relation.w)
        })
        .unzip()
}

#[test]
fn pipeline_runs_pesat_tc_ood_twice() {
    // ── setup: long-lived ─────────────────────────────────────────────
    let l1 = 4;
    let s = 8;
    let log_l = (l1 as f64).log2() as usize;
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
    let hasher = Blake3FieldHasher::<F>::new();
    let r1cs_constraints = r1cs.constraints().clone();

    let n = code.code_len();
    let log_n = (n as f64).log2() as usize;

    let config = WarpPipelineConfig {
        l1,
        log_l,
        log_m: r1cs.log_m,
        log_n,
        n_minus_k: r1cs.n - r1cs.k,
        s,
    };

    // Build the pipeline ONCE — borrows code / hasher / r1cs / bundled
    // PESAT relation for 'phase.
    let pipeline =
        WarpPipeline::<F, _, _, H>::new(&code, &hasher, &r1cs_constraints, &r1cs, n);

    // ── two independent batches with independent lifetimes ────────────
    let (instances_a, witnesses_a) = make_batch(l1, &poseidon_config, hash_chain_size, &mut rng);
    let (instances_b, witnesses_b) = make_batch(l1, &poseidon_config, hash_chain_size, &mut rng);

    let acc_w_empty: Vec<Vec<F>> = vec![];
    let acc_codewords_empty: Vec<Vec<F>> = vec![];

    // Call A: borrows witnesses_a / instances_a.
    let mut prover_state_a = spongefish::domain_separator!("test::composition_demo")
        .without_session()
        .instance(&0u32)
        .std_prover();
    let red_a = pipeline
        .prove(
            &mut prover_state_a,
            &config,
            WarpPipelineInputs {
                witnesses: &witnesses_a,
                instances: &instances_a,
                acc_witness_w: &acc_w_empty,
                acc_codewords: &acc_codewords_empty,
                acc_instance: AccumulatorInstance::<F, H>::empty(),
            },
        )
        .expect("first prove call should succeed");

    // Call B: borrows witnesses_b / instances_b. The pipeline value is
    // still alive — this is what would not compile without GATs.
    let mut prover_state_b = spongefish::domain_separator!("test::composition_demo")
        .without_session()
        .instance(&0u32)
        .std_prover();
    let red_b = pipeline
        .prove(
            &mut prover_state_b,
            &config,
            WarpPipelineInputs {
                witnesses: &witnesses_b,
                instances: &instances_b,
                acc_witness_w: &acc_w_empty,
                acc_codewords: &acc_codewords_empty,
                acc_instance: AccumulatorInstance::<F, H>::empty(),
            },
        )
        .expect("second prove call should succeed");

    // Shape sanity across all three phases.
    assert_eq!(red_a.pesat.mus.len(), l1);
    assert_eq!(red_a.pesat.taus.len(), l1);
    assert_eq!(red_a.tc.gamma.len(), log_l);
    assert_eq!(red_a.tc.zeta_0.len(), log_n);
    // Ood: s answers, samples_flat is s * log_n long.
    assert_eq!(red_a.ood.answers.len(), s);
    assert_eq!(red_a.ood.samples_flat.len(), s * log_n);

    // Inter-phase glue produced sensible split halves.
    assert_eq!(red_a.new_x.len(), r1cs.n - r1cs.k);
    assert_eq!(red_a.new_w.len(), r1cs.k);

    assert_eq!(red_b.pesat.mus.len(), l1);
    assert_eq!(red_b.ood.answers.len(), s);

    // Independent randomness across calls => reductions differ.
    assert_ne!(red_a.pesat.mus, red_b.pesat.mus);
    assert_ne!(red_a.eta, red_b.eta);
}

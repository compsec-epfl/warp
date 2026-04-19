use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;

use spongefish::{
    Decoding, Encoding, NargDeserialize, ProverState, VerificationResult, VerifierState,
};

pub type AccInstances<F, MT> = (
    Vec<<MT as Config>::InnerDigest>, // rt
    Vec<Vec<F>>,                      // alpha
    Vec<F>,                           // mu
    (Vec<Vec<F>>, Vec<Vec<F>>),       // (tau, x)
    Vec<F>,                           // eta
);

pub fn absorb_instances<F: Field + Encoding<[u8]>>(
    prover_state: &mut ProverState,
    instances: &[Vec<F>],
) {
    for instance in instances {
        for f in instance {
            prover_state.prover_message(f);
        }
    }
}

pub fn absorb_accumulated_instances<
    F: Field + Encoding<[u8]>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    prover_state: &mut ProverState,
    acc_instances: &AccInstances<F, MT>,
) {
    // digests (rt)
    for digest in &acc_instances.0 {
        let bytes: [u8; 32] = digest.as_ref().try_into().expect("digest must be 32 bytes");
        prover_state.prover_message(&bytes);
    }

    // alpha
    for alpha in &acc_instances.1 {
        for f in alpha {
            prover_state.prover_message(f);
        }
    }

    // mu
    for f in &acc_instances.2 {
        prover_state.prover_message(f);
    }

    // taus
    for tau in &acc_instances.3 .0 {
        for f in tau {
            prover_state.prover_message(f);
        }
    }

    // xs
    for x in &acc_instances.3 .1 {
        for f in x {
            prover_state.prover_message(f);
        }
    }

    // etas
    for f in &acc_instances.4 {
        prover_state.prover_message(f);
    }
}

pub type ParsedStatement<F, MT> = (Vec<Vec<F>>, AccInstances<F, MT>);

pub fn parse_statement<
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    l2: usize,
    instance_len: usize,
    log_n: usize,
    #[allow(non_snake_case)] log_M: usize,
) -> VerificationResult<ParsedStatement<F, MT>> {
    // f. absorb l1 instances
    let mut l1_xs = Vec::with_capacity(l1);
    for _ in 0..l1 {
        let inst: Vec<F> = verifier_state.prover_messages_vec(instance_len)?;
        l1_xs.push(inst);
    }

    // l2 instances
    let mut l2_roots = Vec::with_capacity(l2);
    for _ in 0..l2 {
        let bytes: [u8; 32] = verifier_state.prover_message()?;
        l2_roots.push(bytes.into());
    }

    let mut l2_alphas = Vec::with_capacity(l2);
    for _ in 0..l2 {
        let alpha: Vec<F> = verifier_state.prover_messages_vec(log_n)?;
        l2_alphas.push(alpha);
    }

    let l2_mus: Vec<F> = verifier_state.prover_messages_vec(l2)?;

    let mut l2_taus = Vec::with_capacity(l2);
    for _ in 0..l2 {
        let tau: Vec<F> = verifier_state.prover_messages_vec(log_M)?;
        l2_taus.push(tau);
    }

    let mut l2_xs = Vec::with_capacity(l2);
    for _ in 0..l2 {
        let x: Vec<F> = verifier_state.prover_messages_vec(instance_len)?;
        l2_xs.push(x);
    }

    let l2_etas: Vec<F> = verifier_state.prover_messages_vec(l2)?;

    Ok((
        l1_xs,
        (l2_roots, l2_alphas, l2_mus, (l2_taus, l2_xs), l2_etas),
    ))
}

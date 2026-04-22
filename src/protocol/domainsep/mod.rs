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

/// Read `rt_0 + l1_mus`, squeeze `l1_taus + ω + τ`. Runs before the
/// twin-constraint sumcheck on the verifier side.
#[allow(clippy::type_complexity)]
pub fn derive_pre_twin_constraint<
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    vs: &mut VerifierState<'_>,
    l1: usize,
    log_l: usize,
    #[allow(non_snake_case)] log_M: usize,
) -> VerificationResult<(MT::InnerDigest, Vec<F>, Vec<Vec<F>>, F, Vec<F>)> {
    let rt_0: MT::InnerDigest = <[u8; 32]>::into(vs.prover_message()?);
    let l1_mus = vs.prover_messages_vec(l1)?;
    let l1_taus = (0..l1)
        .map(|_| (0..log_M).map(|_| vs.verifier_message::<F>()).collect())
        .collect();
    let omega = vs.verifier_message();
    let tau = (0..log_l).map(|_| vs.verifier_message::<F>()).collect();
    Ok((rt_0, l1_mus, l1_taus, omega, tau))
}

/// Read `td + η + ν₀`, squeeze OOD points, read OOD answers, squeeze shift
/// query bytes and `ξ`. Runs between the two sumchecks on the verifier side.
#[allow(clippy::type_complexity)]
pub fn derive_between_sumchecks<
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    vs: &mut VerifierState<'_>,
    log_n: usize,
    s: usize,
    t: usize,
    log_r: usize,
) -> VerificationResult<(MT::InnerDigest, F, Vec<F>, Vec<F>, Vec<u8>, Vec<F>)> {
    let td: MT::InnerDigest = <[u8; 32]>::into(vs.prover_message()?);
    let eta = vs.prover_message()?;
    let mut nus = vec![vs.prover_message::<F>()?];
    let ood_samples = (0..s * log_n).map(|_| vs.verifier_message::<F>()).collect();
    nus.extend(vs.prover_messages_vec::<F>(s)?);
    let bytes_shift_queries = (0..(t * log_n).div_ceil(8))
        .map(|_| vs.verifier_message::<[u8; 1]>()[0])
        .collect();
    let xi = (0..log_r).map(|_| vs.verifier_message::<F>()).collect();
    Ok((td, eta, nus, ood_samples, bytes_shift_queries, xi))
}

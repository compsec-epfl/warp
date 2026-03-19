use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::log2;

use spongefish::{
    Decoding, DuplexSpongeInterface, Encoding, NargDeserialize, ProverState, VerificationResult,
    VerifierState,
};

use crate::utils::{HintDeserialize, HintSerialize};

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

pub type DerivedRandomness<F, MT> = (
    <MT as Config>::InnerDigest,
    Vec<F>,
    Vec<Vec<F>>,
    F,
    Vec<F>,
    Vec<F>,
    Vec<Vec<F>>,
    <MT as Config>::InnerDigest,
    F,
    Vec<F>,
    Vec<F>,
    Vec<u8>,
    Vec<F>,
    Vec<F>,
    Vec<[F; 3]>,
);

pub fn derive_randomness<
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    log_n: usize,
    log_l: usize,
    s: usize,
    t: usize,
    #[allow(non_snake_case)] log_M: usize,
) -> VerificationResult<DerivedRandomness<F, MT>> {
    // read commitment digest
    let rt_0_bytes: [u8; 32] = verifier_state.prover_message()?;
    let rt_0: MT::InnerDigest = rt_0_bytes.into();

    // read mus
    let l1_mus: Vec<F> = verifier_state.prover_messages_vec(l1)?;

    // challenge taus
    let mut l1_taus = Vec::with_capacity(l1);
    for _ in 0..l1 {
        let tau: Vec<F> = (0..log_M)
            .map(|_| verifier_state.verifier_message::<F>())
            .collect();
        l1_taus.push(tau);
    }

    let omega: F = verifier_state.verifier_message();
    let tau: Vec<F> = (0..log_l)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // e. twin constraints sumcheck
    let mut gamma_sumcheck = Vec::new();
    let mut coeffs_twinc_sumcheck = Vec::new();
    for _ in 0..log_l {
        let h_coeffs: Vec<F> =
            verifier_state.prover_messages_vec(2 + (log_n + 1).max(log_M + 2))?;
        let c: F = verifier_state.verifier_message();
        gamma_sumcheck.push(c);
        coeffs_twinc_sumcheck.push(h_coeffs);
    }

    // read td digest
    let td_bytes: [u8; 32] = verifier_state.prover_message()?;
    let _td: MT::InnerDigest = td_bytes.into();

    // read eta and nu_0
    let eta: F = verifier_state.prover_message()?;
    let nu_0: F = verifier_state.prover_message()?;
    let mut nus = vec![nu_0];

    // g. ood samples
    let n_ood_samples = s * log_n;
    let ood_samples: Vec<F> = (0..n_ood_samples)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // h. ood answers
    let ood_answers: Vec<F> = verifier_state.prover_messages_vec(s)?;
    nus.extend(ood_answers);

    // i. shift queries and zero check
    let r = 1 + s + t;
    let log_r = log2(r) as usize;
    let n_shift_queries = (t * log_n).div_ceil(8);
    let bytes_shift_queries: Vec<u8> = (0..n_shift_queries)
        .map(|_| verifier_state.verifier_message::<[u8; 1]>()[0])
        .collect();
    let xi: Vec<F> = (0..log_r)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // j. batching sumcheck
    let mut alpha_sumcheck = Vec::new();
    let mut sums_batching_sumcheck = Vec::new();
    for _ in 0..log_n {
        let sums: [F; 3] = verifier_state.prover_messages()?;
        let c: F = verifier_state.verifier_message();
        alpha_sumcheck.push(c);
        sums_batching_sumcheck.push(sums);
    }

    Ok((
        rt_0,
        l1_mus,
        l1_taus,
        omega,
        tau,
        gamma_sumcheck,
        coeffs_twinc_sumcheck,
        _td,
        eta,
        nus,
        ood_samples,
        bytes_shift_queries,
        xi,
        alpha_sumcheck,
        sums_batching_sumcheck,
    ))
}

// Hint implementations for the new ProverState / VerifierState
impl<H, R> HintSerialize for ProverState<H, R>
where
    H: DuplexSpongeInterface<U = u8>,
    R: rand::RngCore + rand::CryptoRng,
{
    fn hint<T: CanonicalSerialize>(&mut self, hint: &T) {
        let mut bytes = Vec::new();
        hint.serialize_compressed(&mut bytes)
            .expect("hint serialization failed");
        // Write length as u32, then the raw bytes as a slice
        self.prover_message(&(bytes.len() as u32));
        self.prover_message(&bytes);
    }
}

impl<H> HintDeserialize for VerifierState<'_, H>
where
    H: DuplexSpongeInterface<U = u8>,
{
    fn hint<T: CanonicalDeserialize>(&mut self) -> VerificationResult<T> {
        // Read the length first
        let len: u32 = self.prover_message()?;
        // Read exact number of bytes one at a time
        let bytes: Vec<u8> = (0..len)
            .map(|_| self.prover_message::<[u8; 1]>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|b| b[0])
            .collect();
        T::deserialize_compressed(&mut bytes.as_slice()).map_err(|_| spongefish::VerificationError)
    }
}

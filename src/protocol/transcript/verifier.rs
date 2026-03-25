use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::Field;
use ark_std::log2;

use spongefish::{Decoding, Encoding, NargDeserialize, VerificationResult, VerifierState};

use crate::types::AccumulatorInstance;

// (l1 instances, accumulated instance)
pub type ParsedStatement<F, MT> = (Vec<Vec<F>>, AccumulatorInstance<F, MT>);

// parse l1 plain instances + an AccumulatorInstance from the transcript
pub fn parse_statement<
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    l2: usize,
    instance_len: usize,
    log_n: usize,
    log_m: usize,
) -> VerificationResult<ParsedStatement<F, MT>> {
    let l1_xs: Vec<Vec<F>> = (0..l1)
        .map(|_| verifier_state.prover_messages_vec(instance_len))
        .collect::<Result<_, _>>()?;

    let acc =
        AccumulatorInstance::<F, MT>::parse_from(verifier_state, l2, log_n, log_m, instance_len)?;

    Ok((l1_xs, acc))
}

// parse an AccumulatorInstance from the verifier transcript
impl<
        F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
        MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
    > AccumulatorInstance<F, MT>
{
    pub fn parse_from(
        verifier_state: &mut VerifierState<'_>,
        l2: usize,
        log_n: usize,
        log_m: usize,
        instance_len: usize,
    ) -> VerificationResult<Self> {
        let rt: Vec<MT::InnerDigest> = (0..l2)
            .map(|_| -> VerificationResult<_> {
                let bytes: [u8; 32] = verifier_state.prover_message()?;
                Ok(bytes.into())
            })
            .collect::<Result<_, _>>()?;

        let alpha: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(log_n))
            .collect::<Result<_, _>>()?;

        let mu: Vec<F> = verifier_state.prover_messages_vec(l2)?;

        let taus: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(log_m))
            .collect::<Result<_, _>>()?;

        let xs: Vec<Vec<F>> = (0..l2)
            .map(|_| verifier_state.prover_messages_vec(instance_len))
            .collect::<Result<_, _>>()?;

        let eta: Vec<F> = verifier_state.prover_messages_vec(l2)?;

        Ok(Self {
            rt,
            alpha,
            mu,
            beta: (taus, xs),
            eta,
        })
    }
}

pub struct DerivedRandomness<F: Field, MT: Config> {
    pub rt_0: MT::InnerDigest,
    pub l1_mus: Vec<F>,
    pub l1_taus: Vec<Vec<F>>,
    pub omega: F,
    pub tau: Vec<F>,
    pub gamma_sumcheck: Vec<F>,
    pub coeffs_twinc_sumcheck: Vec<Vec<F>>,
    pub td: MT::InnerDigest,
    pub eta: F,
    pub nus: Vec<F>,
    pub ood_samples: Vec<F>,
    pub bytes_shift_queries: Vec<u8>,
    pub xi: Vec<F>,
    pub alpha_sumcheck: Vec<F>,
    pub sums_batching_sumcheck: Vec<[F; 3]>,
}

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
    log_m: usize,
) -> VerificationResult<DerivedRandomness<F, MT>> {
    // commitment digest
    let rt_0_bytes: [u8; 32] = verifier_state.prover_message()?;
    let rt_0: MT::InnerDigest = rt_0_bytes.into();

    // mus
    let l1_mus: Vec<F> = verifier_state.prover_messages_vec(l1)?;

    // challenge taus
    let l1_taus: Vec<Vec<F>> = (0..l1)
        .map(|_| {
            (0..log_m)
                .map(|_| verifier_state.verifier_message::<F>())
                .collect()
        })
        .collect();

    let omega: F = verifier_state.verifier_message();
    let tau: Vec<F> = (0..log_l)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // twin constraints sumcheck
    let mut gamma_sumcheck = Vec::new();
    let mut coeffs_twinc_sumcheck = Vec::new();
    for _ in 0..log_l {
        let h_coeffs: Vec<F> =
            verifier_state.prover_messages_vec(2 + (log_n + 1).max(log_m + 2))?;
        let c: F = verifier_state.verifier_message();
        gamma_sumcheck.push(c);
        coeffs_twinc_sumcheck.push(h_coeffs);
    }

    // td digest
    let td_bytes: [u8; 32] = verifier_state.prover_message()?;
    let td: MT::InnerDigest = td_bytes.into();

    // eta and nu_0
    let eta: F = verifier_state.prover_message()?;
    let nu_0: F = verifier_state.prover_message()?;
    let mut nus = vec![nu_0];

    // ood samples
    let n_ood_samples = s * log_n;
    let ood_samples: Vec<F> = (0..n_ood_samples)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // ood answers
    let ood_answers: Vec<F> = verifier_state.prover_messages_vec(s)?;
    nus.extend(ood_answers);

    // shift queries and zero check
    let r = 1 + s + t;
    let log_r = log2(r) as usize;
    let n_shift_queries = (t * log_n).div_ceil(8);
    let bytes_shift_queries: Vec<u8> = (0..n_shift_queries)
        .map(|_| verifier_state.verifier_message::<[u8; 1]>()[0])
        .collect();
    let xi: Vec<F> = (0..log_r)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    // batching sumcheck
    let mut alpha_sumcheck = Vec::new();
    let mut sums_batching_sumcheck = Vec::new();
    for _ in 0..log_n {
        let sums: [F; 3] = verifier_state.prover_messages()?;
        let c: F = verifier_state.verifier_message();
        alpha_sumcheck.push(c);
        sums_batching_sumcheck.push(sums);
    }

    Ok(DerivedRandomness {
        rt_0,
        l1_mus,
        l1_taus,
        omega,
        tau,
        gamma_sumcheck,
        coeffs_twinc_sumcheck,
        td,
        eta,
        nus,
        ood_samples,
        bytes_shift_queries,
        xi,
        alpha_sumcheck,
        sums_batching_sumcheck,
    })
}

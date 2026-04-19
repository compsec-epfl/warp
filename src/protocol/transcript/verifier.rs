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

/// Transcript values read BEFORE the twin-constraint sumcheck: PESAT
/// commitment + l1 mus + l1 τs + ω + τ.
pub struct PreTwinConstraint<F: Field, MT: Config> {
    pub rt_0: MT::InnerDigest,
    pub l1_mus: Vec<F>,
    pub l1_taus: Vec<Vec<F>>,
    pub omega: F,
    pub tau: Vec<F>,
}

/// Transcript values read BETWEEN the two sumchecks: new commitment,
/// η, ν₀, OOD samples+answers, shift-query byte challenges, ξ.
pub struct BetweenSumchecks<F: Field, MT: Config> {
    pub td: MT::InnerDigest,
    pub eta: F,
    pub nus: Vec<F>,
    pub ood_samples: Vec<F>,
    pub bytes_shift_queries: Vec<u8>,
    pub xi: Vec<F>,
}

pub fn derive_pre_twin_constraint<
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    log_l: usize,
    log_m: usize,
) -> VerificationResult<PreTwinConstraint<F, MT>> {
    // commitment digest
    let rt_0_bytes: [u8; 32] = verifier_state.prover_message()?;
    let rt_0: MT::InnerDigest = rt_0_bytes.into();

    // mus
    let l1_mus: Vec<F> = verifier_state.prover_messages_vec(l1)?;

    // challenge taus (squeezed)
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

    Ok(PreTwinConstraint {
        rt_0,
        l1_mus,
        l1_taus,
        omega,
        tau,
    })
}

pub fn derive_between_sumchecks<
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
    MT: Config<Leaf = [F], InnerDigest: AsRef<[u8]> + From<[u8; 32]>>,
>(
    verifier_state: &mut VerifierState<'_>,
    log_n: usize,
    s: usize,
    t: usize,
) -> VerificationResult<BetweenSumchecks<F, MT>> {
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

    // shift queries and ξ
    let r = 1 + s + t;
    let log_r = log2(r) as usize;
    let n_shift_queries = (t * log_n).div_ceil(8);
    let bytes_shift_queries: Vec<u8> = (0..n_shift_queries)
        .map(|_| verifier_state.verifier_message::<[u8; 1]>()[0])
        .collect();
    let xi: Vec<F> = (0..log_r)
        .map(|_| verifier_state.verifier_message::<F>())
        .collect();

    Ok(BetweenSumchecks {
        td,
        eta,
        nus,
        ood_samples,
        bytes_shift_queries,
        xi,
    })
}

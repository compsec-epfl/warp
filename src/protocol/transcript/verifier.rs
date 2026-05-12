use ark_ff::Field;
use ark_mt::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, VerificationResult, VerifierState};

use crate::warp::AccumulatorInstance;

// (l1 instances, accumulated instance)
pub type ParsedStatement<F, H> = (Vec<Vec<F>>, AccumulatorInstance<F, H>);

// parse l1 plain instances + an AccumulatorInstance from the transcript
pub fn parse_statement<F, H>(
    verifier_state: &mut VerifierState<'_>,
    l1: usize,
    l2: usize,
    instance_len: usize,
    log_n: usize,
    log_m: usize,
) -> VerificationResult<ParsedStatement<F, H>>
where
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    H: MerkleHasher,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
{
    let l1_xs: Vec<Vec<F>> = (0..l1)
        .map(|_| verifier_state.prover_messages_vec(instance_len))
        .collect::<Result<_, _>>()?;

    let acc =
        AccumulatorInstance::<F, H>::parse_from(verifier_state, l2, log_n, log_m, instance_len)?;

    Ok((l1_xs, acc))
}

// parse an AccumulatorInstance from the verifier transcript
impl<F, H> AccumulatorInstance<F, H>
where
    F: Field + NargDeserialize + Encoding<[u8]> + Decoding<[u8]>,
    H: MerkleHasher,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
{
    pub fn parse_from(
        verifier_state: &mut VerifierState<'_>,
        l2: usize,
        log_n: usize,
        log_m: usize,
        instance_len: usize,
    ) -> VerificationResult<Self> {
        let rt: Vec<H::Digest> = (0..l2)
            .map(|_| verifier_state.prover_message::<H::Digest>())
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

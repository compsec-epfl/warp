//! Adapter plugging spongefish's [`VerifierState`] into effsc's
//! [`VerifierTranscript`] trait, so warp's verifier can call
//! [`effsc::verifier::sumcheck_verify`]. Prover-side is already handled by
//! a blanket impl inside effsc (on `spongefish::ProverState`), so no
//! wrapper is needed there.

use effsc::transcript::VerifierTranscript;
use spongefish::{Decoding, Encoding, NargDeserialize, VerifierState};

pub struct EffscVerifierTranscript<'s, 'a>(pub &'s mut VerifierState<'a>);

impl<'s, 'a, F> VerifierTranscript<F> for EffscVerifierTranscript<'s, 'a>
where
    F: ark_ff::Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize,
{
    type Error = spongefish::VerificationError;

    fn receive(&mut self) -> Result<F, Self::Error> {
        self.0.prover_message::<F>()
    }

    fn challenge(&mut self) -> F {
        self.0.verifier_message::<F>()
    }
}

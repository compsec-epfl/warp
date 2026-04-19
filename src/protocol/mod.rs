pub mod domainsep;

use effsc::transcript::VerifierTranscript;
use spongefish::{Decoding, Encoding, NargDeserialize, VerifierState};

/// Adapter plugging spongefish's [`VerifierState`] into effsc's
/// [`VerifierTranscript`] so the verifier can call
/// [`effsc::verifier::sumcheck_verify`]. Prover side is covered by a blanket
/// impl inside effsc (on `spongefish::ProverState`).
pub struct EffscVerifierTranscript<'s, 'a>(pub &'s mut VerifierState<'a>);

impl<F> VerifierTranscript<F> for EffscVerifierTranscript<'_, '_>
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

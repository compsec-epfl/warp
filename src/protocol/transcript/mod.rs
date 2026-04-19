pub mod prover;
pub mod verifier;

pub use prover::*;
pub use verifier::*;

use effsc::transcript::VerifierTranscript;
use spongefish::{Decoding, Encoding, NargDeserialize, VerifierState};

/// Adapter wrapping spongefish's [`VerifierState`] so it implements effsc's
/// [`VerifierTranscript`] trait. Used to plug warp's transcript into
/// [`effsc::verifier::sumcheck_verify`].
///
/// The prover-side adapter is a blanket impl inside effsc
/// (`ProverTranscript` on `spongefish::ProverState`); no wrapper needed there.
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

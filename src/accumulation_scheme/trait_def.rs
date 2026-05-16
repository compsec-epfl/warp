//! BCLMS-shaped split-accumulation trait. Warp-local; upstream when a
//! second consumer appears.

use ark_iop::{ProverTranscript, VerifierTranscript, IOP};

use crate::error::DeciderError;

pub trait AccumulationScheme {
    const NAME: &'static str;

    type Iop: IOP;

    /// Kept distinct from `Iop::Statement` so batched/transcript-derived
    /// forms are expressible.
    type FreshInstance;
    type FreshWitness;

    type AccumulatorInstance;
    /// Atomic schemes set this to `()`.
    type AccumulatorWitness;

    /// `()` for atomic schemes.
    type AccumulationProof;

    /// Subsumes `IOP::absorb_protocol_map_*` — invoke one or the other.
    fn absorb_scheme_prologue_prover<P: ProverTranscript>(&self, transcript: &mut P) {
        transcript.public_message(b"AS:");
        transcript.public_message(Self::NAME.as_bytes());
        transcript.public_message(b"|");
        transcript.public_message(<Self::Iop as IOP>::NAME.as_bytes());
        transcript.public_message(b"|");
        for name in <Self::Iop as IOP>::ior_names() {
            transcript.public_message(name.as_bytes());
            transcript.public_message(b"|");
        }
    }

    fn absorb_scheme_prologue_verifier<V: VerifierTranscript>(&self, transcript: &mut V) {
        transcript.public_message(b"AS:");
        transcript.public_message(Self::NAME.as_bytes());
        transcript.public_message(b"|");
        transcript.public_message(<Self::Iop as IOP>::NAME.as_bytes());
        transcript.public_message(b"|");
        for name in <Self::Iop as IOP>::ior_names() {
            transcript.public_message(name.as_bytes());
            transcript.public_message(b"|");
        }
    }

    fn decide(
        &self,
        acc_instance: &Self::AccumulatorInstance,
        acc_witness: &Self::AccumulatorWitness,
    ) -> Result<(), DeciderError>;
}

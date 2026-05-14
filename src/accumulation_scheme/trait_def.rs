//! Accumulation-scheme trait — warp-local, slated for upstream to
//! `ark-iop` once a second accumulating consumer appears.
//!
//! Mirrors the BCLMS (Bünz–Chen–Lin–Mishra–Vesely) split-accumulation
//! shape: an accumulator splits into a public `Instance` and a private
//! `Witness`; the scheme accumulates fresh claims via an inner IOP run
//! per round; the decider closes the accumulator. Atomic accumulation
//! falls out as `AccumulatorWitness = ()` and `AccumulationProof = ()`.
//!
//! Identity-shaped trait (no method signatures). The scheme is the FS
//! root once it implements this — its prologue absorbs `AS:NAME` plus
//! the inner IOP's name and IOR list, so callers no longer also need
//! to invoke `IOP::absorb_protocol_map_*`.

use ark_iop::{ProverTranscript, VerifierTranscript, IOP};

use crate::error::DeciderError;

pub trait AccumulationScheme {
    const NAME: &'static str;

    /// The IOP whose transcripts this scheme accumulates per round.
    type Iop: IOP;

    /// One fresh claim's public part. Often equal to `<Self::Iop as
    /// IOP>::Statement`; kept separate to allow batching or
    /// transcript-derived forms.
    type FreshInstance;
    /// Witness counterpart of `FreshInstance`.
    type FreshWitness;

    /// Public part of the accumulator (BCLMS "instance").
    type AccumulatorInstance;
    /// Private part of the accumulator (BCLMS "witness"). Atomic
    /// schemes set this to `()`.
    type AccumulatorWitness;

    /// Per-round proof of correct accumulation. For atomic schemes
    /// this is typically `()` (fold happens in-line).
    type AccumulationProof;

    /// Absorb the scheme-level FS prologue: `AS:` tag + scheme NAME +
    /// inner IOP NAME + inner IOP ior_names. Subsumes the inner
    /// `IOP::absorb_protocol_map_prover` — callers invoke one or the
    /// other, not both.
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

    /// Decider — closes the accumulator. The single BCLMS-uniform check
    /// across split-accumulation schemes: `(instance, witness) → ok/err`.
    fn decide(
        &self,
        acc_instance: &Self::AccumulatorInstance,
        acc_witness: &Self::AccumulatorWitness,
    ) -> Result<(), DeciderError>;
}

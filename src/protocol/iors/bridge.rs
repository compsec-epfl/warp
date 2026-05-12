//! TC → OOD bridge phase.
//!
//! After TwinConstraint reduces to `(γ, ζ₀, β_τ)` on the verifier side
//! and `(γ, ζ₀, β_τ, deferred, f, z)` on the prover side, three new
//! values get published into the transcript:
//!
//! - `η = ⟨ eq(β_τ), p(z) ⟩` — bundled-PESAT evaluation
//! - `ν₀ = f̂(ζ₀)` — reduced-oracle evaluation at the new code point
//! - `td_new` — Merkle commit to `f`'s codeword (becomes the next
//!   accumulator's root)
//!
//! The prover also splits `z` into `(new_x, new_w) = z[..N-k], z[N-k..]`
//! for the next accumulator's `(β.1, witness.w)` slots.
//!
//! The verifier reads `(td_digest, η, ν₀)` from the transcript and
//! discharges TwinConstraint's deferred oracle check:
//!
//! ```text
//!   eq(τ, γ) · (ν₀ + ω · η)  ≟  final_claim
//! ```
//!
//! Modeled as an IOR for uniformity with the rest of the choreography,
//! even though it has no verifier challenges — Bridge is "0-round,
//! prover sends three values, verifier checks deferred."
//!
//! IOR ports
//! ---------
//! - input (prover): `{ zeta_0, beta_tau, z, f, bundled_pesat, hasher,
//!   code_len, log_m, n_minus_k }`
//! - input (verifier): `{ gamma, deferred }`
//! - `reduced`: `{ eta, nu_0, td_new_root }` — same on both sides
//! - `carry` (prover): `{ td_new, new_x, new_w }` — feeds the next
//!   accumulator
//! - verifier has no carry — `discharge` consumes the deferred check
//!   in-place

use ark_ff::Field;
use ark_mt::MerkleHasher;
use effsc::hypercube::compute_hypercube_eq_evals;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerifierState};
use std::marker::PhantomData;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted};
use crate::error::{ProverError, VerifierError};
use crate::protocol::oracle::Oracle;
use crate::protocol::iors::twin_constraint::DeferredOracleCheck;
use crate::protocol::iors::IOR;
use crate::relations::BundledPESAT;

// ─── Inputs ───────────────────────────────────────────────────────────────

pub struct BridgeProverInput<'a, F, P, H>
where
    F: Field,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub zeta_0: &'a [F],
    pub beta_tau: &'a [F],
    pub z: &'a [F],
    pub f: &'a Oracle<F>,
    pub bundled_pesat: &'a P,
    pub hasher: &'a H,
    pub code_len: usize,
    pub log_m: usize,
    pub n_minus_k: usize,
}

pub struct BridgeVerifierInput<'a, F: Field> {
    pub gamma: &'a [F],
    pub deferred: &'a DeferredOracleCheck<F>,
}

// ─── Output ports ─────────────────────────────────────────────────────────

/// Public reduced claim — same on both sides.
pub struct BridgeReduced<F: Field, H: MerkleHasher> {
    pub eta: F,
    pub nu_0: F,
    pub td_new_root: H::Digest,
}

pub struct BridgeProverCarry<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub td_new: WarpCommitted<H, F>,
    pub new_x: Vec<F>,
    pub new_w: Vec<F>,
}

pub struct BridgeProverOutput<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub reduced: BridgeReduced<F, H>,
    pub carry: BridgeProverCarry<F, H>,
}

pub struct BridgeVerifierOutput<F: Field, H: MerkleHasher> {
    pub reduced: BridgeReduced<F, H>,
    pub carry: (),
}

// ─── IOR ──────────────────────────────────────────────────────────────────

/// TC → OOD bridge phase configuration. Stateless; the lifetime
/// parameter exists only to anchor `ProverInput<'a>` for the IOR trait
/// impl.
pub struct Bridge<'a, F, P, H>
where
    F: Field,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub _phantom: PhantomData<(&'a F, &'a P, &'a H)>,
}

impl<'a, F, P, H> Bridge<'a, F, P, H>
where
    F: Field,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<'a, F, P, H> Default for Bridge<'a, F, P, H>
where
    F: Field,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, F, P, H> IOR for Bridge<'a, F, P, H>
where
    F: Field + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: BundledPESAT<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize + Clone,
{
    const NAME: &'static str = "Bridge";

    type ProverInput<'b>
        = BridgeProverInput<'b, F, P, H>
    where
        Self: 'b;
    type ProverOutput = BridgeProverOutput<F, H>;
    type VerifierInput<'b>
        = BridgeVerifierInput<'b, F>
    where
        Self: 'b;
    type VerifierOutput = BridgeVerifierOutput<F, H>;

    #[tracing::instrument(
        name = "bridge",
        skip_all,
        fields(log_m = input.log_m, n_minus_k = input.n_minus_k)
    )]
    fn prove<'b>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'b>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'b,
    {
        // η = ⟨ eq(β_τ), p(z) ⟩
        let beta_eq_evals = compute_hypercube_eq_evals(input.log_m, input.beta_tau);
        let eta = input
            .bundled_pesat
            .evaluate_bundled(&beta_eq_evals, input.z)
            .map_err(|_| ProverError::SpongeFish)?;

        // ν₀ = f̂(ζ₀)
        let nu_0 = input.f.query_at_point(input.zeta_0);

        // (new_x, new_w) = z[..N-k], z[N-k..]
        let (new_x_slice, new_w_slice) = input.z.split_at(input.n_minus_k);
        let new_x = new_x_slice.to_vec();
        let new_w = new_w_slice.to_vec();

        // td_new ← Merkle.commit(f.evals())
        let td_new = {
            let _s = tracing::info_span!("bridge.commit_new_oracle").entered();
            count_ops!(MerkleTreeBuilds);
            let scheme = warp_scheme::<H, F>(input.hasher.clone(), input.code_len);
            scheme.commit(&[input.f.evals().to_vec()])
        };
        let td_new_root = td_new.root().clone();

        // Absorb (td_new.root, η, ν₀)
        transcript.prover_message(&td_new_root);
        transcript.prover_message(&eta);
        transcript.prover_message(&nu_0);

        Ok(BridgeProverOutput {
            reduced: BridgeReduced {
                eta,
                nu_0,
                td_new_root,
            },
            carry: BridgeProverCarry {
                td_new,
                new_x,
                new_w,
            },
        })
    }

    #[tracing::instrument(name = "bridge.verify", skip_all)]
    fn verify<'b, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'b>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'b,
    {
        // Read (td_digest, η, ν₀) from the transcript.
        let td_new_root: H::Digest = transcript.prover_message()?;
        let eta: F = transcript.prover_message()?;
        let nu_0: F = transcript.prover_message()?;

        // Discharge TC's deferred check.
        input.deferred.discharge(input.gamma, nu_0, eta)?;

        Ok(BridgeVerifierOutput {
            reduced: BridgeReduced {
                eta,
                nu_0,
                td_new_root,
            },
            carry: (),
        })
    }
}

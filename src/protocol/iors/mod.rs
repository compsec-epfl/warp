//! Warp IORs as first-class modules.
//!
//! Each submodule implements one Interactive Oracle Reduction from the
//! WARP construction. Every IOR has the same shape (a single typed
//! `ProverInput` and `VerifierInput`, returning a single typed
//! `ProverOutput` and `VerifierOutput`), so the orchestrator in
//! [`crate::WARP::prove`] / [`crate::WARP::verify`] is a destructured
//! choreography of IOR calls.
//!
//! Output structure convention: each `ProverOutput` / `VerifierOutput`
//! is built from named *ports*:
//!
//! - `reduced` — public reduced claim, identical on prover and verifier
//!   sides (same type). Both endpoints derive their `reduced` from the
//!   transcript reads.
//! - `carry` — endpoint-only local state needed by *later* IORs (prover
//!   carry holds full oracle data, witnesses, commitments; verifier
//!   carry holds parsed digests).
//! - `proof` — external proof material that the orchestrator collects
//!   into the global `WARPProof`. Optional; many IORs have `()` here.
//!
//! Downstream IORs reference upstream ports explicitly by name in their
//! own `ProverInput` / `VerifierInput`. The WARP protocol is a DAG over
//! IORs, not a linear chain.

pub mod batching;
pub mod bridge;
pub mod ood;
pub mod oracle_handle;
pub mod pesat;
pub mod proximity;
pub mod sample_queries;
pub mod twin_constraint;

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};

/// Interactive Oracle Reduction.
///
/// The single abstraction in WARP's protocol layer. Each IOR exposes
/// `prove(transcript, input) -> output` and a symmetric `verify`. Both
/// sides return a typed `ProverOutput` / `VerifierOutput` whose fields
/// are named ports (`reduced`, `carry`, optionally `proof`) — the
/// caller destructures by name at the call site.
///
/// Drift between prover and verifier sides is structural: the `reduced`
/// field on both outputs has the same type. Each IOR's implementation
/// is responsible for computing the same reduced value on both sides
/// (typically via a shared private helper inside its module).
pub trait IOR {
    /// Human-readable identifier — matches the WARP paper's phase label.
    const NAME: &'static str;

    /// Prover-side input. Bundles the public claim, prover-private
    /// witness, and any upstream-IOR oracle data the prover consumes.
    type ProverInput<'a>
    where
        Self: 'a;

    /// Prover-side output: `reduced` + `carry` + optional `proof`.
    type ProverOutput;

    /// Verifier-side input. Bundles the public claim and any
    /// upstream-IOR digests/handles the verifier consumes.
    type VerifierInput<'a>
    where
        Self: 'a;

    /// Verifier-side output: `reduced` + `carry` + optional `proof`.
    type VerifierOutput;

    fn prove<'a>(
        &self,
        transcript: &mut ProverState,
        input: Self::ProverInput<'a>,
    ) -> Result<Self::ProverOutput, ProverError>
    where
        Self: 'a;

    fn verify<'a, 'v>(
        &self,
        transcript: &mut VerifierState<'v>,
        input: Self::VerifierInput<'a>,
    ) -> Result<Self::VerifierOutput, VerifierError>
    where
        Self: 'a;
}

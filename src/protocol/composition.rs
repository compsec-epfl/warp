//! Typed composition of [`IOR`]s — design sketch.
//!
//! # Status
//!
//! **Sketch, not yet wired.** The orchestrator in [`crate::WARP::prove`] /
//! [`crate::WARP::verify`] still threads the five phases by hand. This
//! module lays out the trait shape that would let us replace those ~250
//! lines of bespoke threading with a typed pipeline value, and explains
//! the open design questions before we migrate.
//!
//! # Goal
//!
//! Today, swapping out (say) [`crate::protocol::phases::batching::Batching`]
//! for a different sumcheck variant requires editing the orchestrator at
//! two sites (prove + verify), updating the proof struct, and re-deriving
//! by hand which fields flow into which downstream phase. We want this to
//! be a one-line type change at the pipeline definition.
//!
//! # The two shapes WARP actually needs
//!
//! ## (a) Linear chain
//!
//! Most pairs of WARP phases compose as `A.ReducedStatement → B.Statement`
//! plus a constructor that may pull in extra orchestrator state. The
//! [`Then`] combinator below captures this case.
//!
//! ## (b) Fan-in / shared state
//!
//! The hard case: [`crate::protocol::phases::batching::BatchingStatement`]
//! is built from *three* upstream sources — the TwinConstraint reduction
//! (`zeta_0`), the Ood phase (`samples_flat`), and the orchestrator's
//! sampled query indices. A pure `A.then(B)` chain can't express that
//! directly. Two reasonable answers:
//!
//! - **Pipeline state:** thread an opaque accumulator value through the
//!   chain, with each phase reading from / writing to it. Closer to a
//!   typed monadic state-machine. Good ergonomics, more boilerplate per
//!   phase to declare what state it touches.
//! - **Explicit assembly nodes:** make the assembly itself a typed node
//!   in the pipeline (think: a "construct BatchingStatement from prior
//!   outputs" node), and let the chain only handle the IORs proper. The
//!   `from_phase_outputs` constructor on `BatchingStatement` (added in
//!   the IOR-cleanup pass) is already the right shape for this — we'd
//!   lift it to a trait method.
//!
//! The second is closer to the "single source of truth" pattern that
//! [`IOR::reduce_statement`] already enforces inside each phase, and
//! plays well with the orchestrator owning between-phase computations
//! (e.g. the `eta` / `nu_0` reads, the `td_new` commit, the query
//! sampling). The pipeline holds the phases; the orchestrator owns the
//! glue.
//!
//! # Sketch
//!
//! ```ignore
//! let pipeline = Pesat::new(...)
//!     .then(TwinConstraint::new(...))
//!     .then(Ood::new())
//!     .then(Batching::new())
//!     .then(Proximity::new(...));
//!
//! let (final_reduced, proof) = pipeline.prove(&mut prover_state, statement, witness)?;
//! ```
//!
//! Open: how `Witness` flows. WARP phases mostly take witness slices by
//! reference, with each phase reading a different subset. A pipeline
//! value either has to (a) accept a single tuple-of-all-witnesses and
//! pluck per phase, or (b) take the witness once and re-borrow into
//! each phase. (b) is closer to the current orchestrator and avoids
//! re-cloning, but requires a `WitnessProjection<P>` associated type on
//! each phase.

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;

/// Two-phase linear composition. The next phase's statement is built
/// from the previous phase's [`IOR::ReducedStatement`] via `make_next`.
///
/// **Limitation:** captures only "B's statement is fully determined by
/// A's reduced statement" — does not handle WARP's fan-in case where
/// downstream phases need state from multiple upstream phases plus the
/// orchestrator. See module docs.
pub struct Then<A, B, MakeNext> {
    pub first: A,
    pub second: B,
    pub make_next: MakeNext,
}

impl<A, B, MakeNext> Then<A, B, MakeNext> {
    pub fn new(first: A, second: B, make_next: MakeNext) -> Self {
        Self {
            first,
            second,
            make_next,
        }
    }
}

/// Extension trait so any [`IOR`] can be chained with `.then(next, make_next)`.
pub trait IORChain: IOR + Sized {
    fn then<B, MakeNext>(self, next: B, make_next: MakeNext) -> Then<Self, B, MakeNext>
    where
        B: IOR,
        MakeNext: Fn(&Self::ReducedStatement) -> B::Statement,
    {
        Then::new(self, next, make_next)
    }
}

impl<T: IOR> IORChain for T {}

/// Composed prove: run `first.prove`, derive `second`'s statement via
/// `make_next`, run `second.prove`. Returns `second`'s reduced statement
/// and a tuple of both proof strings.
///
/// **Why this isn't yet a `impl IOR for Then<...>`**: the composition's
/// associated types (`ReducedStatement`, `ProofString`, etc.) don't
/// align trivially with the [`IOR`] trait — the proof string becomes a
/// tuple, the reduced witness becomes the second's, and pipeline-level
/// `Statement` / `Witness` need projections. Working out those projections
/// is the next design task; the prove/verify methods below are the
/// minimum viable demonstration.
impl<A, B, MakeNext> Then<A, B, MakeNext>
where
    A: IOR,
    B: IOR,
    MakeNext: Fn(&A::ReducedStatement) -> B::Statement,
{
    #[allow(clippy::type_complexity)]
    pub fn prove(
        &self,
        prover_state: &mut ProverState,
        a_statement: &A::Statement,
        a_witness: &A::Witness,
        a_inputs: &A::ProverInputs,
        b_witness: &B::Witness,
        b_inputs: &B::ProverInputs,
    ) -> Result<
        (
            B::ReducedStatement,
            (A::ProofString, B::ProofString),
            B::ReducedWitness,
        ),
        ProverError,
    > {
        let (a_reduced, a_proof, _a_red_wit) =
            self.first.prove(prover_state, a_statement, a_witness, a_inputs)?;
        let b_statement = (self.make_next)(&a_reduced);
        let (b_reduced, b_proof, b_red_wit) =
            self.second
                .prove(prover_state, &b_statement, b_witness, b_inputs)?;
        Ok((b_reduced, (a_proof, b_proof), b_red_wit))
    }

    #[allow(clippy::type_complexity)]
    pub fn verify<'a>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        a_statement: &A::Statement,
        a_inputs: &A::VerifierInputs,
        b_inputs: &B::VerifierInputs,
    ) -> Result<
        (
            B::ReducedStatement,
            (A::VerifierOutputs, B::VerifierOutputs),
        ),
        VerifierError,
    > {
        let (a_reduced, a_vouts) = self.first.verify(verifier_state, a_statement, a_inputs)?;
        let b_statement = (self.make_next)(&a_reduced);
        let (b_reduced, b_vouts) = self.second.verify(verifier_state, &b_statement, b_inputs)?;
        Ok((b_reduced, (a_vouts, b_vouts)))
    }
}

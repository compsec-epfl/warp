//! Generic [`Then<A, B, Trans>`] combinator over [`Pipeline`].
//!
//! Demonstrates that [`crate::protocol::composition::Pipeline`] actually
//! composes — without forcing every consumer to hand-write a
//! [`crate::protocol::composition::WarpPipeline`]-style struct each time.
//!
//! # Design choices (first cut)
//!
//! 1. **Witness threading.** `Then::Witness = (A::Witness, B::Witness)`.
//!    Caller supplies a tuple, `prove` destructures. Simple, but does not
//!    scale gracefully past 2 phases — chains nest as
//!    `((A::W, B::W), C::W)` etc. Follow-up: introduce a
//!    `WitnessProjection` trait so each phase plucks its slice from a
//!    flat top-level witness, eliminating the nesting.
//! 2. **Context.** Shared. `A::Context = B::Context = Then::Context`.
//!    Closer to the [`crate::protocol::composition::WarpPipeline`] data
//!    flow (one orchestrator-owned struct read by all phases). Alternative
//!    would be `Then::Context = (A::Context, B::Context)` — split per
//!    sub-pipeline — but inter-phase glue (e.g. WARP's `eta` / `nu_0` /
//!    `td_new`) is exactly the kind of thing that wants to land in shared
//!    state, not in B's private context.
//! 3. **Transition function shape.** Closure rather than dedicated trait.
//!    More ergonomic at call sites; the trait variant
//!    (`trait Transition<A, B> { fn transition(...); }`) is more
//!    inspectable / nameable at the type level — switch if the closure
//!    blanket impls cause inference problems for downstream users.
//!
//! # Proof shape
//!
//! `Then::Proof = (A::Proof, B::Proof)` — nests for now. A
//! `WithFlatProof` adapter (sketched in
//! [`crate::protocol::composition::WithFlatProof`]) is the planned
//! follow-up that maps the nested tuple to a flat caller-supplied proof
//! type.
//!
//! # What this file is NOT
//!
//! Not a replacement for `WarpPipeline`. `WarpPipeline` is the concrete,
//! hand-tuned five-phase composition with known WARP-specific glue
//! (committing `td_new`, sampling shift queries between Ood and
//! Batching, etc). `Then` is the generic combinator that proves the
//! abstraction composes; once verifier-side oracle handles land
//! (`crate::protocol::phases::oracle_handle`) and `Pipeline::verify`
//! is wired on `WarpPipeline`, the WARP composition can be expressed
//! as a chain of `Then` combinators if desired.

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};
use crate::protocol::composition::Pipeline;

/// Sequential composition of two [`Pipeline`]s.
///
/// Holds `first` and `second` by value plus a `transition` value (a
/// `(prove_fn, verify_fn)` closure pair) that runs *between* the two
/// pipelines' `prove` (or `verify`) calls. The transition is where
/// orchestrator-owned glue lives — reading challenges off the
/// transcript, deriving `B`'s statement from `A`'s reduced output,
/// updating shared context.
///
/// See module docs for the design choices behind the associated-type
/// shapes (witness tuple, shared context, closure-based transition).
pub struct Then<A, B, Trans> {
    pub first: A,
    pub second: B,
    pub transition: Trans,
}

impl<A, B, Trans> Then<A, B, Trans> {
    /// Build a `Then` combinator. `transition` is the inter-phase glue
    /// — see the [`Pipeline`] impl below for its required shape.
    pub fn new(first: A, second: B, transition: Trans) -> Self {
        Self {
            first,
            second,
            transition,
        }
    }
}

/// Closure-pair-based [`Pipeline`] composition.
///
/// `Trans` is `(FProve, FVerify)`. Most call sites only need the
/// matching half — at the time the pipeline value is constructed only
/// one side runs — but the type-level honesty of "a transition is a
/// pair of closures" matches the trait's prove/verify symmetry.
/// Callers using only one side can pass any no-op closure for the
/// other slot.
///
/// Both closures receive:
/// - `&mut ProverState` / `&mut VerifierState` so they can sample
///   challenges or absorb glue values into the transcript,
/// - `&A::FinalReduced` — A's reduced output,
/// - `&mut Context` — the shared orchestrator-owned state,
///
/// and return `B`'s statement.
impl<A, B, FProve, FVerify> Pipeline for Then<A, B, (FProve, FVerify)>
where
    A: Pipeline,
    B: Pipeline<Context = A::Context>,
    FProve: Fn(&mut ProverState, &A::FinalReduced, &mut A::Context) -> B::Statement,
    FVerify: for<'a> Fn(&mut VerifierState<'a>, &A::FinalReduced, &mut A::Context) -> B::Statement,
{
    type Statement = A::Statement;
    type Witness = (A::Witness, B::Witness);
    type Context = A::Context;
    type Proof = (A::Proof, B::Proof);
    type FinalReduced = B::FinalReduced;

    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        witness: &Self::Witness,
        context: &mut Self::Context,
    ) -> Result<(Self::FinalReduced, Self::Proof), ProverError> {
        let (a_witness, b_witness) = witness;
        let (a_reduced, a_proof) =
            self.first.prove(prover_state, statement, a_witness, context)?;
        let b_statement = (self.transition.0)(prover_state, &a_reduced, context);
        let (b_reduced, b_proof) =
            self.second
                .prove(prover_state, &b_statement, b_witness, context)?;
        Ok((b_reduced, (a_proof, b_proof)))
    }

    fn verify<'a>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement,
        context: &mut Self::Context,
        proof: &Self::Proof,
    ) -> Result<Self::FinalReduced, VerifierError> {
        let (a_proof, b_proof) = proof;
        let a_reduced = self
            .first
            .verify(verifier_state, statement, context, a_proof)?;
        let b_statement = (self.transition.1)(verifier_state, &a_reduced, context);
        let b_reduced = self
            .second
            .verify(verifier_state, &b_statement, context, b_proof)?;
        Ok(b_reduced)
    }
}

#[cfg(test)]
mod tests {
    //! Type-level validation: the generic `Then` combinator typechecks
    //! and, at runtime, runs both child pipelines in order. Crypto is
    //! deliberately absent — the fake `Pipeline` implementations below
    //! exist solely to drive `Then::prove` through the trait machinery.
    //!
    //! What we actually assert:
    //! 1. `Then::prove` calls `A::prove`, then the transition closure,
    //!    then `B::prove`, in that order.
    //! 2. The shared context is threaded through all three steps.
    //! 3. `B`'s statement is derived from `A`'s reduced output (the
    //!    transition multiplies by 10).
    //! 4. `Then::Proof = (A::Proof, B::Proof)` lands the nested tuple.

    use super::*;

    /// Test-only ordered event log. Each fake pipeline's `prove` pushes
    /// an entry; the transition closure pushes its own. The final
    /// vector is the assertion target.
    #[derive(Default)]
    struct Trace(Vec<String>);

    /// Trivial fake pipeline — does no cryptography. `prove` records
    /// its label + the witness value into the shared trace and returns
    /// `stmt + wit` as the "reduction" so the transition has something
    /// nontrivial to read.
    struct FakePipeline {
        label: &'static str,
    }

    impl Pipeline for FakePipeline {
        type Statement = u32;
        type Witness = u32;
        type Context = Trace;
        type Proof = u32;
        type FinalReduced = u32;

        fn prove(
            &self,
            _prover_state: &mut ProverState,
            statement: &Self::Statement,
            witness: &Self::Witness,
            context: &mut Self::Context,
        ) -> Result<(Self::FinalReduced, Self::Proof), ProverError> {
            context.0.push(format!(
                "{}.prove(stmt={}, wit={})",
                self.label, statement, witness
            ));
            Ok((statement + witness, *witness))
        }

        fn verify<'a>(
            &self,
            _verifier_state: &mut VerifierState<'a>,
            _statement: &Self::Statement,
            _context: &mut Self::Context,
            _proof: &Self::Proof,
        ) -> Result<Self::FinalReduced, VerifierError> {
            unimplemented!("verify side not exercised by this test");
        }
    }

    #[test]
    fn then_runs_first_then_transition_then_second() {
        let pipeline = Then::new(
            FakePipeline { label: "A" },
            FakePipeline { label: "B" },
            (
                // Prove-side transition: log + derive B's stmt from A's
                // reduced output. Multiplies by 10 — arbitrary
                // deterministic transform we can assert on.
                |_ps: &mut ProverState, a_reduced: &u32, ctx: &mut Trace| -> u32 {
                    ctx.0.push(format!("transition(a_reduced={})", a_reduced));
                    a_reduced * 10
                },
                // Verify-side closure — never invoked in this test.
                |_vs: &mut VerifierState, _r: &u32, _c: &mut Trace| -> u32 { 0 },
            ),
        );

        let mut prover_state = spongefish::domain_separator!("test::then::compose")
            .without_session()
            .instance(&0u32)
            .std_prover();

        let mut trace = Trace::default();
        let witness: (u32, u32) = (3, 7);
        let statement: u32 = 5;

        let (final_reduced, proof) = pipeline
            .prove(&mut prover_state, &statement, &witness, &mut trace)
            .expect("composition should run");

        // Order: A.prove → transition → B.prove.
        assert_eq!(
            trace.0.len(),
            3,
            "expected 3 events; got {:?}",
            trace.0
        );
        assert_eq!(trace.0[0], "A.prove(stmt=5, wit=3)");
        // A's reduced = stmt(5) + wit(3) = 8 → B's stmt = 80.
        assert_eq!(trace.0[1], "transition(a_reduced=8)");
        assert_eq!(trace.0[2], "B.prove(stmt=80, wit=7)");

        // Final reduced = B's reduced = B.stmt + B.wit = 80 + 7 = 87.
        assert_eq!(final_reduced, 87);
        // Proof = (A.proof, B.proof) = (A.wit, B.wit) = (3, 7).
        assert_eq!(proof, (3, 7));
    }
}

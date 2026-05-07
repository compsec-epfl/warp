//! Typed composition of [`IOR`]s — design sketch.
//!
//! # Status
//!
//! **Sketch, not yet wired.** The orchestrator in [`crate::WARP::prove`] /
//! [`crate::WARP::verify`] still threads the five phases by hand. This
//! module proposes a layered design — keep [`IOR`] as the single-phase
//! abstraction it already is, build a new [`Pipeline`] trait above it
//! for composition.
//!
//! # Why two traits, not one extended one
//!
//! `IOR` is well-shaped for one phase: `(stmt, wit, oracles_in) →
//! (reduced_stmt, oracles_out)` plus the [`IOR::reduce_statement`] single
//! source of truth. Trying to make a `Then<A, B>` value `impl IOR` runs
//! into three problems:
//!
//! - `ReductionInputs` doesn't generalize. It's per-phase by construction
//!   — a composition reduces a *sequence* of statements, not one.
//! - `ProofString = (A::ProofString, B::ProofString)` nests 5-deep for
//!   WARP. Extracting pieces to assemble the global proof is just the
//!   hand-threading we wanted to eliminate, in a different shape.
//! - WARP's data flow isn't a clean linear chain — it's DAG-shaped.
//!   `BatchingStatement` reads from TwinConstraint's reduction *and*
//!   Ood's outputs *and* orchestrator-sampled queries. `IOR` has no
//!   place for "between-phase orchestrator work."
//!
//! Analogy: `Functor` captures `fmap`, `Monad` captures sequencing —
//! they're separate traits because they're different concepts. Same here:
//! `IOR` captures phase semantics; `Pipeline` captures composition.
//! Folding sequencing into `IOR` makes both worse.
//!
//! # The shape
//!
//! ```ignore
//! trait Pipeline {
//!     type Statement;
//!     type Witness;
//!     type Context;        // orchestrator-owned state read by phases
//!     type Proof;          // flat — pipeline owns the assembly
//!     type FinalReduced;   // the last phase's ReducedStatement
//!     fn prove(...) -> Result<(Self::FinalReduced, Self::Proof), ProverError>;
//!     fn verify(...) -> Result<Self::FinalReduced, VerifierError>;
//! }
//! ```
//!
//! Three things make this work where the bare `Then.impl IOR` attempt
//! didn't:
//!
//! 1. **Context as a first-class associated type.** WARP's actual data
//!    flow has each phase reading some upstream-phase output *and* some
//!    pipeline-level shared state (the `acc_instance`, the fresh
//!    witnesses, the sampled queries, etc.). Context is that shared
//!    state. The orchestrator builds it once; each phase reads what it
//!    needs.
//! 2. **Witness projection.** Each phase reads a different slice of the
//!    pipeline's `Witness`. A composition combinator takes a
//!    user-supplied projection `Self::Witness → SubPhase::Witness` so
//!    no re-cloning is forced.
//! 3. **Flat `Proof`.** The pipeline owns proof assembly — a leaf
//!    pipeline produces a concrete user-defined proof type via a
//!    user-supplied `assemble` function. No nested-tuple
//!    `(((A, B), C), D)` shapes leak out.
//!
//! # Worked example: how WARP would compose
//!
//! ```ignore
//! // Context = everything the orchestrator computes / holds across phases.
//! struct WARPContext<'a, F, H> {
//!     acc_instance: &'a AccumulatorInstance<F, H>,
//!     acc_witness: &'a AccumulatorWitness<F, H>,
//!     acc_codewords: &'a [Vec<F>],
//!     instances: &'a [Vec<F>],
//!     witnesses: &'a [Vec<F>],
//!     queries: Option<QueryIndices<F>>,        // populated mid-pipeline
//!     pesat_outputs: Option<PesatReduced<F>>,  // populated by Pesat phase
//!     // ... etc.
//! }
//!
//! let pipeline =
//!     Pesat::new(...)
//!         .lift(/* prover_inputs_fn */ |_, ctx| (), /* witness_fn */ |w, _| w.fresh)
//!     .then(
//!         TwinConstraint::new(...).lift(...),
//!         /* make_next_stmt */ |pesat_red, ctx| TwinConstraintStatement {
//!             acc_instance: ctx.acc_instance.clone(),
//!             l1_mus: pesat_red.mus.clone(),
//!             l1_taus: pesat_red.taus.clone(),
//!             ..
//!         },
//!     )
//!     .then(Ood::new().lift(...), /* make_next_stmt */ |_, _| OodStatement { .. })
//!     .then(Batching::new().lift(...), |_, ctx| BatchingStatement::from_phase_outputs(...))
//!     .then(Proximity::new(...).lift(...), |_, ctx| ProximityStatement { .. })
//!     .assemble(|reduced, parts, ctx| WARPProof {
//!         rt_0: parts.pesat.td_0_root,
//!         mu_i: parts.pesat.mus,
//!         // ... pluck from named parts, not nested tuples
//!     });
//! ```
//!
//! Swapping `Batching` for a different sumcheck variant becomes a one-line
//! type change at the pipeline definition. The phases stay
//! self-contained; the assembly function is the only place that names
//! the global proof shape.
//!
//! # Open design questions
//!
//! - **Is `Context` `&mut`?** Some phases mutate (e.g., the orchestrator
//!   sampling query indices "between" Ood and Batching). A `&mut Context`
//!   threaded through `prove` is one answer; an explicit "context node"
//!   in the pipeline (no IOR call, just a context update) is another.
//! - **`ProverInputs` lifetime story.** Phases like
//!   [`crate::protocol::phases::twin_constraint::TwinConstraintProverInputs`]
//!   borrow from upstream reduced witnesses. The pipeline value can't
//!   live longer than those borrows. Either (a) `prove` takes a
//!   `WitnessRef` instead of `Witness`, or (b) the lifetime is on
//!   `Pipeline` itself.
//! - **Verifier-side oracle handles.** Verifier `ProverInputs` carry
//!   `IndexedOracle` / `EvalOracle` handles — exactly the refactor
//!   already noted in
//!   `[crate::protocol::phases::oracle_handle]`. Pipeline composition
//!   slots in *over* that abstraction; we shouldn't conflate the two.

use spongefish::{ProverState, VerifierState};

use crate::error::{ProverError, VerifierError};
use crate::protocol::phases::IOR;

/// Composition of one or more [`IOR`]s into a typed pipeline.
///
/// Models WARP-shaped flows: each phase reads from its own statement
/// plus a shared `Context`, and emits a chunk of proof bytes plus its
/// reduced statement. The pipeline value owns proof assembly: callers
/// see one flat [`Pipeline::Proof`] type and one flat
/// [`Pipeline::FinalReduced`] result, not nested tuples.
///
/// **Not yet wired.** The methods below are the minimum-viable shape;
/// no current WARP code calls them. See module docs for the worked
/// example of how the five phases would compose.
pub trait Pipeline {
    /// Top-level statement supplied to the pipeline. Each phase derives
    /// its own statement from this plus the upstream reduction.
    type Statement;
    /// Top-level witness. Each phase projects out the slice it needs.
    type Witness;
    /// Orchestrator-owned shared state read by phases. WARP's
    /// `acc_instance`, fresh witnesses, sampled queries, and inter-phase
    /// derived values live here.
    type Context;
    /// Flat global proof value. Pipeline owns assembly.
    type Proof;
    /// The last phase's [`IOR::ReducedStatement`].
    type FinalReduced;

    fn prove(
        &self,
        prover_state: &mut ProverState,
        statement: &Self::Statement,
        witness: &Self::Witness,
        context: &mut Self::Context,
    ) -> Result<(Self::FinalReduced, Self::Proof), ProverError>;

    fn verify<'a>(
        &self,
        verifier_state: &mut VerifierState<'a>,
        statement: &Self::Statement,
        context: &mut Self::Context,
        proof: &Self::Proof,
    ) -> Result<Self::FinalReduced, VerifierError>;
}

/// Lift a single [`IOR`] into a one-phase [`Pipeline`].
///
/// The user-supplied closures bridge [`IOR`]'s per-phase types
/// (`Statement`, `Witness`, `ProverInputs`, `VerifierInputs`) to the
/// pipeline-level types — they're how a phase declares "here's how I
/// project myself out of the pipeline-level state."
///
/// **Sketch only.** Concrete implementation deferred until the lifetime
/// design (open question #2 in module docs) is settled — the closures
/// likely need to return references rather than owned values for
/// production use.
pub struct Lift<I, MakeStmt, MakeWit, MakeProverInputs, MakeVerifierInputs, AssembleProof> {
    pub inner: I,
    pub make_statement: MakeStmt,
    pub make_witness: MakeWit,
    pub make_prover_inputs: MakeProverInputs,
    pub make_verifier_inputs: MakeVerifierInputs,
    pub assemble_proof: AssembleProof,
}

/// Sequential composition of two pipelines.
///
/// `make_next_context` runs *between* the two phases' `prove`/`verify`
/// calls. It's where orchestrator-owned glue lives — sampling queries,
/// reading `eta`/`nu_0` off the transcript, committing to a new oracle.
/// In the WARP case, the `td_new` commit and the OOD-to-Batching
/// `zetas_prefix` assembly would land here.
pub struct Then<A, B, MakeNextContext> {
    pub first: A,
    pub second: B,
    pub make_next_context: MakeNextContext,
}

/// Convert a pipeline's nested intermediate values into a flat
/// user-defined [`Pipeline::Proof`].
///
/// Wraps any `Pipeline` and replaces its `Proof` type. The `Map` closure
/// receives the inner proof + final reduced statement and returns the
/// caller's flat proof shape. This is the leaf that closes the
/// "no nested tuples leak out" property promised in the trait docs.
pub struct WithFlatProof<P, FlatProof, Map> {
    pub inner: P,
    pub map: Map,
    pub _phantom: std::marker::PhantomData<FlatProof>,
}

// Generic `Lift` / `Then` / `WithFlatProof` impls deliberately omitted
// for now. The concrete composition below — `PesatTwinConstraint` —
// validates that the GAT-decoupled `IOR` trait actually composes; the
// generic combinators wait on the verifier-side oracle-handle refactor
// (open question #3 above) so the abstraction lands once, against the
// final `IOR` shape.

// ─── Concrete demo: Pesat → TwinConstraint ────────────────────────────────
//
// First real composition built on the GAT'd `IOR`. Holds both phases by
// value so the same pipeline can serve many `prove` calls with
// different witnesses — the lifetime decoupling that motivated the GAT
// migration. Used by `tests/composition_demo.rs`.

use ark_codes::traits::LinearCode;
use ark_ff::{Field, PrimeField};
use ark_mt::MerkleHasher;
use spongefish::{Decoding, Encoding, NargDeserialize, NargSerialize};
use std::marker::PhantomData;

use crate::protocol::phases::pesat::{
    Pesat, PesatReducedStatement, PesatReducedWitness, PesatStatement, PesatWitness,
};
use crate::protocol::phases::twin_constraint::{
    TwinConstraint, TwinConstraintProverInputs, TwinConstraintReducedStatement,
    TwinConstraintReducedWitness, TwinConstraintStatement, TwinConstraintWitness,
};
use crate::relations::r1cs::R1CSConstraints;
use crate::types::AccumulatorInstance;

/// Pipeline value chaining Pesat into TwinConstraint.
///
/// Holds both phases as data. Constructed once, calls `prove` many
/// times — each call passes new short-lived witnesses without forcing
/// the phase structs (or their `R1CSConstraints` / code / hasher
/// borrows) to be reconstructed.
pub struct PesatTwinConstraint<'phase, F, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    pub pesat: Pesat<'phase, F, C, H>,
    pub twin_constraint: TwinConstraint<'phase, F, H>,
}

impl<'phase, F, C, H> PesatTwinConstraint<'phase, F, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    /// Build the pipeline. Borrows `code`, `hasher`, and `r1cs` for
    /// `'phase` — the lifetime of the WARP params, typically.
    pub fn new(code: &'phase C, hasher: &'phase H, r1cs: &'phase R1CSConstraints<F>) -> Self {
        Self {
            pesat: Pesat {
                code,
                hasher,
                _phantom: PhantomData,
            },
            twin_constraint: TwinConstraint {
                r1cs,
                _phantom: PhantomData,
            },
        }
    }
}

/// Static config (dimensions) consumed by both phases. Cheap to clone;
/// pass by reference.
pub struct PesatTcConfig {
    pub l1: usize,
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
}

/// Per-call inputs. Lifetime `'a` is independent of the pipeline's
/// `'phase` — exactly what the GAT migration unlocked.
pub struct PesatTcInputs<'a, F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub witnesses: &'a [Vec<F>],
    pub instances: &'a [Vec<F>],
    pub acc_witness_w: &'a [Vec<F>],
    pub acc_codewords: &'a [Vec<F>],
    /// Moves into `TwinConstraintStatement`. Cloned across calls if a
    /// single accumulator is reused.
    pub acc_instance: AccumulatorInstance<F, H>,
}

/// Reduced output of the Pesat → TwinConstraint chain. Holds both
/// phases' reduced statements + reduced witnesses; downstream phases
/// (Ood / Batching / Proximity) read from these.
pub struct PesatTcReduced<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub pesat: PesatReducedStatement<F>,
    pub tc: TwinConstraintReducedStatement<F>,
    pub pesat_witness: PesatReducedWitness<F, H>,
    pub tc_witness: TwinConstraintReducedWitness<F>,
}

impl<'phase, F, C, H> PesatTwinConstraint<'phase, F, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    /// Run Pesat then TwinConstraint, threading the upstream reduction
    /// into the downstream statement and the upstream reduced witness's
    /// codewords into the downstream prover inputs.
    pub fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        config: &PesatTcConfig,
        inputs: PesatTcInputs<'a, F, H>,
    ) -> Result<PesatTcReduced<F, H>, ProverError> {
        let (pesat_red, _, pesat_witness) = self.pesat.prove(
            prover_state,
            &PesatStatement {
                l1: config.l1,
                log_m: config.log_m,
            },
            &PesatWitness {
                witnesses: inputs.witnesses,
            },
            &(),
        )?;

        // l1_taus is consumed below; clone it for the statement so the
        // returned `pesat_red` keeps its own copy via `pesat.taus` (the
        // values *are* the same — `reduce_statement` produces them).
        let (tc_red, _, tc_witness) = self.twin_constraint.prove(
            prover_state,
            &TwinConstraintStatement {
                acc_instance: inputs.acc_instance,
                l1_mus: pesat_red.mus.clone(),
                l1_taus: pesat_red.taus.clone(),
                log_l: config.log_l,
                log_m: config.log_m,
                log_n: config.log_n,
            },
            &TwinConstraintWitness {
                acc_witness_w: inputs.acc_witness_w,
                instances: inputs.instances,
                witnesses: inputs.witnesses,
            },
            &TwinConstraintProverInputs {
                fresh_codewords: &pesat_witness.codewords,
                acc_codewords: inputs.acc_codewords,
            },
        )?;

        Ok(PesatTcReduced {
            pesat: pesat_red,
            tc: tc_red,
            pesat_witness,
            tc_witness,
        })
    }
}

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

use effsc::hypercube::compute_hypercube_eq_evals;

use crate::count_ops;
use crate::crypto::merkle::{warp_scheme, WarpCommitted};
use crate::protocol::phases::ood::{Ood, OodProverInputs, OodReducedStatement, OodStatement};
use crate::protocol::phases::pesat::{
    Pesat, PesatReducedStatement, PesatReducedWitness, PesatStatement, PesatWitness,
};
use crate::protocol::phases::twin_constraint::{
    TwinConstraint, TwinConstraintProverInputs, TwinConstraintReducedStatement,
    TwinConstraintReducedWitness, TwinConstraintStatement, TwinConstraintWitness,
};
use crate::relations::r1cs::R1CSConstraints;
use crate::relations::BundledPESAT;
use crate::types::AccumulatorInstance;

/// Growing pipeline value: Pesat → TwinConstraint → Ood.
///
/// Holds three phases as data plus the few `WARPParams` references
/// the inter-phase glue needs (`bundled_pesat`, `hasher`, `code_len`).
/// Constructed once, `prove` is callable many times with short-lived
/// per-batch inputs — the GAT decoupling on [`crate::protocol::phases::IOR`]
/// keeps that ergonomic.
///
/// Will grow: Batching next (with the DAG fan-in from `zeta_0` +
/// `samples_flat` + sampled queries), then Proximity, at which point
/// this struct becomes the full replacement for `WARP::prove`.
pub struct WarpPipeline<'phase, F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: BundledPESAT<F>,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
{
    pub pesat: Pesat<'phase, F, C, H>,
    pub twin_constraint: TwinConstraint<'phase, F, H>,
    pub ood: Ood<'phase, F>,
    /// `BundledPESAT` for the inter-phase `eta` evaluation between TC
    /// and Ood. Kept by reference so the pipeline value doesn't own
    /// the relation.
    pub bundled_pesat: &'phase P,
    /// Cached for building the new-oracle Merkle commit between TC
    /// and Ood (`warp_scheme(hasher.clone(), code_len)`).
    pub code_len: usize,
}

impl<'phase, F, P, C, H> WarpPipeline<'phase, F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: BundledPESAT<F>,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize + Clone + Eq,
{
    pub fn new(
        code: &'phase C,
        hasher: &'phase H,
        r1cs: &'phase R1CSConstraints<F>,
        bundled_pesat: &'phase P,
        code_len: usize,
    ) -> Self {
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
            ood: Ood::new(),
            bundled_pesat,
            code_len,
        }
    }
}

/// Static config (dimensions + per-phase tuning). Cheap to pass by
/// reference; covers all phases through Ood.
pub struct WarpPipelineConfig {
    pub l1: usize,
    pub log_l: usize,
    pub log_m: usize,
    pub log_n: usize,
    /// Witness arity: `n - k` instance variables. Used to split the
    /// reduced-z vector at the TC→Ood boundary.
    pub n_minus_k: usize,
    /// Number of OOD samples (Ood phase).
    pub s: usize,
}

/// Per-call inputs. Lifetime `'a` is independent of the pipeline's
/// `'phase` — exactly what the GAT migration unlocked.
pub struct WarpPipelineInputs<'a, F, H>
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

/// Reduced output of the prefix pipeline. Holds the per-phase
/// reductions plus the TC→Ood inter-phase published values
/// (`eta`, `nu_0`, `td_new`) that downstream Batching/Proximity will
/// consume — and that the new accumulator instance carries.
pub struct WarpPipelineReduced<F, H>
where
    F: Field,
    H: MerkleHasher<Symbol = Vec<F>>,
{
    pub pesat: PesatReducedStatement<F>,
    pub tc: TwinConstraintReducedStatement<F>,
    pub ood: OodReducedStatement<F>,
    pub pesat_witness: PesatReducedWitness<F, H>,
    pub tc_witness: TwinConstraintReducedWitness<F>,
    /// Bundled-PESAT evaluation of the reduced witness — the `η` value
    /// absorbed between TC and Ood.
    pub eta: F,
    /// Reduced-oracle code-eval at `tc.zeta_0` — the `ν₀` absorbed
    /// between TC and Ood.
    pub nu_0: F,
    /// New (single-codeword) Merkle commitment to the reduced
    /// codeword. Becomes the next accumulator's root.
    pub td_new: WarpCommitted<H, F>,
    /// Split halves of the reduced witness vector `z`: `(new_x, new_w)`.
    /// Become the instance/witness components of the next accumulator.
    pub new_x: Vec<F>,
    pub new_w: Vec<F>,
}

impl<'phase, F, P, C, H> WarpPipeline<'phase, F, P, C, H>
where
    F: Field + PrimeField + Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize,
    P: BundledPESAT<F>,
    C: LinearCode<F>,
    H: MerkleHasher<Symbol = Vec<F>>,
    H::Digest: Encoding<[u8]> + Decoding<[u8]> + NargDeserialize + NargSerialize + Clone + Eq,
{
    /// Run Pesat → TwinConstraint → (inter-phase glue) → Ood.
    ///
    /// Mirrors the orchestrator's data flow exactly:
    /// - `pesat_red.mus / .taus` feed TC's `Statement`
    /// - `pesat_witness.codewords` feed TC's `ProverInputs` by reference
    /// - between TC and Ood: compute `eta` (bundled-PESAT eval),
    ///   `nu_0` (oracle eval at `tc.zeta_0`), commit to the reduced
    ///   codeword as `td_new`, absorb `(td_new.root, eta, nu_0)` into
    ///   the transcript
    /// - Ood reads its samples / answers from the transcript using
    ///   `tc_witness.f` as the oracle
    pub fn prove<'a>(
        &self,
        prover_state: &mut ProverState,
        config: &WarpPipelineConfig,
        inputs: WarpPipelineInputs<'a, F, H>,
    ) -> Result<WarpPipelineReduced<F, H>, ProverError> {
        // ── Phase 2: PESAT ─────────────────────────────────────────────
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

        // ── Phase 3a: twin-constraint sumcheck ─────────────────────────
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

        // ── Phase 3b: TC→Ood glue (eta, nu_0, td_new commit, absorb) ──
        let beta_eq_evals = compute_hypercube_eq_evals(config.log_m, &tc_red.beta_tau);
        let eta = self
            .bundled_pesat
            .evaluate_bundled(&beta_eq_evals, &tc_witness.z)
            .map_err(|_| ProverError::SpongeFish)?;
        let nu_0 = tc_witness.f.query_at_point(&tc_red.zeta_0);

        let (new_x_slice, new_w_slice) = tc_witness.z.split_at(config.n_minus_k);
        let new_x = new_x_slice.to_vec();
        let new_w = new_w_slice.to_vec();

        let td_new = {
            let _s = tracing::info_span!("warp_pipeline.commit_new_oracle").entered();
            count_ops!(MerkleTreeBuilds);
            let scheme = warp_scheme::<H, F>(self.pesat.hasher.clone(), self.code_len);
            scheme.commit(&[tc_witness.f.evals().to_vec()])
        };
        prover_state.prover_message(td_new.root());
        prover_state.prover_message(&eta);
        prover_state.prover_message(&nu_0);

        // ── Phase 3c: OOD ─────────────────────────────────────────────
        let (ood_red, _, _) = self.ood.prove(
            prover_state,
            &OodStatement {
                s: config.s,
                log_n: config.log_n,
            },
            &(),
            &OodProverInputs {
                oracle: &tc_witness.f,
            },
        )?;

        Ok(WarpPipelineReduced {
            pesat: pesat_red,
            tc: tc_red,
            ood: ood_red,
            pesat_witness,
            tc_witness,
            eta,
            nu_0,
            td_new,
            new_x,
            new_w,
        })
    }
}

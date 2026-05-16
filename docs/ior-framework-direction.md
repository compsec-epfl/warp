# IOR Framework — Research Direction

This document summarises the findings of an extended design discussion about
extending warp's IOR layer into a universal IOR-to-argument compilation
framework. It is **not** a design document — it is the record of where the
discussion landed, what was rejected, and what the design document (still to
be written) must address.

The stated long-term goal:

> Write each IOR once, feed them into a generic compiler, get back a
> non-interactive argument — across protocols, not just WARP.

This is a research project. It is not a refactor of warp.

---

## 1. The endpoint

A universal IOR-to-argument framework should expose:

- A **typed IOR DSL / component contract** for protocol authors.
- A **core Protocol IR** that records the IOR sequence, typed inter-IOR
  wires, declared transcript/oracle events, delegated operations, and
  obligations.
- A set of **compilers** (FS, BCS, eventually others) that consume the IR
  and produce non-interactive arguments without knowing protocol-specific
  details.

Operating slogan, agreed across the discussion:

> An IOR is a typed, effectful arrow between relations.
> A protocol is a typed DAG of IOR arrows.
> An argument compiler is an interpreter for the protocol's
> oracle/transcript effect language.

WARP is the first serious benchmark — a source of design constraints and
honest pain points — but is not "half the framework." The framework's
correctness must be validated against at least one second, unrelated
protocol.

---

## 2. Where warp currently stands

Post-cleanup state, as of this discussion:

- `IOR` trait (in external `ark_iop`): clean local-reduction kernel.
  Statement/Witness/ProverInputs/VerifierInputs/ReductionInputs/
  ReducedStatement/ProofString/ReducedWitness/VerifierOutputs associated
  types; `compose_prove` / `compose_verify` enforce reduction parity via
  `reduce_statement` + private result constructors.
- `MESSAGE_TAGS` constants on each IOR: per-step transcript-event labels
  absorbed by `compose_*` as an FS prologue.
- `ProtocolSchema` (warp-local): structured value listing
  `(IOR NAME, MESSAGE_TAGS, delegated_events)` in order, with a stable
  blake3 fingerprint. Snapshot-tested.
- `Proximity` symmetrised: VC-agnostic at the IOR level on both prover and
  verifier; orchestrator owns `V::open_multiple` / `V::check_multiple`.
- FS regression protection: `snapshot_fs` (narg_string + proof bytes) +
  end-of-protocol transcript sentinel (prover and verifier squeeze a final
  challenge; values must match).

Calibrated readiness, for the universal goal:

- **WARP-specific runner discipline:** fairly mature.
- **Universal IOR compiler framework:** early research stage.
- **Useful benchmark and design constraints:** yes, definitely.
- **Actual generic runner:** not close yet.

---

## 3. The central missing object

A typed DAG of inter-IOR dataflow.

For WARP, this DAG includes (non-exhaustive):

- `Pesat.taus_zero_check_challenges → TwinConstraint.l1_taus...`
- `Pesat.mus_codeword_first_coords → TwinConstraint.l1_mus...`
- `TwinConstraint.f_oracle → Bridge, Ood, Batching`
- `TwinConstraint.deferred_obligation → Bridge.discharge`
- `SampleQueries.queries → Batching, Proximity`
- `Proximity.shift_query_answers → delegated VC openings`

Today this DAG is encoded as imperative state-threading in
`accumulation_scheme/prove.rs` and `verify.rs`. The framework must lift
this into a first-class object.

A list of IORs is not a protocol. A protocol is a list **and** a wire
graph.

---

## 4. Designs explicitly rejected

The discussion converged on rejecting four candidate designs:

| Candidate | Why rejected |
|---|---|
| `Vec<Box<dyn IOR>>` (runtime trait-object runner) | Type-erases the heterogeneous Statement/Witness/Reduced types that are the protocol's mathematical wiring. Forces runtime downcasts. Loses compile-checked composition. |
| WARP-specific procedural macro (the `warp_protocol!` endpoint) | Solves WARP only; doesn't generalise. Useful as an intermediate cosmetic layer but not the research endpoint. |
| `ProverBackend` / `VerifierBackend` trait (each IOR generic over backend) | Re-introduces the D4 lifetime cascade (E0276, E0477, GAT-as-method-parameter). Walked through repeatedly; will not compile cleanly with borrow-bearing IORs (Pesat, Bridge, Proximity, TwinConstraint). |
| Procedural macro as the **first** artifact | Highest-cost implementation piece. Risks investing months making the wrong abstraction pleasant to write. Macros must come last. |

A `ctx.commit_oracle(...)` / `ctx.challenge(...)` style "declared effects"
trait, where IOR bodies call methods on a generic context, is
`ProverBackend` renamed. Any proposal of this shape must explicitly show
trait signatures compiling against warp's borrow-bearing IORs.

---

## 5. Design direction accepted

A three-layer separation:

```
Layer 1: Mathematical IOR implementation
  Ordinary typed Rust. Computes prover/verifier behaviour. May call
  spongefish / effsc / ark-vc directly. NOT generic over an abstract
  backend.

Layer 2: Protocol IR
  Declarative description of ports, wires, transcript/oracle events,
  delegated operations, and obligations. Built once per protocol. The
  compiler-facing object.

Layer 3: Compiler / interpreter
  Consumes the IR (and, for the FS prove/verify path, a typed execution
  trace) to materialise concrete argument bytes. FS first, BCS later.
```

The IOR implementation does **not** become backend-polymorphic. The IR
sits beside it as a parallel declaration. This is the design that
escapes the D4 trap: nothing inside an IOR's `prove_inner` needs to be
generic over a backend trait.

---

## 6. Revised phased plan

The reviewer's original plan (design doc → procedural macro → generated
Rust → compiler → WARP → BCS → second protocol) was reordered.
**Macros are highest-cost and must come last.** The validated order:

1. **Design doc** — write `docs/ior-framework-design.md` with the 10-section
   outline below. Includes worked examples for at least Pesat, TwinConstraint,
   Bridge, and Proximity.
2. **Hand-coded core IR** — express WARP by hand-building a `ProtocolIR`
   value. No macros. Cheapest way to validate IR expressiveness.
3. **Formal admissibility rules + soundness theorem skeleton.** Math, not
   code.
4. **Hand-written FS interpreter/compiler** over the hand-coded IR.
   Confirms the IR is compileable.
5. **WARP port** — replace `accumulation_scheme/prove.rs` orchestration
   with IR-driven orchestration. Real stress test.
6. **Second protocol expressed as IR** — only run after #5 succeeds. If
   the IR can't express a second protocol without redesign, back to #1.
7. **BCS compiler** — once IR + admissibility + soundness skeleton are
   stable.
8. **Macro DSL** — cosmetic surface layer on top of a validated calculus.

Each step is a research artifact. Step 1 alone is publishable.

---

## 7. The four hard questions (load-bearing)

The design doc must answer all four. The framework's correctness depends
on them.

### Q1: What is the formal contract of an IOR?

Beyond `Statement / Witness / Reduced{Statement,Witness}`, a composable
IOR must expose:

- Input and output relations
- Public and private input ports
- Prover messages and verifier challenges (as typed events)
- Oracle messages and their query interfaces
- Delegated operations (e.g. `vc.open_multiple`)
- Deferred obligations (emitted and/or discharged)
- The transcript/event schedule

The current `ProtocolSchema` is a partial seed (name + tags + delegated
events). The IR needs typed ports and wires on top of this.

### Q2: How are hidden transcript effects forbidden?

A universal compiler cannot reason about IORs that secretly call
`prover_state.prover_message(...)`, `V::open_multiple(...)`, or
`effsc::sumcheck(...)` without declaring those as effects.

The framework must commit to a strategy for forbidding undeclared
effects. Three known options, all with costs:

- **Runtime instrumentation:** wrap the sponge in a logging adapter; compare
  observed trace to declaration. Has cost; misses traces that produce the
  same bytes but different sponge state.
- **Type-checked DSL** where IORs can only invoke declared effects.
  Collapses back into the `ctx.commit_oracle` pattern and the D4 trap.
- **Proof-carrying implementation:** formal verification that the
  implementation matches the declaration. Most expensive.

This is the **trace-vs-declaration consistency problem** — the central
soundness gap of the three-layer architecture. The design doc must pick a
strategy.

### Q3: What does `V::open_multiple` mean abstractly?

For warp's current Merkle-VC, `open_multiple` emits authentication
material into the spongefish transcript. For a universal framework, the
IR must express:

> open commitment C at positions I with tuple values V, under oracle
> interface O, using commitment scheme VC.

…without assuming every VC has the same proof shape. The current `delegated_events: &[&str]` field is a stand-in. Structured fields
(`commitment`, `positions`, `values`, `arity`, `scheme_family`,
`opening_mode`, `batching_semantics`) will be needed.

### Q4: What soundness theorem must the compiler preserve?

The framework is not "generate bytes." It produces a non-interactive
argument with a soundness guarantee. The theorem shape:

> If each IOR node is complete and sound as a reduction, and the
> protocol DAG is well-typed/admissible, and all emitted obligations are
> discharged or exported, and the compiler correctly realises the
> declared oracle/transcript effects, then the compiled argument is
> complete and sound for the composed reduction.

This is multiple papers of theoretical work. The code architecture must
follow this theorem, not the other way around.

---

## 8. Four open sub-issues for the design doc

Beyond the four hard questions, these specific items must be explicitly
addressed in the design doc:

1. **Trace-vs-declaration consistency** (the soundness gap from Q2 above).
   Pick a strategy with eyes open.
2. **IR wire types in Rust.** Wire metadata like
   `Wire { from, to, ty: ??? }` — `ty` as a string loses type safety;
   `TypeId` is `'static`-only; encoding proper Rust types in a runtime IR
   is hard. Decide whether the IR is purely runtime (analyzable, weakly
   typed) or also has a type-level encoding (compile-checked, harder to
   inspect).
3. **Second-protocol choice — DECIDED: WHIR** (see
   <https://github.com/WizardOfMenlo/whir/pull/250>). Honest tradeoffs:
   WHIR shares hash-based / code-based / Reed-Solomon / sumcheck-using
   crypto family with WARP, so the framework will initially validate
   only against "hash-based code-based SNARK" rather than fully
   universal. Accepted because (a) WHIR adds recursive folding — a
   structural feature WARP lacks; (b) ground-truth context already
   exists via the `z-tech/efficient_sumcheck` integration branch; (c)
   even within the shared crypto family, WHIR's recursive-fold DAG vs.
   WARP's linear-accumulation DAG is a non-trivial expressiveness test.
   Phase 7+ extensions toward Nova / Spartan / lookup arguments would
   broaden the validation surface beyond the hash-based family later.
4. **Compile-time IR vs runtime IR.** The hand-built sketch
   (`.step(...).wire(...)`) is runtime; wire mismatches are runtime
   errors. For compile-checked composition, a type-level IR (HList-style)
   is needed. Probably both coexist; decide whether one is primary.

---

## 9. Conceptual clarifications established

A few items the discussion repeatedly returned to. These belong in the
framework's vocabulary.

### IOR vs IOP

- An **IOR** is a *reduction*: input relation → output relation.
- An **IOP** is a *proof system*: input relation → accept/reject.
- A composition of IORs followed by a terminal decider is an IOP-shaped
  proof system for the original relation.
- An IOP is **not definitionally** a list of IORs; an IOP construction
  *may be organised* as a composition of IORs.

In warp's vocabulary today: `IOR` trait is correct; `IOP` trait names the
composition's identity (NAME + ior_names) but isn't itself a "proof
system" — the terminal check lives in `AccumulationScheme::decide`. The
naming is loose but documented; renaming is low priority.

### Admissibility

An IOR is admissible (for compilation by the framework) when:

- All transcript / oracle / subprotocol effects are fully declared.
- Public transcript shape depends only on public parameters and prior
  public transcript state.
- The protocol is public-coin (verifier challenges are sampled from the
  transcript / random oracle, not from hidden state).
- Oracle messages have declared query interfaces.
- All oracle commitments / openings are declared as events.
- Witness-dependent control flow cannot change the public event schedule
  unless explicitly represented.
- Deferred obligations are either discharged or exported.
- Subprotocols expose their own IR rather than writing hidden transcript
  bytes.

The framework should make admissibility a first-class, statically
checkable property.

### Sumcheck and VC integration

Two of the largest implementation obstacles:

- **`effsc::sumcheck`** writes transcript bytes internally. For the
  framework, sumcheck must be either (a) rewritten as a DSL IOR
  component, or (b) treated as an opaque "subprotocol event" the
  compiler can't reason through. (a) is invasive; (b) breaks the
  fully-declared-effects property. No clean third option.
- **`ark-vc`'s `V::open_multiple`** writes auth paths in a shape
  determined by `V`'s concrete type. Same fork: either rewrite ark-vc to
  emit "abstract opening events," or treat each VC as an opaque
  delegated event with concrete-typed parameters.

The design doc must commit to a strategy for each.

---

## 10. Outline for the design doc

The reviewer's 10-section structure, with the four sub-issues threaded in:

1. **Goal** — universal composition of IORs into compiled
   arguments/reductions.
2. **Non-goals** — `Vec<Box<dyn IOR>>`; WARP-only macro; hidden
   transcript-writing subroutines; backend-polymorphic IOR trait before
   the IR is known.
3. **Core objects** — Relation, IOR component, Protocol graph, Port,
   Wire, Event, Oracle interface, Commitment interface, Opening,
   Obligation, Compiler, Compiled reduction. *(Open sub-issue: IR wire
   types — Section 8.2.)*
4. **WARP as motivating benchmark** — list all seven IORs, all wires,
   all delegated events, all deferred obligations. *(Trace-vs-declaration
   consistency — Section 8.1 — surfaces here.)*
5. **Toy protocol benchmark** — three IORs, one oracle, one challenge,
   one delegated opening, one deferred obligation. *(Second-protocol
   choice — Section 8.3.)*
6. **Admissibility rules** — public-coin, declared effects, fixed public
   schedule, typed wires, discharged/exported obligations, declared
   oracle interfaces.
7. **Compiler semantics** — FS interpretation; BCS interpretation.
   *(Compile-time vs runtime IR — Section 8.4.)*
8. **Soundness theorem skeleton.**
9. **Rust implementation strategy** — hand-coded IR first; generated
   code later; macro DSL last.
10. **Open problems** — sumcheck, ark-vc / VC generality, dynamic arity,
    witness-dependent control flow, trace-vs-declaration consistency,
    **recursive IOR composition** (forced by WHIR; an IOR's reduced
    statement may itself be a composition of IORs, requiring either DAG
    cycles in the IR or a typed encoding of recursive depth).

---

## 11. What this discussion did NOT settle

- The specific trait surface of a composable IOR (beyond "more than today's
  `IOR`").
- How sumcheck integrates concretely (rewrite vs. opaque).
- How `V::open_multiple` is abstracted (per-scheme delegated event vs.
  ark-vc rewrite).
- Whether the IR is one object (runtime) or two (runtime + type-level).
- The formal soundness theorem.
- How recursive composition (forced by WHIR) is encoded in the IR.
- Resourcing (this is a multi-person research project, not a side quest).

These are the design doc's job.

Settled in this discussion: Phase 6 benchmark is **WHIR**.

---

## 12. Recommended next step

Write `docs/ior-framework-design.md` with the 10-section outline above.
The first draft does not need to answer the four hard questions
definitively — it needs to make them concrete enough that the next
review cycle can engage with proposed answers rather than meta-framing.

Until that draft exists, further design discussion is diminishing
returns. The convergence between reviewer and council in this discussion
is now tight enough that the next productive cycle requires a partial
artifact, not more abstract argument.

WARP's current branch is a stable, useful implementation milestone. The
universal framework is a separate research track, beginning now.

# IOR Framework — Design Document

> **STATUS: SKELETON.** This document captures the structure agreed in
> [`ior-framework-direction.md`](./ior-framework-direction.md). Each
> section is a stub naming what it must contain. Real content — formal
> definitions, trait signatures, worked IR examples — fills in across
> subsequent research cycles.
>
> Cross-reference: the four hard questions and four open sub-issues from
> the direction doc are tagged inline as **HQ1–HQ4** and **OQ1–OQ4**.

---

## 1. Goal

Universal composition of IORs into compiled non-interactive arguments
and reductions. Protocol authors write IOR components and wire them
into a typed protocol graph; one or more compilers (FS first, BCS
later) interpret the graph into an argument.

Operating slogan:

> An IOR is a typed, effectful arrow between relations.
> A protocol is a typed DAG of IOR arrows.
> An argument compiler is an interpreter for the protocol's
> oracle/transcript effect language.

**TODO:** distinguish "argument" from "reduction" precisely. WARP-style
schemes produce a new accumulator instance, not just accept/reject —
the framework's output type must capture both shapes.

---

## 2. Non-goals

These are explicitly out of scope, per the discussion that produced
this document:

- A runtime `Vec<Box<dyn IOR>>` iterator over heterogeneous IORs.
- A WARP-only macro or runner.
- Hidden transcript writes inside IOR bodies (effects must be declared).
- A `ProverBackend` / `VerifierBackend` trait every IOR is generic over
  on day one.
- Procedural macros as the first or even early-stage artifact.
- Validation against a single protocol family (need WARP + WHIR
  minimum).

---

## 3. Core objects

The framework's vocabulary. Each item below needs a formal definition
plus a Rust-level encoding sketch.

- **Relation** — the (statement, witness) pair an IOR reduces from/to.
  **TODO:** decide whether relations are first-class types or just type
  aliases.
- **IOR component** — a typed local reduction. Inputs, outputs, declared
  effects.
  **HQ1: What is the formal IOR contract?** Beyond today's
  `Statement / Witness / ReducedStatement / ReducedWitness`, must
  expose: input/output relations, public/private input ports, prover
  messages and verifier challenges as typed events, oracle messages
  with declared query interfaces, delegated operations, deferred
  obligations, transcript/event schedule.
- **Protocol graph** — typed DAG of IOR components plus inter-IOR wires.
- **Port** — a typed value flowing through the graph
  (`Public<T>`, `Secret<T>`, `Challenge<T>`, `Oracle<O>`,
  `Commitment<O>`, `Obligation<T>`, etc.).
- **Wire** — typed connection between an output port of one IOR and an
  input port of another.
  **OQ2: IR wire types in Rust.** Wires need to carry types, not just
  string fingerprints. Decide: runtime IR with `TypeId`-style
  fingerprints + weak checking; type-level IR with HList-style
  encoding + compile checks; or both coexist.
- **Event** — a declared transcript / oracle / subprotocol operation
  (`AbsorbPublic`, `SendMessage`, `SampleChallenge`, `CommitOracle`,
  `QueryOracle`, `OpenOracle`, `RunSubprotocol`, `EmitObligation`,
  `DischargeObligation`).
- **Oracle interface** — the abstract shape of a committed oracle
  (arity, query domain, value type).
- **Commitment interface** — the abstract shape of a commitment scheme
  (commit, open, check).
  **HQ3: What does `V::open_multiple` mean abstractly?** The IR's
  delegated-event field must carry enough structure to compile across
  multiple VC backends. Probably: commitment, positions, values,
  arity, scheme family, opening mode, batching semantics.
- **Opening** — declared opening event tied to a commitment.
- **Obligation** — a check deferred at one step and discharged at
  another. First-class: emitted obligations must be discharged or
  exported.
- **Compiler** — consumes the IR + execution trace, produces a
  compiled-reduction argument. FS, BCS, future.
- **Compiled reduction** — output type. Carries the reduced statement
  plus compiler-specific argument material.

---

## 4. WARP as motivating benchmark

Worked example #1. The framework's first stress test.

**TODO:** express each IOR's contract in the framework's vocabulary:

- [ ] **Pesat** — input relation, output relation, ports, declared
  events. Must capture the codeword-commit + tau-squeeze structure.
- [ ] **TwinConstraint** — emits a deferred obligation discharged by
  Bridge. The framework must express this cross-step dependency.
  Internal `effsc::sumcheck` call: pick the integration strategy
  (Section 6, HQ2).
- [ ] **Bridge** — discharges TwinConstraint's obligation; emits new
  commitment.
- [ ] **OOD** — emits prover messages, samples challenges.
- [ ] **SampleQueries** — pure challenge-sampling IOR. Smallest example.
- [ ] **Batching** — uses `effsc::sumcheck` again; consumes outputs from
  Pesat, OOD, SampleQueries.
- [ ] **Proximity** — emits *only* shift-query answers; delegates VC
  opens to the orchestrator (post-symmetrization). The framework's
  delegated-event language must capture both the fresh and the
  per-accumulator opens.
- [ ] **The DAG** — list every inter-IOR wire (Section 3 of the
  direction doc enumerates the major ones).
- [ ] **The deferred obligations** — TwinConstraint → Bridge.
- [ ] **The terminal output** — `AccumulatorInstance + AccumulatorWitness`,
  not accept/reject.

**HQ2: How are hidden transcript effects forbidden?** WARP's current
IORs call `prover_state.prover_message(...)` and `V::*` directly. The
framework must commit to one of: runtime instrumentation,
type-checked DSL (with the D4 risk acknowledged), or
proof-carrying-implementation. **TODO:** pick a strategy and justify
against this section's worked examples.

**OQ1: Trace-vs-declaration consistency.** If IOR implementation stays
ordinary Rust (the accepted architecture) and the IR is a separate
parallel declaration, what mechanism guarantees they match? This is
the central soundness gap. **TODO:** decide strategy in this section.

---

## 5. Toy protocol benchmark

Worked example #2. Phase 2 cheap validation before WHIR.

**TODO:** design the toy protocol. Reviewer's spec:

- 3 IORs minimum
- 1 oracle commitment
- 1 challenge
- 1 delegated opening
- 1 deferred obligation
- 1 cross-cutting wire (output of step 1 consumed by step 3, skipping 2)

Pseudo-shape:

```
Step A: commits an oracle, samples a challenge, produces value X.
Step B: consumes X (via the cross-cut), emits a deferred obligation O.
Step C: consumes A's oracle handle and challenge,
        discharges O,
        delegates an opening at queried positions.
```

**TODO:** name this toy. **TODO:** fully express it in the IR (whatever
the IR turns out to be).

---

## 6. Admissibility rules

What makes an IOR "compilable" by the framework.

Candidate rules (from the direction doc):

1. All transcript/oracle/subprotocol effects are fully declared.
2. Public transcript shape depends only on public parameters and prior
   public transcript state.
3. The protocol is public-coin.
4. Oracle messages have declared query interfaces.
5. All oracle commitments/openings are declared as events.
6. Witness-dependent control flow cannot change the public event
   schedule unless explicitly represented.
7. Deferred obligations are either discharged or exported.
8. Subprotocols expose their own IR rather than writing hidden
   transcript bytes.

**TODO:** formalize each. **TODO:** decide which are checkable
statically (i.e. enforceable by the framework's API) vs which are
proof obligations the protocol author must satisfy.

**Sub-fork: effsc::sumcheck integration.** Either:
- (a) Rewrite sumcheck as a DSL IOR component (subprotocol IR exposed)
- (b) Treat sumcheck as an opaque transcript-effect event

(a) is invasive; (b) breaks rule 8. **TODO:** pick a strategy. Same
applies to `ark-vc`'s `V::open_multiple`.

---

## 7. Compiler semantics

How a compiler interprets the IR.

### 7.1 FS interpretation

**TODO:** spell out how each event type maps to FS-transcript actions:

- `AbsorbPublic` → `public_message`
- `SendMessage` → `prover_message`
- `SampleChallenge` → squeeze via `verifier_message`
- `CommitOracle` → write commitment bytes via `prover_message`
- `QueryOracle` → look up locally (verifier-side)
- `OpenOracle` → orchestrator calls `V::open_multiple` /
  `V::check_multiple`
- `RunSubprotocol` → recurse into the child IR
- `EmitObligation` / `DischargeObligation` → out-of-band check;
  framework enforces all obligations terminate

### 7.2 BCS interpretation

**TODO:** the BCS compiler converts the same event stream into:
- Merkle commitments per oracle commit
- Random-coin derivation from prior commitments/messages
- Scheduled query/decision phase
- Opening proofs/auth paths attached to the final argument

**HQ4: What soundness theorem must the compiler preserve?** The FS
and BCS compilers must each have a soundness theorem of the shape:

> If each IOR is complete and sound, and the protocol DAG is
> admissible, and obligations are discharged or exported, and the
> compiler correctly realises declared effects, then the compiled
> argument is complete and sound for the composed reduction.

**TODO:** state the theorem precisely. **TODO:** identify the IR
properties it depends on.

### 7.3 Recursive composition

Forced by WHIR. The IR must support an IOR whose reduced statement is
itself a composition of IORs.

**TODO:** decide encoding. Candidates:
- DAG cycles in the IR (most general; hard to reason about)
- Typed encoding of recursive depth (e.g., `RecursiveProtocol<N>`)
- A separate `RunSubprotocol` event that nests an IR

**OQ4: Compile-time IR vs runtime IR.** Recursive composition is
especially painful for compile-time encodings. **TODO:** decide
whether the IR is one object (runtime, weakly typed) or two
(runtime + type-level encoding), and how recursion is handled in each.

---

## 8. Soundness theorem skeleton

The framework's load-bearing math. **HQ4** lives here.

**TODO:** state the composition theorem. Probably:

> Let `P` be a protocol consisting of admissible IORs
> `I_1, ..., I_n` composed via wires `W`. Let `C` be a compiler.
> If every `I_i` is complete and sound as a reduction, every
> obligation emitted by some `I_i` is discharged by some `I_j` (j > i)
> or exported in the protocol's terminal output, and `C` correctly
> realises declared effects, then `C(P)` is a complete and sound
> compiled reduction for the relation pair
> `(input_relation(I_1), output_relation(I_n))`.

**TODO:** identify the precise IR conditions for "admissible,"
"correctly realises declared effects," etc.

**TODO:** prove (or cite, where applicable) that the FS and BCS
compilers each satisfy "correctly realises declared effects."

**TODO:** Connect to the iBCS / SNRDX literature on BCS-for-IOR.

---

## 9. Rust implementation strategy

Per the revised phased plan:

1. **Hand-coded IR first.** Define `ProtocolIR`, `Wire`, `Event`,
   etc. as ordinary Rust types. Hand-build the WARP IR by populating
   one of these values. No macros. Cheapest validation.
2. **Hand-written FS interpreter.** Walks the IR. Compares against an
   execution trace from running the WARP prover. Confirms the IR is
   compilable.
3. **WARP port.** Replace `accumulation_scheme/{prove,verify}.rs`
   orchestration with IR-driven orchestration. The IORs themselves
   stay ordinary Rust; the IR is parallel.
4. **WHIR expressed in the IR.** Forces the recursive-composition
   feature and validates that the IR is more than WARP-shaped.
5. **BCS compiler.** Once the IR is stable.
6. **Macro DSL.** Cosmetic surface layer over a validated IR. Last.

**TODO:** decide whether the hand-coded IR is its own crate
(`ark-iop-ir`?) or stays warp-local until WHIR validates the design.

---

## 10. Open problems

Items the framework must eventually solve. Not blockers for the
design doc's first cycle, but must be acknowledged.

- **Sumcheck integration** (Section 6 sub-fork).
- **VC abstraction** for `V::open_multiple` across schemes (HQ3).
- **Trace-vs-declaration consistency** (OQ1).
- **IR wire types** in Rust (OQ2).
- **Compile-time vs runtime IR** (OQ4).
- **Recursive IOR composition** (forced by WHIR).
- **Dynamic arity** (IORs that produce a variable number of outputs).
- **Witness-dependent control flow** (admissibility rule 6).
- **Resourcing.** This is a multi-person research project. Solo
  execution is not feasible on a useful timeline.

---

## 11. Worked examples — placeholders

These sections fill in across iterations as the IR shape stabilizes.

### 11.1 Pesat in IR form

**TODO**

### 11.2 TwinConstraint in IR form (including the deferred obligation)

**TODO**

### 11.3 Bridge in IR form (including the discharge)

**TODO**

### 11.4 Proximity in IR form (with delegated VC opens)

**TODO**

### 11.5 Toy protocol in IR form

**TODO** (depends on §5 design)

### 11.6 A WHIR round in IR form (with the recursive-composition encoding)

**TODO** (depends on §7.3 decision)

---

## 12. What the first content cycle should focus on

To make this doc useful before the next review cycle, prioritize:

1. **Pick a strategy for HQ2** (hidden-effects forbidding) and **OQ1**
   (trace-vs-declaration consistency) — these are coupled.
2. **Pick a strategy for sumcheck and VC integration** (§6 sub-fork).
3. ~~**Sketch the runtime IR's Rust types**~~ — **DONE.** See
   [`src/iop/ir.rs`](../src/iop/ir.rs): `ProtocolIR`, `StepNode`,
   `Wire`, `EventNode`, `ObligationNode`, etc. as ordinary Rust types.
   Three sanity tests build minimal IR values (one-step, two-step
   with a wire, two-step with an emit/discharge obligation pair).
   Status: **skeleton only** — no compilation, no validation, no
   builder ergonomics. OQ2 (wire types) is stubbed as
   `TypeFingerprint(String)`; OQ4 (compile-time vs runtime IR) is
   answered "runtime, for now."
4. **Hand-build §11.1 (Pesat) in the IR** — the smallest non-trivial
   worked example. If this can't be done, the IR isn't real yet.

Remaining first-cycle artifacts: 1, 2, 4.

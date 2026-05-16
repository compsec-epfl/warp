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

### Sub-fork: effsc::sumcheck integration — **DECIDED: D**

The user's framing: best interface design, effort tolerated. Four
options:

- **A.** Sumcheck as opaque library call. Violates rule 8. **Rejected.**
- **B.** Reimplement sumcheck inside the framework, abandon effsc.
  Throws away years of work for marginal cleanliness gain.
  **Rejected.**
- **C.** `SumcheckIOR` is first-class in the IR; its implementation
  *wraps* `effsc::sumcheck` internally. Effsc stays standalone. The
  OQ1 trace-vs-declaration consistency problem appears at the
  wrapper boundary. **Rejected as a compromise.**
- **D.** **`SumcheckIOR` is defined IN the framework. Effsc is
  refactored to become a (high-performance) implementation of it.
  Effsc's own transcript trait is removed; the framework's event
  language replaces it.** **CHOSEN.**

The layering under D:

```
Framework layer:    defines SumcheckIOR — IR + Rust trait + event schedule
                                 ↑
Implementation:     effsc::SumcheckCore  (production impl: SIMD, streaming)
                    toy::SumcheckCore    (reference impl for tests)
                    ...future impls
                                 ↑
Caller layer:       WARP's TwinConstraint + Batching
                    WHIR's sumcheck rounds
                    other framework consumers
```

Wins vs option C:
- **No OQ1 gap for sumcheck.** Effsc's emitted events *are* the
  framework's declared events (effsc is the implementation, not a
  wrapper). Trace-vs-declaration consistency becomes a non-question
  for this subprotocol.
- **Effsc's own transcript trait disappears.** One transcript
  abstraction in the ecosystem (the framework's), not two.
- **Multiple sumcheck implementations become first-class.** Reference
  toy, production effsc-backed, future GPU/distributed — all
  implement the same trait.
- **WARP and WHIR share the same `SumcheckIOR` automatically.**
- **Effsc's algorithmic optimizations preserved** as internal
  implementation details: SIMD, memmap-streaming, polynomial-form
  variants (multilinear vs tablewise vs coefficient), etc. These
  are implementation concerns, not interface concerns.

Costs (accepted under "irrespective of effort"):
- Effsc loses standalone-library identity; becomes a framework
  implementation.
- WARP's `effsc::sumcheck` / `effsc::sumcheck_verify` call sites in
  `iors/twin_constraint.rs` and `iors/batching.rs` are rewritten to
  use the framework's `SumcheckIOR`.
- WHIR's sumcheck integration (the in-flight PR
  <https://github.com/WizardOfMenlo/whir/pull/250>) is similarly
  affected — that PR likely supersedes itself in the framework story.
- Cross-crate coordination: effsc and ark-iop must evolve together
  for this refactor.

**`SumcheckIOR` interface shape** (framework-defined):
- Parameters: `degree: usize`, `num_rounds: usize`,
  `prover_strategy: SumcheckProverStrategy` (multilinear / tablewise /
  coefficient — implementation hint).
- Public input: `claim: F`.
- Private input: `polynomial: SumcheckPolynomial<F>` (abstract over
  the strategy).
- Events (per round, in order): `SendMessage { tag: "sumcheck:round_poly", ... }`,
  `SampleChallenge { tag: "sumcheck:round_chal", ..., distribution: Field }`.
- Outputs: `final_claim: F`, `challenges: Vec<F>` (length =
  `num_rounds`).

At IR-construction time `num_rounds` is fixed. The framework
materialises the `2 * num_rounds` events.

### Sub-fork: hidden-effect control / trace-vs-declaration — **DECIDED: validated-trace architecture (HQ2 + OQ1)**

A four-component architecture, agreed across all council passes:

```
ProtocolIR     = static declaration (steps, wires, events, obligations)
ExecutionTrace = runtime record of concrete protocol-visible effects
TraceChecker   = validates trace ⊢ IR
ValidatedTrace = compiler-consumable proof of conformance
Compiler       = ProtocolIR + ValidatedTrace → Argument
```

**Flow:** the prover runs each IOR (in ordinary typed Rust) and the
framework records a `TraceEvent` for each protocol-visible effect.
After execution, `TraceChecker::check(&ir, trace)` validates structural
conformance. Only the validated trace can be fed to a compiler.

**Hidden-effect control is audit-class** in the first framework
version: declared effects + trace validation + future static-analysis
lint (`ior-lint-no-raw-channel`), **not** Rust type-level enforcement.

The reasoning: a type-class enforcement would wrap the sponge in a
context trait that IOR implementations are forced to go through. That
re-opens the D4 lifetime trap (same `&mut transcript + &committed_state`
aliasing problem the framework already escaped) and applies the
re-opened trap to every IOR, not just VC. The validated-trace
architecture catches hidden effects post-hoc: any divergence between
the trace and the IR's declared effects fails validation. Combined
with code review and (future) lint, this is the right research-stage
choice.

This is explicit honesty: **the framework detects hidden effects, it
does not structurally forbid them.** Direct transcript/channel access
inside IOR `prove_inner` bodies is inadmissible by convention. The
trace checker will catch any drift between declared and actual
behaviour, but only after the fact.

**Trace event shape:** per IR event variant. `TraceEvent::SendMessage`
carries `(ir_event_id, value_digest)`; `TraceEvent::OpenOracle` carries
`(ir_event_id, commitment_digest, positions_digest, values_digest,
evidence)`; etc.

**Evidence:** start with the simplest workable shape.

```rust
pub enum Evidence {
    Bytes { scheme: &'static str, bytes: Vec<u8> },
}
```

Typed `OpeningProof` evidence (with scheme-specific Rust types) comes
later, after OQ2 (wire types) matures. Premature typing here would
couple the runtime trace to scheme-specific generics before the
framework knows how to express them.

**TraceChecker validates** (first version):
- Event count matches IR event count
- Each `trace.events[i].ir_event` resolves to a real `ir.events[id]`
- Event kinds match (SendMessage in IR ↔ SendMessage in trace, etc.)
- Trace order matches IR order (modulo subprotocol nesting)
- `protocol_fingerprint` matches the IR's `schema().fingerprint()`
- Obligations: every `EmitObligation` in the trace has a matching
  `DischargeObligation` somewhere, or is exported via an output

**TraceChecker does NOT validate** (deferred to later versions):
- Challenge consistency (challenge values are derived from prior sponge
  state — needs FS-replay tooling)
- Oracle opening consistency (values returned by `V::check_multiple`
  match the auth-path proof — needs cooperation with the VC layer)
- Type compatibility beyond string `TypeFingerprint` (needs OQ2)
- Witness-dependent control flow detection (needs static analysis)

**Future artifact:** `ior-lint-no-raw-channel`, a Clippy-style or
custom-rustc-driver lint that flags direct `prover_state.public_message`,
`verifier_message`, `V::open_multiple` calls inside IOR `prove_inner` /
`verify_inner` bodies. Forces the audit-class discipline to be
machine-checked even before type-class enforcement exists.

---

### Sub-fork: ark-vc's `V::open_multiple` integration — **DECIDED: C-prime (asymmetric with sumcheck)**

A three-agent council reviewed whether to apply Option D (sumcheck's
strategy) to ark-vc as "D-prime." Verdict 2-against-1 against D-prime:
the asymmetry between sumcheck and VC is **structural**, not aesthetic,
and D-prime collapses to C-prime in Rust anyway.

**The asymmetry that broke D-prime:**

- **Sumcheck's `prove()` owns its own event loop.** Each iteration
  produces a stable (send-poly, squeeze-chal) pair. The implementation
  can emit framework events natively because *the implementation is
  the loop.* Effsc-as-impl falls out cleanly.
- **VC's `open_multiple()` is atomic from the framework's view.** One
  call, scheme-specific internal proof structure (Merkle auth paths
  vs KZG group elements vs binius binary-field-specific vs packed
  alphabet), no loop the framework can name. The Rust critic walked
  three trait sketches:
  - `&mut impl EventEmitter` param → D4 lifetime trap when emitter
    shares an owner with committed-codeword state.
  - Return opening data → compiles, but this is just C-prime, not D.
  - Static IR fragment + runtime byte work → two parallel sources of
    truth, drift hazard.

**C-prime:**

```rust
pub trait MultiVectorCommitment: VectorCommitment {
    type OpeningProof: CanonicalSerialize + CanonicalDeserialize;

    fn open_multiple<'a, Codeword>(...)
        -> Result<Self::OpeningProof, Self::Error>;

    fn check_multiple<R: RngCore + CryptoRng>(
        ...,
        proof: &Self::OpeningProof,
        rng: &mut R,
    ) -> Result<(), Self::Error>;
}
```

Flow under C-prime:
1. Orchestrator calls `V::open_multiple(...)` → receives `Self::OpeningProof`.
2. Orchestrator binds proof + values + positions to declared PortIds.
3. Orchestrator emits `EventNode::OpenOracle { tag, commitment,
   positions, values, oracle_interface }`.
4. FS/BCS compilers see the declared event and interpret it per
   backend.

**Admissibility is still satisfied.** Rule 8 ("subprotocols expose
their IR") holds because the event IS declared — just by the
orchestrator, not by ark-vc. The soundness theorem doesn't care who
emits the event, only that it's emitted and corresponds to actual
behaviour. The advocate's claim that "without D-prime, VC-using
protocols are inadmissible" conflates *who emits* with *whether
emitted*.

**The framework supports two integration patterns, not one:**

| Subprotocol shape | Integration pattern | Example |
|---|---|---|
| Owns its event loop (multi-round, stable per-round structure) | **D** — impl emits events natively | Sumcheck (effsc backend) |
| Atomic from framework view (single call, complex internal proof) | **C-prime** — impl returns data, framework emits events | VC (Merkle / KZG / binius / etc.) |

This is structural honesty. Sumcheck and VC are different shapes;
forcing symmetry breaks Rust.

**Compatibility with ia_core / PR #5:**

C-prime is compatible with the in-flight `ia_core::{ProverChannel,
VerifierChannel}` work. ia_core sits **below** framework events:
- ia_core: byte transport (low level)
- Framework events: protocol actions (high level)

ark-vc takes a channel parameter for its byte work; framework
emits events at a higher abstraction level after ark-vc returns the
`OpeningProof`. No conflict with Christian's design.

**Costs:**
- ark-vc gets a new `OpeningProof` associated type and a return-shape
  change. Smaller refactor than effsc's, and compatible with PR #5.
- Existing ark-vc consumers (non-IOP) are unaffected by the framework
  event language — they just receive `OpeningProof` and do whatever
  they want with it.
- WARP's `accumulation_scheme/prove.rs` and `verify.rs` keep their
  current orchestrator-owns-the-opens structure, gaining explicit
  event emissions around each `V::open_multiple` / `V::check_multiple`
  call.

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

**FIRST PASS LANDED.** See [`src/iop/ir_examples.rs`](../src/iop/ir_examples.rs)
`fn warp_pesat_only_ir() -> ProtocolIR`. Four sanity tests:
- `pesat_ir_builds` — types compose
- `pesat_step_events_reference_real_events` — step ↔ events
  consistency
- `pesat_all_step_outputs_are_protocol_outputs` — output ports
  exported correctly in single-step protocol
- `pesat_output_sources_resolve` — output sources point to real
  step output ports

Findings from doing the exercise (these inform the next IR revision):

**F1: No event variant for internal prover compute.** Pesat computes
its codewords and mus from witnesses *before* any transcript event.
The IR has CommitOracle, SendMessage, SampleChallenge etc. — all
transcript-visible — but no "internal compute" variant. Probably
correct: internal compute *shouldn't* be a transcript event. But it
means the IR doesn't fully describe what the component does; the
reader has to infer that codewords come from witnesses via the
component's `prove()` body. **This is the trace-vs-declaration gap
(OQ1) in concrete form.** The declaration says "this commitment
exists"; the implementation knows how it was built. The framework
must commit to a strategy for verifying they match.

**F2: `SampleChallenge` lacks shape annotations.** Pesat samples `l1`
challenges each of `log_m` field elements — total `l1 × log_m` field
elements, shaped `Vec<Vec<F>>`. Current `ChallengeDistribution` is
`Field | Bytes{count}` (scalar). Neither emitting one event with no
shape info nor emitting `l1` events captures the structure. **Open
issue:** add structured shape annotations:

```rust
pub enum Shape {
    Scalar,
    Vector(usize),
    Matrix(usize, usize),
    // ... or a typed-shape mini-DSL
}

pub enum ChallengeDistribution {
    Field { shape: Shape },
    Bytes { count: usize },
}
```

Same problem will recur in WHIR's recursive challenge sampling.

**F3: Step `outputs` field carries port declarations, not values.**
The codeword commitment is *created by* the `CommitOracle` event, but
also appears as a `PortDecl` in the step's `outputs`. The current type
definition treats events as the source of truth for which ports exist;
the step's `outputs` is redundant data that must be kept consistent
with the events. Consider: derive `outputs` from events automatically
(builder pattern), or drop the redundancy entirely.

**F4: Type fingerprints lose generic context.** `V::Commitment` is
fingerprinted as the literal string `"V::Commitment"`. The IR has no
encoding of what `V` is, what `F` is, or that this is the same `V`
that appears in `CommitterKey`. For two-step protocols where Pesat's
`V::Commitment` must equal Bridge's `V::Commitment`, the IR can't
check that automatically. (Confirms OQ2 — wire types as strings are
genuinely insufficient.)

**F5: Population is awkward without a builder.** The example uses
`ir.events.push(...)` followed by `ir.steps.push(...)` referencing
`e_commit`, `e_send_mus`, `e_squeeze_taus` by index. A real builder
would chain these and assign indices automatically. The current
imperative-population style is fine for skeleton work but tedious as
scale grows. **Open issue:** design a builder API (probably
`ProtocolIR::builder()` returning a typed builder that gives you
per-event handles).

**F6: Single-step Pesat doesn't test wires or obligations.** This
exercise validates: params, private inputs, three event variants
(`CommitOracle` / `SendMessage` / `SampleChallenge`), step outputs,
protocol outputs. It does **not** validate: cross-step wires,
delegated events, deferred obligations, recursive subprotocols,
multi-IOR DAG topology. §11.2 (TwinConstraint with deferred
obligation) and §11.3 (Bridge with discharge) are the natural next
exercises.

### 11.2 TwinConstraint in IR form (including the deferred obligation)

**FIRST PASS LANDED.** See [`src/iop/ir_examples.rs`](../src/iop/ir_examples.rs)
`fn warp_twin_constraint_ior(log_l, tc_degree)`. Constructed using the
new [`ProtocolIrBuilder`](../src/iop/ir_builder.rs) (addresses F5).
Four sanity tests pass:
- `twin_constraint_ir_builds` — types compose; 4 events (omega,
  tau, sumcheck, emit_obligation)
- `twin_constraint_ir_embeds_sumcheck_child` — RunSubprotocol's
  child IR has 2·log_l events as expected
- `twin_constraint_obligation_lifecycle_is_declared` — emitter +
  discharger naming consistent
- `twin_constraint_emit_event_matches_obligation` — EmitObligation
  event references the registered obligation id

Findings F7-F9 from doing the exercise:

**F7: Subprotocol output extraction has no formal mechanism.** The
SumcheckIOR child IR's outputs (`final_claim`, `challenges`) need to
be wired back into the outer IR's port namespace. Today this is done
informally: TwinConstraint declares its own `gamma_sumcheck_challenges`
and `final_claim` outputs, and the implementation is expected to copy
the values from the child's outputs. The IR has no explicit "subprotocol
output → outer port" wire shape. **Open issue:** add a
`subprotocol_output_bindings: Vec<PortBinding>` field to the
RunSubprotocol event, mapping the child's output port names to outer
port references.

**F8 (confirmed from sumcheck): no shape annotations on
`ChallengeDistribution`.** TwinConstraint squeezes both a scalar
omega and a vector beta_tau. With current `Field | Bytes{count}`,
both render as the same event, losing the structural distinction.
Same fix as previously noted: structured shape annotations.

**F9: The obligation's "data" lives outside the event.** The
deferred check obligation has implicit data (the gamma challenges,
the final_claim) that Bridge consumes when discharging. The current
`EmitObligation { obligation: ObligationId }` event names the
obligation but doesn't reference the data ports. The data is exposed
via the step's other output ports; Bridge consumes them as wires.
This works because obligations and ordinary data wires are kept
separate. But it means an obligation's *semantics* (what evidence
discharges it) is not in the IR — it's documentation. **Open issue:**
consider whether obligations should carry a typed
`expected_evidence_shape` so the TraceChecker can validate discharge
events more strongly.

**F10 (positive): the builder API closed F5 cleanly.** TwinConstraint's
IR construction is ~30 lines of chained method calls, vs. the ~100
lines of manual `ir.events.push(...)` + index management Pesat
needed. The chain reads top-to-bottom and the dataflow is locally
visible. The builder approach is validated; expanding to Bridge,
Proximity, and the toy 3-IOR will use the same pattern.

### 11.3 Bridge in IR form (including the discharge)

**FIRST PASS LANDED.** See [`src/iop/ir_examples.rs`](../src/iop/ir_examples.rs)
`fn warp_bridge_ior() -> ProtocolIR`. Built with [`ProtocolIrBuilder`].
Closes the obligation lifecycle TwinConstraint opens. Three sanity
tests pass:
- `bridge_ir_builds` — types compose; 4 events
  (CommitOracle, SendMessage, SendMessage, DischargeObligation)
- `bridge_discharges_tc_obligation` — Bridge's DischargeObligation
  event names `tc_deferred_oracle_check` exactly
- `bridge_event_sequence_is_correct` — event order matches Bridge's
  intended commit-send-send-discharge structure

Finding F11 from the exercise:

**F11: `DischargeObligation.evidence` is `Vec<PortId>` — untyped.**
Bridge's discharge passes four ports: `eta_predicate_eval`,
`nu_0_oracle_eval`, the upstream `gamma_sumcheck_challenges`, and the
upstream `final_claim`. The `EventNode::DischargeObligation` variant
accepts these as an opaque `Vec<PortId>`. The IR can't check that the
evidence shape matches the obligation's expected_evidence_shape
(because no such field exists yet, per F9). Combined with F9 this
becomes concrete: Bridge silently providing the wrong number or
wrong-typed evidence ports would not be caught at IR-construction
time. **Resolution path:** tie F11's fix to F9's — when
`ObligationNode` gains an `expected_evidence_shape`, the discharge
event can be checked against it at TraceChecker time. Until then,
discharge evidence is convention.

### 11.4 Proximity in IR form (with delegated VC opens)

**FIRST PASS LANDED.** See [`src/iop/ir_examples.rs`](../src/iop/ir_examples.rs)
`fn warp_proximity_ior(num_accs) -> ProtocolIR`. Built with
[`ProtocolIrBuilder`]. Exercises the C-prime VC pattern (events
*declared* by Proximity, *emitted* by the orchestrator at runtime).
Three sanity tests pass:
- `proximity_ir_zero_accs` — degenerate `num_accs = 0` builds with
  just the fresh open
- `proximity_ir_scales_with_num_accs` — `1 + num_accs` OpenOracle
  events and `3 + num_accs` step output ports for each `num_accs ∈
  {0, 1, 4, 8}`
- `proximity_all_events_are_open_oracle` — Proximity has *only*
  opens, no sends/squeezes/commits

Findings F12-F13:

**F12: No `emission_owner` field on events.** Per the C-prime decision
(§6 VC sub-fork), Proximity's IR *declares* the OpenOracle events,
but the orchestrator is the actual runtime emitter. There's no IR
mechanism today to distinguish declarer from emitter — the convention
is implicit (Proximity owns the declaration, orchestrator runs
`V::open_multiple` and writes the trace event). This works for now
because TraceChecker just validates structural conformance (count +
kind + order + fingerprint), and it doesn't care who wrote the bytes.
But once we add per-event validity checks (e.g., "the
OpenOracle.commitment field references a real prior CommitOracle"),
or once we add a `ior-lint-no-raw-channel` lint that flags direct VC
calls inside IOR bodies, we'll need an explicit
`emission_owner: EmissionOwner { Declarer, Orchestrator(StepId) }`
field on EventNode to know which IOR bodies are *allowed* to write
the bytes. **Open issue:** add `emission_owner` when the lint and
per-event validity logic are designed (post-FS-interpreter).

**F13: Linear port-name scaling with `num_accs` reproduces F2/F8.**
Proximity declares `num_accs` separately-named output ports
(`acc_column_tuples_0`, `acc_column_tuples_1`, ...) and the
corresponding number of OpenOracle events. The shape mini-DSL
proposed in F2 would let this collapse to one port and one event with
a `Shape::Vector(num_accs)` annotation. Recurs in WHIR's per-fold
opens. **Resolution path:** ship the F2/F8 shape DSL and refactor
Proximity, SumcheckIOR, and (when written) WHIR to use it.

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
   [`src/iop/ir.rs`](../src/iop/ir.rs).
4. ~~**Hand-build §11.1 (Pesat) in the IR**~~ — **DONE.** See
   [`src/iop/ir_examples.rs`](../src/iop/ir_examples.rs) and §11.1
   above for findings F1–F6.

All first-cycle artifacts landed:
- §12.1 (HQ2/OQ1): validated-trace architecture, audit-class
  hidden-effect control. See §6's "trace-vs-declaration" sub-fork.
- §12.2: sumcheck → D, VC → C-prime.
- §12.3: IR Rust types in `src/iop/ir.rs`.
- §12.4: Pesat in IR + findings F1-F6.

Next-cycle artifacts (per the design plan):
1. ~~Execution trace types: `src/iop/trace.rs` with `ExecutionTrace`,
   `TraceEvent`, `Evidence`, `TraceChecker` stub, `ValidatedTrace`.~~
   **DONE.**
2. ~~Builder API for `ProtocolIR` (addresses finding F5).~~ **DONE.**
3. ~~TwinConstraint in IR (stresses obligations + SumcheckIOR
   subprotocol).~~ **DONE.**
4. ~~Bridge in IR (stresses obligation discharge).~~ **DONE.**
5. ~~Proximity in IR (stresses C-prime VC openings).~~ **DONE.**
6. Toy 3-IOR protocol (stresses non-WARP generality). **NEXT.**
7. FS interpreter (only after 6 lands).

### Findings already surfaced (drive the next IR revision)

Thirteen findings from §11.1 (Pesat), §11.2 (TwinConstraint), §11.3
(Bridge) and §11.4 (Proximity) feed back into the IR design:

- **F1 → OQ1.** Internal prover compute isn't a transcript event but
  must be reconciled with declared output ports. Concrete instance of
  the trace-vs-declaration gap.
- **F2.** `ChallengeDistribution` needs a shape mini-DSL
  (`Scalar` / `Vector(n)` / `Matrix(r, c)`). Pesat's `Vec<Vec<F>>`
  taus expose this. Recurs in WHIR.
- **F3.** `StepNode.outputs` is redundant data vs the events that
  create the ports. Consider deriving via builder.
- **F4 → OQ2.** Type fingerprints as strings lose generic-parameter
  identity. `V::Commitment` from two different steps fingerprints to
  the same string but the IR can't *check* they're the same `V`.
- **F5.** Imperative population is tedious. A builder API is needed
  before the IR scales to multi-step examples.
- **F6.** Single-step Pesat doesn't stress wires, delegated events,
  or obligations. §11.2 / §11.3 / §11.4 cover those.
- **F7.** Subprotocol output extraction has no formal mechanism in
  the IR. Add `subprotocol_output_bindings` to `RunSubprotocol`.
- **F8** (confirmed via TwinConstraint): `ChallengeDistribution`
  shape mini-DSL is needed. Both Pesat's matrix taus and
  TwinConstraint's omega-vs-tau distinction demand it.
- **F9.** Obligation semantics (what evidence discharges it) is
  documentation, not IR data. Consider typed
  `expected_evidence_shape` on `ObligationNode`.
- **F10** (positive). The builder API closed F5. TwinConstraint's IR
  is ~30 lines using the builder vs. an estimated ~100 with manual
  pushes. Validates the no-macro / builder-only ergonomics path.
- **F11.** `DischargeObligation.evidence` is untyped (`Vec<PortId>`).
  Bridge would silently pass wrong-shape evidence with no check.
  Resolved together with F9 (typed `expected_evidence_shape` on
  `ObligationNode`).
- **F12.** No `emission_owner` field on events. The C-prime VC
  pattern (events declared by IOR, emitted by orchestrator) works
  by convention today. Needed once per-event validity checks or the
  `ior-lint-no-raw-channel` lint land.
- **F13** (confirmed via Proximity): the F2/F8 shape mini-DSL is
  load-bearing. Three independent worked examples (Pesat,
  SumcheckIOR, Proximity) already need it; WHIR will make four.
